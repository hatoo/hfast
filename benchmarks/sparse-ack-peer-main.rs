//! Delayed sparse ACK workload. Fixed transport, exact wire response oracle.
#![allow(dead_code)]
mod clock;
mod quic;
mod tls;
#[cfg(test)]
mod http3 {
    pub mod proto;
    pub mod qpack;
}
#[cfg(test)]
mod status;
#[cfg(test)]
pub fn is_informational(status: u16) -> bool {
    (100..200).contains(&status)
}

use anyhow::{Context, Result, bail, ensure};
use quic::{
    conn::{Connection, LocalParamsInput},
    frame::{self, Frame},
    varint::put_varint,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    net::UdpSocket,
    time::{Duration, Instant},
};

const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

// Checking a whole batch makes omitted responses fail, even if all received
// bytes look valid. Request IDs cannot be counted twice or cross batch bounds.
struct Batch {
    first: u64,
    count: usize,
    seen: u64,
    pn: Option<u64>,
}
impl Batch {
    fn new(first: u64, count: usize) -> Self {
        assert!((1..=32).contains(&count));
        Self {
            first,
            count,
            seen: 0,
            pn: None,
        }
    }
    fn response(&mut self, pn: u64, id: u64, offset: u64, fin: bool, data: &[u8]) -> Result<()> {
        ensure!(
            id >= self.first && (id - self.first).is_multiple_of(4),
            "unexpected stream {id}"
        );
        let i = ((id - self.first) / 4) as usize;
        ensure!(
            i < self.count && self.seen & (1 << i) == 0,
            "duplicate or unsolicited response {id}"
        );
        ensure!(
            offset == 0 && fin && data == RESPONSE,
            "wrong response bytes or incomplete FIN"
        );
        ensure!(
            self.pn.is_none_or(|prev| prev == pn),
            "batch split across packets; workload changed"
        );
        self.pn = Some(pn);
        self.seen |= 1 << i;
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        ensure!(
            self.seen == (1 << self.count) - 1,
            "missing responses: {}/{}",
            self.seen.count_ones(),
            self.count
        );
        Ok(())
    }
}

fn sparse_ranges(first: u64, last: u64, gaps: &BTreeSet<u64>) -> Result<Vec<(u64, u64)>> {
    ensure!(first <= last, "empty receive interval");
    let mut ranges = Vec::new();
    let mut lo = first;
    for &gap in gaps {
        ensure!(gap > lo && gap < last, "gap lacks response on both sides");
        ranges.push((lo, gap - 1));
        lo = gap + 1;
    }
    ranges.push((lo, last));
    ranges.reverse();
    Ok(ranges)
}

fn cpu(pid: u32) -> Result<f64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>()? + fields[12].parse::<u64>()?;
    Ok(ticks as f64 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64)
}

struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    request: Vec<u8>,
    last_received: u64,
    next_stream: u64,
    stream_limit: u64,
    initial_limit: u64,
    max_data: u64,
    sent_data: u64,
    completed: usize,
    packet_count: usize,
    // Every sent 1-RTT request/PING packet must ultimately be acknowledged.
    acked_through: Option<u64>,
    sent_packets: Vec<u64>,
}
impl Peer {
    fn connect(port: u16, window: usize) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut conn = Connection::connect(
            tls::client_config(b"h3")?,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 30,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 16,
                max_idle_timeout_ms: 30_000,
                handshake_timeout_ms: 5_000,
            },
        )?;
        let mut wire = Vec::with_capacity(1200);
        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            wire.clear();
            while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
                ensure!(socket.send(&wire)? == wire.len());
                wire.clear();
            }
            if conn.probe_ready() {
                break;
            }
            ensure!(Instant::now() < deadline, "handshake timeout");
            let n = socket.recv(&mut buf)?;
            conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?;
            while let Some(ev) = conn.poll_event() {
                if let quic::conn::Event::Lost(reason) = ev {
                    bail!("handshake lost: {reason}");
                }
            }
        }
        // Busy receive avoids a scheduler wakeup in each measured round trip.
        // The peer has its own pinned CPU; both servers use the same workload.
        socket.set_nonblocking(true)?;
        let (stream_limit, max_data, last_received) = conn.probe_limits();
        ensure!(
            stream_limit == (window * 2) as u64,
            "unexpected initial stream credit"
        );
        // Static QPACK: GET, https, literal :authority=localhost, path=/.
        let headers = b"\x00\x00\xd1\xd7\x50\x09localhost\xc1";
        let mut request = vec![1];
        put_varint(&mut request, headers.len() as u64);
        request.extend(headers);
        let mut peer = Self {
            socket,
            conn,
            wire,
            request,
            last_received,
            next_stream: 0,
            initial_limit: stream_limit,
            stream_limit,
            max_data,
            sent_data: 0,
            completed: 0,
            packet_count: 0,
            acked_through: None,
            sent_packets: Vec::new(),
        };
        let mut control = Vec::new();
        frame::put_stream(&mut control, 2, 0, false, &[0, 4, 0]);
        frame::put_stream(&mut control, 6, 0, false, &[2]);
        frame::put_stream(&mut control, 10, 0, false, &[3]);
        peer.sent_data += 5;
        peer.send(&control)?;
        peer.receive(None)?;
        peer.ping(Some(peer.last_received))?;
        Ok(peer)
    }
    fn send(&mut self, payload: &[u8]) -> Result<u64> {
        let pn = self.conn.probe_seal(payload, &mut self.wire)?;
        ensure!(self.socket.send(&self.wire)? == self.wire.len());
        self.sent_packets.push(pn);
        Ok(pn)
    }
    fn receive(&mut self, mut batch: Option<&mut Batch>) -> Result<(u64, bool)> {
        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        let n = loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(Instant::now() < deadline, "missing response or ACK fence");
                    std::hint::spin_loop();
                }
                Err(e) => return Err(e.into()),
            }
        };
        let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
        // A dropped, reordered or duplicated packet invalidates this timing
        // fixture. Independent protocol regression fixtures exercise recovery.
        ensure!(
            pn == self.last_received + 1,
            "noncontiguous packet: {} after {}",
            pn,
            self.last_received
        );
        self.last_received = pn;
        self.packet_count += 1;
        let mut ack_only = true;
        for f in frame::Iter::new(plain) {
            match f? {
                Frame::Padding => {}
                Frame::Ack {
                    largest,
                    first_range,
                    ranges,
                    ..
                } => {
                    ensure!(
                        first_range == largest && ranges.is_empty(),
                        "client packet missing from server ACK"
                    );
                    self.acked_through = Some(self.acked_through.unwrap_or(0).max(largest));
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } if id & 3 == 0 => {
                    ack_only = false;
                    batch
                        .as_mut()
                        .context("response outside requested batch")?
                        .response(pn, id, offset, fin, data)?;
                }
                Frame::Stream {
                    id: 3,
                    offset: 0,
                    fin: false,
                    data: [0, 4, 0],
                } => {
                    ack_only = false;
                }
                Frame::MaxStreams { uni: false, limit } => {
                    ack_only = false;
                    ensure!(limit >= self.stream_limit);
                    self.stream_limit = limit;
                }
                Frame::MaxStreams { uni: true, .. } => {
                    ack_only = false;
                }
                Frame::MaxData(limit) => {
                    ack_only = false;
                    self.max_data = self.max_data.max(limit);
                }
                Frame::HandshakeDone => {
                    ack_only = false;
                }
                other => bail!("unexpected frame: {other:?}"),
            }
        }
        Ok((pn, ack_only))
    }
    fn request(&mut self, count: usize, ranges: &[(u64, u64)]) -> Result<u64> {
        ensure!(
            self.next_stream / 4 + count as u64 <= self.stream_limit,
            "stream credit exceeded"
        );
        self.sent_data += (count * self.request.len()) as u64;
        ensure!(
            self.sent_data <= self.max_data,
            "connection credit exceeded"
        );
        let mut payload = Vec::with_capacity(1200);
        if !ranges.is_empty() {
            frame::put_ack(&mut payload, ranges, 0);
        }
        let mut batch = Batch::new(self.next_stream, count);
        for i in 0..count {
            frame::put_stream(
                &mut payload,
                self.next_stream + 4 * i as u64,
                0,
                true,
                &self.request,
            );
        }
        self.send(&payload)?;
        self.next_stream += 4 * count as u64;
        loop {
            self.receive(Some(&mut batch))?;
            if batch.complete().is_ok() {
                break;
            }
        }
        batch.complete()?;
        self.completed += count;
        Ok(batch.pn.unwrap())
    }
    fn ping(&mut self, acknowledge_through: Option<u64>) -> Result<(u64, bool)> {
        let mut payload = Vec::new();
        if let Some(last) = acknowledge_through {
            frame::put_ack(&mut payload, &[(0, last)], 0);
        }
        payload.push(frame::PING as u8);
        let sent = self.send(&payload)?;
        let mut last;
        loop {
            last = self.receive(None)?;
            if self.acked_through.is_some_and(|pn| pn >= sent) {
                break;
            }
        }
        Ok(last)
    }
    fn cycle(
        &mut self,
        window: usize,
        ranges: usize,
        batch_size: usize,
        pid: u32,
    ) -> Result<Value> {
        let before = cpu(pid)?;
        let start = Instant::now();
        let completed_before = self.completed;
        let mut outstanding = VecDeque::<(u64, usize)>::new();
        let mut count = 0;
        let first = self.last_received + 1;
        let mut gaps = BTreeSet::new();
        let mut batches = 0;
        let mut since_gap = 0;
        while count < window {
            let progress = if batches > 0 && batches % 64 == 0 {
                let (pn, n) = outstanding.pop_front().context("missing oldest packet")?;
                count -= n;
                Some(pn)
            } else {
                None
            };
            let n = batch_size.min(window - count);
            let ack = progress.map(|pn| vec![(0, pn)]).unwrap_or_default();
            let pn = self.request(n, &ack)?;
            outstanding.push_back((pn, n));
            count += n;
            batches += 1;
            since_gap += n;
            if since_gap >= window / ranges && gaps.len() < ranges - 1 {
                let (pn, only) = self.ping(None)?;
                ensure!(only, "gap packet carried non-ACK state");
                gaps.insert(pn);
                since_gap = 0;
            }
        }
        ensure!(count == window && gaps.len() == ranges - 1);
        let ack = sparse_ranges(first, self.last_received, &gaps)?;
        ensure!(ack.len() == ranges);
        for &(pn, _) in &outstanding {
            ensure!(
                ack.iter().any(|&(lo, hi)| lo <= pn && pn <= hi),
                "response omitted from ACK"
            );
        }
        let fence_start = Instant::now();
        self.request(1, &ack)?;
        let ack_response_seconds = fence_start.elapsed().as_secs_f64();
        let seconds = start.elapsed().as_secs_f64();
        let after = cpu(pid)?;
        let completed = self.completed - completed_before;
        ensure!(
            self.stream_limit == self.initial_limit + self.completed as u64 - 1,
            "wrong exact stream credit: {} expected {}",
            self.stream_limit,
            self.initial_limit + self.completed as u64 - 1
        );
        // Final response ACK and PING are outside timing, never discarded.
        self.ping(Some(self.last_received))?;
        ensure!(
            self.acked_through
                .is_some_and(|pn| self.sent_packets.last().is_some_and(|last| *last <= pn)),
            "unacknowledged client packet"
        );
        Ok(
            json!({"completed":completed,"seconds":seconds,"requests_per_second":completed as f64/seconds,
            "ack_response_seconds":ack_response_seconds,"ack_ranges":ack.len(),"outstanding_responses":count,
            "server_cpu_ns_per_request":(after-before)*1e9/completed as f64,
            "advertised_stream_limit":self.stream_limit,"received_packets":self.packet_count}),
        )
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7,
        "usage: peer PORT PID WINDOW RANGES BATCH CYCLES"
    );
    let port = args[1].parse()?;
    let pid = args[2].parse()?;
    let window: usize = args[3].parse()?;
    let ranges: usize = args[4].parse()?;
    let batch: usize = args[5].parse()?;
    let cycles: usize = args[6].parse()?;
    ensure!(window >= 64 && (1..=256).contains(&ranges) && window.is_multiple_of(ranges));
    ensure!(
        (1..=32).contains(&batch)
            && window.is_multiple_of(batch)
            && batch <= window / ranges
            && cycles > 0
    );
    let mut peer = Peer::connect(port, window)?;
    let warmup = peer.cycle(window, ranges, batch, pid)?;
    let mut rows = Vec::new();
    for _ in 0..cycles {
        rows.push(peer.cycle(window, ranges, batch, pid)?);
    }
    println!(
        "{}",
        json!({"window":window,"ranges":ranges,"batch":batch,"warmup":warmup,"cycles":rows,
        "completed":peer.completed,"errors":0,"lost_packets":0,"duplicate_responses":0,
        "advertised_stream_limit":peer.stream_limit})
    );
    Ok(())
}
#[cfg(test)]
mod peer_tests {
    use super::*;
    #[test]
    fn missing_response_fails() {
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.complete().is_err());
    }
    #[test]
    fn duplicates_and_wrong_streams_fail() {
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.response(10, 4, 0, true, RESPONSE).is_err());
        assert!(b.response(10, 12, 0, true, RESPONSE).is_err());
    }
    #[test]
    fn incorrect_bytes_and_partial_fin_fail() {
        for (offset, fin, data) in [
            (1, true, RESPONSE),
            (0, false, RESPONSE),
            (0, true, &RESPONSE[..RESPONSE.len() - 1]),
        ] {
            assert!(Batch::new(4, 1).response(10, 4, offset, fin, data).is_err());
        }
    }
    #[test]
    fn complete_response_ids_pass() {
        let mut b = Batch::new(262140, 32);
        for i in (0..32).rev() {
            b.response(10, 262140 + 4 * i, 0, true, RESPONSE).unwrap();
        }
        b.complete().unwrap();
    }
    #[test]
    fn all_256_ranges_survive_wire_encoding() {
        let gaps = (1..256).map(|n| n * 256).collect();
        let expected = sparse_ranges(1, 65536, &gaps).unwrap();
        let mut wire = Vec::new();
        frame::put_ack(&mut wire, &expected, 0);
        let Frame::Ack {
            largest,
            first_range,
            ranges,
            range_count,
            ..
        } = frame::Iter::new(&wire).next().unwrap().unwrap()
        else {
            panic!("not ACK");
        };
        assert_eq!(range_count, 255);
        assert_eq!(
            frame::AckRanges::new(largest, first_range, ranges).collect::<Vec<_>>(),
            expected
        );
    }
    #[test]
    fn sparse_ack_set_oracle() {
        for len in [64, 1024, 65536] {
            let gaps = (4..len - 1).step_by(16).collect();
            let r = sparse_ranges(2, len, &gaps).unwrap();
            for pn in 2..=len {
                assert_eq!(
                    r.iter().any(|&(lo, hi)| lo <= pn && pn <= hi),
                    !gaps.contains(&pn)
                );
            }
        }
    }
}
