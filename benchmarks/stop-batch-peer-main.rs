//! Exact fully sent response cancellation workload. No production code changes.
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
    io::Write,
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

const CANCEL_ERROR: u64 = 0x10c;

// Reject missing, duplicate, unsolicited and corrupt resets independently of
// response accounting. Every timing reset must refer to a fully sent response.
struct ResetBatch {
    expected: BTreeSet<u64>,
    seen: BTreeSet<u64>,
}
impl ResetBatch {
    fn new(ids: &[u64]) -> Result<Self> {
        let expected: BTreeSet<_> = ids.iter().copied().collect();
        ensure!(
            !ids.is_empty() && expected.len() == ids.len(),
            "invalid cancellation set"
        );
        Ok(Self {
            expected,
            seen: BTreeSet::new(),
        })
    }
    fn reset(&mut self, id: u64, error: u64, final_size: u64) -> Result<()> {
        ensure!(self.expected.contains(&id), "unsolicited reset {id}");
        ensure!(error == CANCEL_ERROR, "wrong reset error {error}");
        ensure!(
            final_size == RESPONSE.len() as u64,
            "wrong reset final size {final_size}"
        );
        ensure!(self.seen.insert(id), "duplicate reset {id}");
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        ensure!(
            self.seen == self.expected,
            "missing resets: {}/{}",
            self.seen.len(),
            self.expected.len()
        );
        Ok(())
    }
}

fn put_stops(payload: &mut Vec<u8>, ids: &[u64], error: u64) {
    for &id in ids {
        put_varint(payload, 5);
        put_varint(payload, id);
        put_varint(payload, error);
    }
}

fn cancellation_ids(first: u64, window: usize, count: usize) -> Result<Vec<u64>> {
    ensure!(
        count > 0 && count <= window && window.is_multiple_of(count),
        "invalid sparse set"
    );
    let step = window / count;
    Ok((0..count)
        .map(|i| first + 4 * (i * step + step / 2) as u64)
        .collect())
}

fn credit(actual: u64, told: &mut u64, initial: u64, completed: usize) -> Result<()> {
    let limit = initial + completed as u64;
    let expected = if limit - *told >= initial / 2 {
        limit
    } else {
        *told
    };
    ensure!(
        actual == expected,
        "wrong advertised stream credit: {actual}, expected {expected} ({completed} completed)"
    );
    *told = expected;
    Ok(())
}

fn empty_socket(socket: &UdpSocket) -> Result<()> {
    let mut buf = [0u8; 65536];
    match socket.recv(&mut buf) {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Ok(n) => bail!("leftover datagram after final fence: {n} bytes"),
        Err(e) => Err(e.into()),
    }
}

fn trace(file: &mut Option<std::fs::File>, direction: &str, pn: u64, plain: &[u8]) -> Result<()> {
    if let Some(file) = file {
        let hex: String = plain.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            file,
            "{}",
            json!({"direction":direction, "pn":pn, "hex":hex})
        )?;
    }
    Ok(())
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
    expected_credit: u64,
    max_data: u64,
    sent_data: u64,
    completed: usize,
    reset_count: usize,
    resets: Option<ResetBatch>,
    packet_count: usize,
    // Every sent 1-RTT request/PING packet must ultimately be acknowledged.
    acked_through: Option<u64>,
    sent_packets: Vec<u64>,
    trace: Option<std::fs::File>,
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
            expected_credit: stream_limit,
            stream_limit,
            max_data,
            sent_data: 0,
            completed: 0,
            reset_count: 0,
            resets: None,
            packet_count: 0,
            acked_through: None,
            sent_packets: Vec::new(),
            trace: std::env::var_os("STOP_BATCH_TRACE")
                .map(|path| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                })
                .transpose()?,
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
        trace(&mut self.trace, "tx", pn, payload)?;
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
        trace(&mut self.trace, "rx", pn, plain)?;
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
                Frame::ResetStream {
                    id,
                    error,
                    final_size,
                } => {
                    ack_only = false;
                    self.resets
                        .as_mut()
                        .context("reset outside cancellation batch")?
                        .reset(id, error, final_size)?;
                    self.reset_count += 1;
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
    fn check_credit(&mut self, completed: usize) -> Result<()> {
        credit(
            self.stream_limit,
            &mut self.expected_credit,
            self.initial_limit,
            completed,
        )
    }

    fn cycle(
        &mut self,
        window: usize,
        cancellations: usize,
        batch_size: usize,
        stop_batch: usize,
        pid: u32,
        mode: &str,
    ) -> Result<Value> {
        let before = cpu(pid)?;
        let start = Instant::now();
        let completed_before = self.completed;
        let resets_before = self.reset_count;
        let packets_before = self.packet_count;
        let sent_before = self.sent_packets.len();
        let mut outstanding = VecDeque::<(u64, u64, usize)>::new();
        let mut count = 0;
        let mut batches = 0;
        // ACK only the oldest response every 64 batches. This maintains PTO
        // progress while leaving exactly `window` fully sent responses live.
        while count < window {
            let progress = if batches > 0 && batches % 64 == 0 {
                let (pn, _, n) = outstanding.pop_front().context("missing oldest packet")?;
                count -= n;
                Some(pn)
            } else {
                None
            };
            let n = batch_size.min(window - count);
            let ack = progress.map(|pn| vec![(0, pn)]).unwrap_or_default();
            let first = self.next_stream;
            let pn = self.request(n, &ack)?;
            outstanding.push_back((pn, first, n));
            count += n;
            batches += 1;
        }
        ensure!(count == window);
        self.check_credit(self.completed - window)?;
        let first = outstanding.front().unwrap().1;
        ensure!(
            self.next_stream == first + 4 * window as u64,
            "noncontiguous live streams"
        );
        let ids = cancellation_ids(first, window, cancellations)?;
        let original_last = self.last_received;
        let cancel_start = Instant::now();
        for chunk in ids.chunks(stop_batch) {
            let mut payload = Vec::with_capacity(1200);
            if mode == "ack-stop" {
                frame::put_ack(&mut payload, &[(0, original_last)], 0);
            }
            put_stops(&mut payload, chunk, CANCEL_ERROR);
            if mode == "stop-ack" {
                frame::put_ack(&mut payload, &[(0, original_last)], 0);
            }
            let expected = if mode == "ack-stop" { 0 } else { chunk.len() };
            self.resets = if expected == 0 {
                None
            } else {
                Some(ResetBatch::new(chunk)?)
            };
            let sent = self.send(&payload)?;
            loop {
                self.receive(None)?;
                if self.acked_through.is_some_and(|pn| pn >= sent)
                    && self.resets.as_ref().is_none_or(|r| r.complete().is_ok())
                {
                    break;
                }
            }
            if let Some(resets) = self.resets.take() {
                resets.complete()?;
            }
        }
        let before_reset_ack = match mode {
            "stop-ack" => self.completed - cancellations,
            "ack-stop" => self.completed,
            _ => self.completed - window,
        };
        self.check_credit(before_reset_ack)?;
        let advertised_before_reset_ack = self.stream_limit;
        if mode == "repeat" {
            // A changed error on later stops must not create another reset or
            // change the first error. A packet ACK is a processing fence.
            for chunk in ids.chunks(stop_batch) {
                let mut payload = Vec::new();
                put_stops(&mut payload, chunk, CANCEL_ERROR + 1);
                let sent = self.send(&payload)?;
                while self.acked_through.is_none_or(|pn| pn < sent) {
                    self.receive(None)?;
                }
            }
            self.check_credit(before_reset_ack)?;
        }
        let expected_resets = if mode == "ack-stop" { 0 } else { cancellations };
        ensure!(
            self.reset_count - resets_before == expected_resets,
            "wrong reset count"
        );
        // ACK every original response and reset, then require a fresh complete
        // HTTP response and exact returned credit. The fence itself stays live.
        self.request(1, &[(0, self.last_received)])?;
        self.check_credit(self.completed - 1)?;
        let cancellation_seconds = cancel_start.elapsed().as_secs_f64();
        // Also ACK the fence, re-ACK an old response range, and fence the final
        // credit update. These costs are included in the complete cycle metric.
        self.ping(Some(self.last_received))?;
        self.check_credit(self.completed)?;
        let (_, ack_only) = self.ping(Some(self.last_received))?;
        ensure!(ack_only, "final credit ACK did not drain control state");
        self.check_credit(self.completed)?;
        ensure!(
            self.acked_through
                .is_some_and(|pn| self.sent_packets.last().is_some_and(|last| *last <= pn)),
            "unacknowledged client packet"
        );
        empty_socket(&self.socket)?;
        let seconds = start.elapsed().as_secs_f64();
        let after = cpu(pid)?;
        let completed = self.completed - completed_before;
        Ok(
            json!({"responses":completed, "resets":expected_resets, "seconds":seconds,
            "cancellation_seconds":cancellation_seconds, "window":window,
            "server_cpu_seconds":after-before, "survivors":window-expected_resets,
            "prime_responses":completed-1, "followup_responses":1,
            "credit_before_reset_ack":advertised_before_reset_ack,
            "completed_before_reset_ack":before_reset_ack,
            "advertised_stream_limit":self.stream_limit,
            "unadvertised_credit":self.initial_limit+self.completed as u64-self.stream_limit,
            "received_packets":self.packet_count-packets_before,
            "sent_packets":self.sent_packets.len()-sent_before,
            "leftover_datagrams":0, "outstanding_responses":0, "outstanding_resets":0}),
        )
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 9,
        "usage: peer PORT PID WINDOW CANCELS REQUEST_BATCH STOP_BATCH CYCLES MODE"
    );
    let port = args[1].parse()?;
    let pid = args[2].parse()?;
    let window: usize = args[3].parse()?;
    let cancellations: usize = args[4].parse()?;
    let batch: usize = args[5].parse()?;
    let stop_batch: usize = args[6].parse()?;
    let cycles: usize = args[7].parse()?;
    let mode = args[8].as_str();
    ensure!(
        (64..=65536).contains(&window)
            && (1..=32).contains(&batch)
            && window.is_multiple_of(batch)
            && (1..=64).contains(&stop_batch)
            && cycles > 0
    );
    ensure!(
        matches!(mode, "plain" | "repeat" | "stop-ack" | "ack-stop"),
        "invalid mode"
    );
    ensure!(
        !matches!(mode, "stop-ack" | "ack-stop") || cancellations <= stop_batch,
        "frame-order cases must fit one cancellation packet"
    );
    cancellation_ids(0, window, cancellations)?;
    let mut peer = Peer::connect(port, window)?;
    let warmup = peer.cycle(window, cancellations, batch, stop_batch, pid, mode)?;
    let mut rows = Vec::new();
    for _ in 0..cycles {
        rows.push(peer.cycle(window, cancellations, batch, stop_batch, pid, mode)?);
    }
    println!(
        "{}",
        json!({"window":window,"cancellations":cancellations,"batch":batch,
        "stop_batch":stop_batch,"mode":mode,"warmup":warmup,"cycles":rows,
        "responses":peer.completed,"resets":peer.reset_count,"errors":0,
        "unexpected_packets":0,"duplicate_responses":0,"duplicate_resets":0,
        "initial_stream_limit":peer.initial_limit,"advertised_stream_limit":peer.stream_limit})
    );
    Ok(())
}
#[cfg(test)]
mod peer_tests {
    use super::*;
    #[test]
    fn omitted_duplicate_and_unsolicited_responses_fail() {
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.complete().is_err());
        assert!(b.response(10, 4, 0, true, RESPONSE).is_err());
        assert!(b.response(10, 12, 0, true, RESPONSE).is_err());
    }
    #[test]
    fn corrupt_partial_and_split_responses_fail() {
        for (offset, fin, data) in [
            (1, true, RESPONSE),
            (0, false, RESPONSE),
            (0, true, &RESPONSE[..RESPONSE.len() - 1]),
        ] {
            assert!(Batch::new(4, 1).response(10, 4, offset, fin, data).is_err());
        }
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.response(11, 8, 0, true, RESPONSE).is_err());
    }
    #[test]
    fn omitted_duplicate_and_unsolicited_resets_fail() {
        let mut b = ResetBatch::new(&[0, 8]).unwrap();
        b.reset(0, CANCEL_ERROR, RESPONSE.len() as u64).unwrap();
        assert!(b.complete().is_err());
        assert!(b.reset(0, CANCEL_ERROR, RESPONSE.len() as u64).is_err());
        assert!(b.reset(4, CANCEL_ERROR, RESPONSE.len() as u64).is_err());
        b.reset(8, CANCEL_ERROR, RESPONSE.len() as u64).unwrap();
        b.complete().unwrap();
    }
    #[test]
    fn wrong_reset_error_or_final_size_fails_without_completing() {
        for (error, size) in [
            (CANCEL_ERROR + 1, RESPONSE.len() as u64),
            (CANCEL_ERROR, 0),
            (CANCEL_ERROR, RESPONSE.len() as u64 + 1),
        ] {
            let mut b = ResetBatch::new(&[0]).unwrap();
            assert!(b.reset(0, error, size).is_err());
            assert!(b.complete().is_err());
        }
    }
    #[test]
    fn missing_and_duplicate_stream_credit_fail() {
        let mut told = 2048;
        credit(2048, &mut told, 2048, 1).unwrap();
        assert!(credit(2049, &mut told, 2048, 1).is_err());
        assert!(credit(3071, &mut told, 2048, 1024).is_err());
        assert!(credit(3073, &mut told, 2048, 1024).is_err());
        credit(3072, &mut told, 2048, 1024).unwrap();
        credit(3072, &mut told, 2048, 1025).unwrap();
        credit(4097, &mut told, 2048, 2049).unwrap();
    }
    #[test]
    fn sparse_sets_are_exact_and_packet_bounded() {
        for first in [0, 262144, 1 << 31] {
            for window in [1024, 65536] {
                for count in [1, 64, 1024] {
                    let ids = cancellation_ids(first, window, count).unwrap();
                    let set: BTreeSet<_> = ids.iter().copied().collect();
                    assert_eq!(set.len(), count);
                    assert!(
                        ids.iter().all(|id| *id >= first
                            && *id < first + 4 * window as u64
                            && id % 4 == 0)
                    );
                    for chunk in ids.chunks(64) {
                        let mut wire = Vec::new();
                        put_stops(&mut wire, chunk, CANCEL_ERROR);
                        assert!(wire.len() + 32 <= 1200);
                        let parsed: Vec<_> = frame::Iter::new(&wire)
                            .map(|f| match f.unwrap() {
                                Frame::StopSending { id, error } => {
                                    assert_eq!(error, CANCEL_ERROR);
                                    id
                                }
                                _ => panic!("wrong frame"),
                            })
                            .collect();
                        assert_eq!(parsed, chunk);
                    }
                }
            }
        }
    }
    #[test]
    fn invalid_cancel_sets_fail() {
        for (window, count) in [(64, 0), (64, 65), (64, 3)] {
            assert!(cancellation_ids(0, window, count).is_err());
        }
        assert!(ResetBatch::new(&[]).is_err());
        assert!(ResetBatch::new(&[4, 4]).is_err());
    }
    #[test]
    fn leftover_datagram_oracle() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        empty_socket(&receiver).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"unsolicited", receiver.local_addr().unwrap())
            .unwrap();
        assert!(empty_socket(&receiver).is_err());
        empty_socket(&receiver).unwrap();
    }
}
