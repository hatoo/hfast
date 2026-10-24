//! Bounded localhost upload driver, not the production io_uring client.
#![allow(dead_code)]
mod clock;
mod credit_ledger;
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
use credit_ledger::{Ranges, Upload, ack_chunks, decode_ack};
use quic::{
    conn::{Connection, LocalParamsInput},
    frame::{self, Frame},
    varint::put_varint,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;
const WINDOW: usize = 64;
const CHUNK: usize = 1024;
const ACK_BUDGET: usize = 500;
const RETRY: Duration = Duration::from_millis(50);

#[derive(Clone)]
enum Work {
    Control,
    Data {
        stream: usize,
        offset: u64,
        length: usize,
        fin: bool,
    },
    Ping,
    Fence,
}
struct Flight {
    work: Work,
    copies: Vec<u64>,
    last: Instant,
}

struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    prefix: Vec<u8>,
    body_size: u64,
    uploads: Vec<Upload>,
    starts: Vec<Option<Instant>>,
    flights: Vec<Flight>,
    max_data: u64,
    sent_data: u64,
    seen: Ranges,
    eligible: Ranges,
    withheld: Ranges,
    suppressed: Ranges,
    acked_wire: Ranges,
    highest_sent: u64,
    control_acked: bool,
    mode: String,
    released: bool,
    credit_copies: Vec<u64>,
    credit_limits: Vec<u64>,
    credit_history: Vec<BTreeMap<u64, u64>>,
    credit_release_history: Vec<BTreeMap<u64, u64>>,
    fence_acked: bool,
    pto_pause: Option<(usize, u64, u64)>,
    pto_proven: bool,
    held: Vec<(u64, Vec<u8>)>,
    replayed: bool,
    dropped: u64,
    duplicate_packets: u64,
    retries: u64,
    sent_packets: u64,
    received_packets: u64,
    ack_packets: u64,
    max_ack_ranges: usize,
    max_flights: usize,
    stream_blocked: u64,
    connection_blocked: u64,
    started: Instant,
}
impl Peer {
    fn connect(port: u16, count: usize, size: u64, mode: String) -> Result<Self> {
        ensure!(
            (1..=64).contains(&count) && size > 0 && size <= 1 << 30,
            "invalid workload"
        );
        ensure!(
            ["ordinary", "sparse", "loss", "reorder", "pto"].contains(&mode.as_str()),
            "invalid mode"
        );
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        let mut conn = Connection::connect(
            tls::client_config(b"h3")?,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 30,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 16,
                max_idle_timeout_ms: 30000,
                handshake_timeout_ms: 5000,
            },
        )?;
        let mut wire = Vec::with_capacity(1200);
        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            wire.clear();
            while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
                ensure!(socket.send(&wire)? == wire.len(), "partial UDP send");
                wire.clear();
            }
            if conn.probe_ready() {
                break;
            }
            ensure!(Instant::now() < deadline, "handshake timeout");
            match socket.recv(&mut buf) {
                Ok(n) => conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    conn.handle_timeout(clock::Instant::now())
                }
                Err(e) => return Err(e.into()),
            }
            while let Some(ev) = conn.poll_event() {
                if let quic::conn::Event::Lost(reason) = ev {
                    bail!("handshake lost: {reason}");
                }
            }
        }
        socket.set_nonblocking(true)?;
        let (streams, max_data, _) = conn.probe_limits();
        let (initial_limit, uni_streams, uni_limit) = conn.credit_probe_limits();
        ensure!(
            streams >= count as u64 && uni_streams >= 3 && uni_limit >= 3 && max_data >= 5,
            "insufficient initial stream/control credit"
        );
        // Static QPACK POST, https, literal :authority=localhost, path=/.
        let headers = b"\x00\x00\xd4\xd7\x50\x09localhost\xc1";
        let mut prefix = vec![1];
        put_varint(&mut prefix, headers.len() as u64);
        prefix.extend(headers);
        prefix.push(0);
        put_varint(&mut prefix, size);
        let end = prefix.len() as u64 + size;
        Ok(Self {
            socket,
            conn,
            wire,
            prefix,
            body_size: size,
            uploads: (0..count)
                .map(|_| Upload::new(end, initial_limit))
                .collect(),
            starts: vec![None; count],
            flights: Vec::new(),
            max_data,
            sent_data: 0,
            seen: Ranges::default(),
            eligible: Ranges::default(),
            withheld: Ranges::default(),
            suppressed: Ranges::default(),
            acked_wire: Ranges::default(),
            highest_sent: 0,
            control_acked: false,
            mode,
            released: false,
            credit_copies: vec![0; count],
            credit_limits: vec![initial_limit; count],
            credit_history: vec![BTreeMap::new(); count],
            credit_release_history: Vec::new(),
            fence_acked: false,
            pto_pause: None,
            pto_proven: false,
            held: Vec::new(),
            replayed: false,
            dropped: 0,
            duplicate_packets: 0,
            retries: 0,
            sent_packets: 0,
            received_packets: 0,
            ack_packets: 0,
            max_ack_ranges: 0,
            max_flights: 0,
            stream_blocked: 0,
            connection_blocked: 0,
            started: Instant::now(),
        })
    }
    fn send(&mut self, payload: &[u8]) -> Result<u64> {
        let pn = self.conn.probe_seal(payload, &mut self.wire)?;
        ensure!(
            self.socket.send(&self.wire)? == self.wire.len(),
            "partial UDP send"
        );
        self.highest_sent = pn;
        self.sent_packets += 1;
        Ok(pn)
    }
    fn payload(&self, work: &Work) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1100);
        match work {
            Work::Control => {
                frame::put_stream(&mut payload, 2, 0, false, &[0, 4, 0]);
                frame::put_stream(&mut payload, 6, 0, false, &[2]);
                frame::put_stream(&mut payload, 10, 0, false, &[3]);
            }
            Work::Ping | Work::Fence => payload.push(1),
            Work::Data {
                stream,
                offset,
                length,
                fin,
            } => {
                let mut bytes = [b'x'; CHUNK];
                for (i, byte) in bytes[..*length].iter_mut().enumerate() {
                    if let Some(&prefix) = self.prefix.get(*offset as usize + i) {
                        *byte = prefix;
                    }
                }
                frame::put_stream(
                    &mut payload,
                    *stream as u64 * 4,
                    *offset,
                    *fin,
                    &bytes[..*length],
                );
            }
        }
        payload
    }
    fn queue(&mut self, work: Work) -> Result<()> {
        ensure!(self.flights.len() < WINDOW, "flight budget exceeded");
        let pn = self.send(&self.payload(&work))?;
        self.flights.push(Flight {
            work,
            copies: vec![pn],
            last: Instant::now(),
        });
        self.max_flights = self.max_flights.max(self.flights.len());
        Ok(())
    }
    fn retry(&mut self) -> Result<()> {
        for i in 0..self.flights.len() {
            if self.flights[i].last.elapsed() < RETRY {
                continue;
            }
            ensure!(
                self.flights[i].copies.len() < 128,
                "retransmission budget exhausted"
            );
            let pn = self.send(&self.payload(&self.flights[i].work))?;
            self.flights[i].copies.push(pn);
            self.flights[i].last = Instant::now();
            self.retries += 1;
        }
        Ok(())
    }
    fn acknowledge(&mut self, ack: &Ranges) -> Result<()> {
        ensure!(
            ack.0.last().is_none_or(|&(_, hi)| hi <= self.highest_sent),
            "ACK of unsent packet"
        );
        let mut i = 0;
        while i < self.flights.len() {
            if !self.flights[i].copies.iter().any(|&pn| ack.contains(pn)) {
                i += 1;
                continue;
            }
            let flight = self.flights.swap_remove(i);
            match flight.work {
                Work::Control => self.control_acked = true,
                Work::Ping => {}
                Work::Fence => self.fence_acked = true,
                Work::Data {
                    stream,
                    offset,
                    length,
                    fin,
                } => {
                    let u = &mut self.uploads[stream];
                    if length != 0 {
                        u.acked.insert(offset, offset + length as u64 - 1)?;
                    }
                    if fin {
                        ensure!(
                            u.fin_sent && u.ready_fin(),
                            "FIN ACK before upload complete"
                        );
                        u.fin_acked = true;
                    }
                }
            }
        }
        Ok(())
    }
    fn process(&mut self, pn: u64, plain: &[u8], replay: bool) -> Result<()> {
        let frames: Vec<_> = frame::Iter::new(plain).collect::<Result<_>>()?;
        let credits = frames
            .iter()
            .any(|f| matches!(f, Frame::MaxStreamData { id, .. } if id & 3 == 0));
        if !replay
            && credits
            && ["loss", "reorder"].contains(&self.mode.as_str())
            && self.dropped < 2
        {
            self.held.push((pn, plain.to_vec()));
            self.dropped += 1;
            return Ok(());
        }
        if self.seen.contains(pn) {
            self.duplicate_packets += 1;
            return Ok(());
        }
        self.seen.insert(pn, pn)?;
        let eliciting = frames.iter().any(Frame::ack_eliciting);
        let sparse = self.mode == "sparse" && !self.released;
        if sparse && credits {
            self.withheld.insert(pn, pn)?;
        } else if sparse && !eliciting && self.suppressed.count() < 256 && pn.is_multiple_of(2) {
            self.suppressed.insert(pn, pn)?;
        } else {
            self.eligible.insert(pn, pn)?;
        }
        for f in frames {
            match f {
                Frame::Padding
                | Frame::Ping
                | Frame::HandshakeDone
                | Frame::NewToken
                | Frame::NewConnectionId { .. } => {}
                Frame::Ack {
                    largest,
                    first_range,
                    ranges,
                    range_count,
                    ..
                } => self.acknowledge(&decode_ack(largest, first_range, ranges, range_count)?)?,
                Frame::MaxData(limit) => self.max_data = self.max_data.max(limit),
                Frame::MaxStreamData { id, limit } if id & 3 == 0 => {
                    let i = (id / 4) as usize;
                    ensure!(i < self.uploads.len(), "credit for unknown stream");
                    self.uploads[i].limit = self.uploads[i].limit.max(limit);
                    self.credit_limits[i] = self.credit_limits[i].max(limit);
                    self.credit_copies[i] += 1;
                    ensure!(
                        self.credit_history[i].len() < 16384
                            || self.credit_history[i].contains_key(&limit),
                        "credit history budget exhausted"
                    );
                    *self.credit_history[i].entry(limit).or_default() += 1;
                    if self.mode == "pto" && !self.pto_proven {
                        if let Some((stream, held_limit, sent)) = self.pto_pause {
                            if i == stream && limit == held_limit {
                                ensure!(
                                    self.sent_packets == sent,
                                    "PTO probe transmitted during silence"
                                );
                                self.pto_proven = true;
                            } else if i == stream && limit > held_limit {
                                // Already-sent body packets may raise the retry's limit.
                                // Stay silent and wait for a new packet repeating that limit.
                                self.pto_pause = Some((stream, limit, sent));
                            }
                        } else {
                            self.pto_pause = Some((i, limit, self.sent_packets));
                        }
                    }
                }
                Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } => {}
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } if id & 3 == 0 => {
                    let u = self
                        .uploads
                        .get_mut((id / 4) as usize)
                        .context("unsolicited response stream")?;
                    u.response(offset, data, fin)?;
                }
                Frame::Stream { id, .. } if id & 3 == 3 => {} // peer's HTTP/3 control streams
                Frame::PathChallenge(data) => {
                    let mut response = vec![0x1b];
                    response.extend(data);
                    self.send(&response)?;
                }
                Frame::Close { error, reason, .. } => {
                    bail!("peer closed: {error} {}", String::from_utf8_lossy(reason))
                }
                other => bail!("unexpected frame: {other:?}"),
            }
            self.record_completions()?;
        }
        Ok(())
    }
    fn record_completions(&mut self) -> Result<()> {
        for (i, u) in self.uploads.iter_mut().enumerate() {
            if u.complete() && u.completed_ns.is_none() {
                u.completed_ns = Some(
                    self.starts[i]
                        .context("completed before start")?
                        .elapsed()
                        .as_nanos() as u64,
                );
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<bool> {
        let mut any = false;
        let mut buf = [0u8; 65536];
        for _ in 0..256 {
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };
            self.received_packets += 1;
            let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
            self.process(pn, plain, false)?;
            any = true;
        }
        Ok(any)
    }
    fn send_acks(&mut self) -> Result<()> {
        self.max_ack_ranges = self.max_ack_ranges.max(self.eligible.0.len());
        for bytes in ack_chunks(&self.eligible, ACK_BUDGET)? {
            self.send(&bytes)?;
            self.ack_packets += 1;
        }
        self.acked_wire = self.eligible.clone();
        Ok(())
    }
    fn run(&mut self, timeout: Duration) -> Result<()> {
        self.queue(Work::Control)?;
        self.sent_data = 5;
        let mut cursor = 0;
        let mut last_ping = Instant::now();
        while !self.uploads.iter().all(Upload::complete) {
            ensure!(
                self.started.elapsed() < timeout,
                "timeout: missing body ACK, credit, FIN ACK or response"
            );
            let received = self.receive()?;
            if self.pto_pause.is_some() && !self.pto_proven {
                std::thread::yield_now();
                continue;
            }
            self.retry()?;
            let all_body = self.uploads.iter().all(Upload::ready_fin);
            if all_body && self.mode == "reorder" && !self.replayed {
                for (pn, plain) in self.held.clone().into_iter().rev() {
                    self.process(pn, &plain, true)?;
                    self.process(pn, &plain, true)?;
                }
                self.replayed = true;
            }
            let release = self.mode != "sparse"
                || self
                    .credit_history
                    .iter()
                    .all(|h| h.last_key_value().is_some_and(|(_, &v)| v >= 10));
            if release && !self.released {
                for (lo, hi) in self.withheld.0.clone() {
                    self.eligible.insert(lo, hi)?;
                }
                self.credit_release_history = self.credit_history.clone();
                self.released = true;
                self.send_acks()?;
                if self.mode == "sparse" {
                    self.queue(Work::Fence)?;
                }
            } else if received {
                self.send_acks()?;
            }
            if self.control_acked {
                let mut idle = 0;
                while self.flights.len() < WINDOW && idle < self.uploads.len() {
                    let i = cursor;
                    cursor = (cursor + 1) % self.uploads.len();
                    let u = &self.uploads[i];
                    let credit_pause = self.mode == "sparse"
                        && !self.released
                        && !self.credit_history[i].is_empty();
                    if !credit_pause
                        && u.sent < u.end
                        && u.sent < u.limit
                        && self.sent_data < self.max_data
                    {
                        let offset = u.sent;
                        let length = (u.end - offset)
                            .min(u.limit - offset)
                            .min(self.max_data - self.sent_data)
                            .min(CHUNK as u64) as usize;
                        self.starts[i].get_or_insert_with(Instant::now);
                        self.queue(Work::Data {
                            stream: i,
                            offset,
                            length,
                            fin: false,
                        })?;
                        self.uploads[i].sent += length as u64;
                        self.sent_data += length as u64;
                        idle = 0;
                    } else if u.ready_fin()
                        && !u.fin_sent
                        && self.released
                        && (self.mode != "sparse" || self.fence_acked)
                    {
                        let offset = u.end;
                        self.uploads[i].finish()?;
                        self.queue(Work::Data {
                            stream: i,
                            offset,
                            length: 0,
                            fin: true,
                        })?;
                        idle = 0;
                    } else {
                        if u.sent < u.end && u.sent == u.limit {
                            self.stream_blocked += 1;
                        }
                        if u.sent < u.end && self.sent_data == self.max_data {
                            self.connection_blocked += 1;
                        }
                        idle += 1;
                    }
                }
            }
            self.record_completions()?;
            if self.flights.len() < WINDOW && last_ping.elapsed() >= Duration::from_millis(5) {
                self.queue(Work::Ping)?;
                last_ping = Instant::now();
            }
            if !received {
                std::thread::yield_now();
            }
        }
        self.send_acks()?;
        // Graceful close does not count as a completed request or ACK fence.
        self.send(&[0x1d, 0, 0])?;
        ensure!(
            self.uploads.iter().all(|u| u.completed_ns.is_some()),
            "missing latency"
        );
        Ok(())
    }
    fn report(&self, error: Option<String>) -> Value {
        let prefix = self.prefix.len() as u64;
        json!({"phase": if error.is_some() {"failed"} else {"done"}, "error": error,
            "mode": self.mode, "body_bytes_per_stream": self.body_size,
            "elapsed_ns": self.started.elapsed().as_nanos() as u64,
            "completed": self.uploads.iter().filter(|u| u.complete()).count(),
            "latencies_ns": self.uploads.iter().filter_map(|u| u.completed_ns).collect::<Vec<_>>(),
            "streams": self.uploads.iter().enumerate().map(|(i,u)| json!({"id": i * 4,
                "sent": u.sent, "end": u.end, "acked_ranges": u.acked.0,
                "body_acked": u.acked.0.iter().map(|&(lo,hi)| (hi + 1).saturating_sub(lo.max(prefix))).sum::<u64>(),
                "fin_sent": u.fin_sent, "fin_acked": u.fin_acked,
                "response_ranges": u.response.0, "response_fin": u.response_fin,
                "latency_ns": u.completed_ns, "final_limit": u.limit})).collect::<Vec<_>>(),
            "sent_data": self.sent_data, "max_data": self.max_data, "control_acked": self.control_acked,
            "sent_packets": self.sent_packets, "received_packets": self.received_packets,
            "ack_packets": self.ack_packets, "max_ack_ranges": self.max_ack_ranges,
            "max_flights": self.max_flights, "retransmissions": self.retries,
            "duplicate_packets": self.duplicate_packets, "dropped_credit_packets": self.dropped,
            "replayed": self.replayed, "credit_frames_per_stream": self.credit_copies,
            "credit_history": self.credit_history.iter().map(|h| h.iter().map(|(&k,&v)| (k,v)).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "credit_release_history": self.credit_release_history.iter().map(|h| h.iter().map(|(&k,&v)| (k,v)).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "pto_proven": self.pto_proven, "sparse_fence_acked": self.fence_acked,
            "received_ranges": self.seen.0, "acked_packet_ranges": self.acked_wire.0,
            "withheld_credit_ranges": self.withheld.0, "suppressed_ack_only_ranges": self.suppressed.0,
            "stream_blocked_observations": self.stream_blocked,
            "connection_blocked_observations": self.connection_blocked,
        })
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--ack-vectors" {
        let mut ranges = Ranges::default();
        for base in [
            0,
            63,
            16383,
            (1 << 30) - 1,
            credit_ledger::MAX_VARINT - 10000,
        ] {
            for i in 0..1000 {
                ranges.insert(base + i * 3, base + i * 3)?;
            }
        }
        println!(
            "{}",
            json!({"ranges": ranges.0, "cases": ([33,64,255,1100].iter().map(|&budget|
            json!({"budget": budget, "chunks": ack_chunks(&ranges, budget).unwrap()})).collect::<Vec<_>>())})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 6,
        "usage: peer PORT STREAMS BODY_BYTES ordinary|sparse|loss|reorder|pto TIMEOUT_SECONDS"
    );
    let mut peer = Peer::connect(
        args[1].parse()?,
        args[2].parse()?,
        args[3].parse()?,
        args[4].clone(),
    )?;
    let result = peer.run(Duration::from_secs(args[5].parse()?));
    println!(
        "{}",
        peer.report(result.as_ref().err().map(|e| format!("{e:#}")))
    );
    result
}
