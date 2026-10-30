//! Bounded native response-credit correctness fixture; no throughput claim.
#![allow(dead_code)]
mod clock;
mod credit_control;
mod credit_ledger;
mod quic;
mod response_ledger;
mod tls;
mod udp_evidence;
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
use credit_ledger::{Ranges, ack_chunks, decode_ack};
use quic::{
    conn::{Connection, LocalParamsInput},
    frame::{self, Frame},
    varint::put_varint,
};
use response_ledger::{Copies, RESPONSE, Response};
use serde_json::{Value, json};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

const REQUEST: &[u8] = b"\x01\x10\x00\x00\xd1\xd7\x50\x09localhost\xc1";
const MAX_EVENTS: usize = 131072;
const MAX_FLIGHTS: usize = 2048;
const SEND_WINDOW: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    Bootstrap,
    Request(usize),
    Grant(usize, u64),
    Ping,
    Fence,
}
impl Work {
    fn fields(self) -> (u8, u64, u64) {
        match self {
            Self::Bootstrap => (0, 3, 3),
            Self::Request(i) => (1, i as u64 * 4, 0),
            Self::Grant(i, n) => (2, i as u64 * 4, n),
            Self::Ping => (3, 0, 0),
            Self::Fence => (4, 0, 0),
        }
    }
    fn payload(self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64);
        match self {
            Self::Bootstrap => {
                b.push(0x13);
                put_varint(&mut b, 1); // MAX_STREAMS uni, initially zero
                b.push(0x11);
                put_varint(&mut b, 3);
                put_varint(&mut b, 3);
                frame::put_stream(&mut b, 2, 0, false, &[0, 4, 0]);
                frame::put_stream(&mut b, 6, 0, false, &[2]);
                frame::put_stream(&mut b, 10, 0, false, &[3]);
            }
            Self::Request(i) => frame::put_stream(&mut b, i as u64 * 4, 0, true, REQUEST),
            Self::Grant(i, n) => {
                b.push(0x11);
                put_varint(&mut b, i as u64 * 4);
                put_varint(&mut b, n);
            }
            Self::Ping | Self::Fence => b.push(1),
        }
        b
    }
}
struct Flight {
    work: Work,
    copies: Copies,
}
type Sent = (u64, u8, u64, u64, bool, bool);
type Received = (u64, u64, u64, Vec<u8>, bool, u8);
struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    udp_before: Value,
    responses: Vec<Response>,
    step: u64,
    mode: String,
    epoch: Instant,
    flights: Vec<Flight>,
    sent: Vec<Sent>,
    frames: Vec<Received>,
    acked_work: Vec<(u8, u64, u64)>,
    seen: Ranges,
    eligible: Ranges,
    withheld: Ranges,
    acked_wire: Ranges,
    acked_by_server: Ranges,
    dropped_outgoing: Ranges,
    control: u8,
    bootstrap_acked: bool,
    request_acked: Vec<bool>,
    grant_acked: Vec<u64>,
    released: bool,
    fence_acked: bool,
    held: Vec<(u64, Vec<u8>)>,
    replayed: bool,
    highest_sent: u64,
    handshake_sent: u64,
    handshake_received: u64,
    sent_packets: u64,
    received_packets: u64,
    ack_packets: u64,
    duplicate_packets: u64,
    retries: u64,
    dropped: u64,
    dropped_grants: u64,
    max_ack_ranges: usize,
    completed: usize,
    interval: Option<Value>,
    workload_start_ns: Option<u64>,
    workload_end_ns: Option<u64>,
}
impl Peer {
    fn connect(port: u16, count: usize, step: u64, mode: String) -> Result<Self> {
        ensure!(
            (1..=512).contains(&count) && [1, 2, 25].contains(&step),
            "invalid workload"
        );
        ensure!(
            ["each", "withheld", "sparse", "loss", "reorder"].contains(&mode.as_str()),
            "invalid mode"
        );
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        // Retain the observed capacity/drop count: the host may cap this request.
        socket2::SockRef::from(&socket).set_recv_buffer_size(4 << 20)?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        let udp_before = udp_evidence::snapshot(&socket);
        let mut conn = Connection::connect(
            tls::client_config(b"h3")?,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 20,
                initial_max_stream_data: step,
                // No server control bytes can be consumed by the handshake engine.
                initial_max_streams_uni: 0,
                max_idle_timeout_ms: 30000,
                handshake_timeout_ms: 5000,
            },
        )?;
        let mut wire = Vec::with_capacity(1200);
        let mut buf = [0; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut handshake_sent, mut handshake_received) = (0, 0);
        loop {
            wire.clear();
            while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
                ensure!(socket.send(&wire)? == wire.len(), "partial UDP send");
                handshake_sent += 1;
                wire.clear();
            }
            if conn.probe_ready() {
                break;
            }
            ensure!(Instant::now() < deadline, "handshake timeout");
            match socket.recv(&mut buf) {
                Ok(n) => {
                    handshake_received += 1;
                    conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?;
                }
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
        let (streams, max_data, _) = conn.probe_limits();
        let (stream_limit, uni_count, uni_limit) = conn.response_probe_limits();
        ensure!(
            streams >= count as u64
                && max_data >= 5 + REQUEST.len() as u64 * count as u64
                && stream_limit >= REQUEST.len() as u64
                && uni_count >= 3
                && uni_limit >= 3,
            "insufficient request/control credit"
        );
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            conn,
            wire,
            udp_before,
            responses: (0..count)
                .map(|_| Response::new(step))
                .collect::<Result<_>>()?,
            step,
            mode,
            epoch: Instant::now(),
            flights: Vec::new(),
            sent: Vec::new(),
            frames: Vec::new(),
            acked_work: Vec::new(),
            seen: Ranges::default(),
            eligible: Ranges::default(),
            withheld: Ranges::default(),
            acked_wire: Ranges::default(),
            acked_by_server: Ranges::default(),
            dropped_outgoing: Ranges::default(),
            control: 0,
            bootstrap_acked: false,
            request_acked: vec![false; count],
            grant_acked: vec![step; count],
            released: false,
            fence_acked: false,
            held: Vec::new(),
            replayed: false,
            highest_sent: 0,
            handshake_sent,
            handshake_received,
            sent_packets: 0,
            received_packets: 0,
            ack_packets: 0,
            duplicate_packets: 0,
            retries: 0,
            dropped: 0,
            dropped_grants: 0,
            max_ack_ranges: 0,
            completed: 0,
            interval: None,
            workload_start_ns: None,
            workload_end_ns: None,
        })
    }
    fn now(&self) -> u64 {
        self.epoch
            .elapsed()
            .as_nanos()
            .try_into()
            .expect("fixture clock overflow")
    }
    fn send(&mut self, bytes: &[u8], drop: bool) -> Result<u64> {
        ensure!(
            self.sent_packets + self.dropped_grants < MAX_EVENTS as u64,
            "packet history exhausted"
        );
        let pn = self.conn.probe_seal(bytes, &mut self.wire)?;
        if drop {
            self.dropped_outgoing.insert(pn, pn)?;
            self.dropped_grants += 1;
        } else {
            ensure!(
                self.socket.send(&self.wire)? == self.wire.len(),
                "partial UDP send"
            );
            self.sent_packets += 1;
        }
        self.highest_sent = pn;
        Ok(pn)
    }
    fn transmit(&mut self, work: Work, retry: bool) -> Result<u64> {
        ensure!(self.sent.len() < MAX_EVENTS, "work transcript exhausted");
        let drop =
            self.mode == "loss" && matches!(work, Work::Grant(..)) && self.dropped_grants == 0;
        let pn = self.send(&work.payload(), drop)?;
        let (kind, id, limit) = work.fields();
        self.sent.push((pn, kind, id, limit, !drop, retry));
        Ok(pn)
    }
    fn queue(&mut self, work: Work) -> Result<()> {
        ensure!(self.flights.len() < MAX_FLIGHTS, "flight history exhausted");
        let now = self.now();
        if let Work::Request(i) = work {
            self.responses[i].start(now)?;
        }
        let pn = self.transmit(work, false)?;
        self.flights.push(Flight {
            work,
            copies: Copies::new(pn, now),
        });
        Ok(())
    }
    fn retry(&mut self) -> Result<()> {
        let now = self.now();
        for i in 0..self.flights.len() {
            if self.flights[i].copies.due(now) {
                ensure!(
                    self.flights[i].copies.packets.len() < response_ledger::HISTORY,
                    "retransmission history exhausted"
                );
                let pn = self.transmit(self.flights[i].work, true)?;
                self.flights[i].copies.retry(pn, now)?;
                self.retries += 1;
            }
        }
        Ok(())
    }
    fn acknowledge(&mut self, ack: Ranges) -> Result<()> {
        ensure!(
            ack.0.last().is_none_or(|&(_, hi)| hi <= self.highest_sent),
            "ACK of unsent packet"
        );
        for &(lo, hi) in &ack.0 {
            ensure!(
                !self
                    .dropped_outgoing
                    .0
                    .iter()
                    .any(|&(a, b)| a <= hi && b >= lo),
                "ACK of intentionally unsent grant"
            );
            self.acked_by_server.insert(lo, hi)?;
        }
        let mut i = 0;
        while i < self.flights.len() {
            if !self.flights[i].copies.acked(|pn| ack.contains(pn)) {
                i += 1;
                continue;
            }
            let f = self.flights.swap_remove(i);
            self.acked_work.push(f.work.fields());
            match f.work {
                Work::Bootstrap => self.bootstrap_acked = true,
                Work::Request(s) => self.request_acked[s] = true,
                Work::Grant(s, n) => self.grant_acked[s] = self.grant_acked[s].max(n),
                Work::Fence => self.fence_acked = true,
                Work::Ping => {}
            }
        }
        Ok(())
    }
    fn process(&mut self, pn: u64, plain: &[u8], replay: bool) -> Result<()> {
        let frames: Vec<_> = frame::Iter::new(plain).collect::<Result<_>>()?;
        let response = frames
            .iter()
            .any(|f| matches!(f,Frame::Stream{id,..} if id&3==0));
        let drop = !replay
            && response
            && ["loss", "reorder"].contains(&self.mode.as_str())
            && self.dropped < 2;
        let duplicate = self.seen.contains(pn);
        // Validate even deliberately dropped/duplicate authenticated frames.
        for f in &frames {
            if let Frame::Stream {
                id,
                offset,
                data,
                fin,
            } = f
            {
                let end = offset
                    .checked_add(data.len() as u64)
                    .context("frame offset overflow")?;
                let (expected, limit) = if *id == 3 {
                    (&[0, 4, 0][..], 3)
                } else {
                    ensure!(id & 3 == 0, "unexpected server stream {id}");
                    let r = self
                        .responses
                        .get((id / 4) as usize)
                        .context("unsolicited response")?;
                    ensure!(r.started.is_some(), "response before request");
                    (RESPONSE, r.limit)
                };
                ensure!(
                    end <= expected.len() as u64 && end <= limit,
                    "wire length/credit exceeded"
                );
                ensure!(
                    *data == &expected[*offset as usize..end as usize],
                    "wire bytes differ"
                );
                ensure!(
                    !fin || (*id != 3 && end == 25),
                    "wire premature/control FIN"
                );
                ensure!(self.frames.len() < MAX_EVENTS, "frame transcript exhausted");
                self.frames.push((
                    pn,
                    *id,
                    *offset,
                    data.to_vec(),
                    *fin,
                    if drop {
                        1
                    } else if duplicate {
                        3
                    } else if replay {
                        2
                    } else {
                        0
                    },
                ));
            }
        }
        if drop {
            if self.mode == "reorder" {
                self.held.push((pn, plain.to_vec()));
            }
            self.dropped += 1;
            return Ok(());
        }
        if duplicate {
            self.duplicate_packets += 1;
            return Ok(());
        }
        self.seen.insert(pn, pn)?;
        let eliciting = frames.iter().any(Frame::ack_eliciting);
        if response
            && !self.released
            && (self.mode == "withheld" || (self.mode == "sparse" && pn.is_multiple_of(2)))
        {
            self.withheld.insert(pn, pn)?;
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
                } => self.acknowledge(decode_ack(largest, first_range, ranges, range_count)?)?,
                Frame::Stream {
                    id: 3,
                    offset,
                    data,
                    fin: false,
                } => {
                    for n in offset..offset + data.len() as u64 {
                        self.control |= 1 << n;
                    }
                }
                Frame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                } if id & 3 == 0 => {
                    let now = self.now();
                    if self.responses[(id / 4) as usize].receive(offset, data, fin, now)? {
                        self.completed += 1;
                    }
                }
                Frame::MaxData(_) | Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } => {}
                Frame::PathChallenge(data) => {
                    let mut b = vec![0x1b];
                    b.extend(data);
                    self.send(&b, false)?;
                }
                Frame::Close { error, reason, .. } => {
                    bail!("server closed: {error} {}", String::from_utf8_lossy(reason))
                }
                f => bail!("unexpected frame: {f:?}"),
            }
        }
        if eliciting {
            self.send_acks()?;
        }
        Ok(())
    }
    fn receive(&mut self) -> Result<bool> {
        let mut buf = [0; 65536];
        let mut any = false;
        for _ in 0..256 {
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            };
            self.received_packets += 1;
            ensure!(
                self.received_packets <= MAX_EVENTS as u64,
                "receive history exhausted"
            );
            let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
            self.process(pn, plain, false)?;
            any = true;
        }
        Ok(any)
    }
    fn send_acks(&mut self) -> Result<()> {
        self.max_ack_ranges = self.max_ack_ranges.max(self.eligible.0.len());
        for bytes in ack_chunks(&self.eligible, 1000)? {
            self.send(&bytes, false)?;
            self.ack_packets += 1;
        }
        self.acked_wire = self.eligible.clone();
        Ok(())
    }
    fn bootstrap(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.queue(Work::Bootstrap)?;
        while !self.bootstrap_acked || self.control != 7 {
            ensure!(Instant::now() < deadline, "control bootstrap timeout");
            if !self.receive()? {
                std::thread::yield_now();
            }
            self.retry()?;
        }
        self.send_acks()?;
        Ok(())
    }
    fn run(&mut self, timeout: Duration) -> Result<()> {
        ensure!(
            self.bootstrap_acked && self.control == 7,
            "unbootstrapped measurement"
        );
        let deadline = Instant::now() + timeout;
        for i in 0..self.responses.len() {
            while self.flights.len() >= SEND_WINDOW {
                ensure!(Instant::now() < deadline, "request ACK window timeout");
                if !self.receive()? {
                    std::thread::yield_now();
                }
                self.retry()?;
            }
            self.queue(Work::Request(i))?;
            if i % 16 == 15 {
                self.receive()?;
            }
        }
        let mut last_ping = Instant::now();
        let mut fenced = false;
        loop {
            ensure!(Instant::now() < deadline, "response/grant/ACK timeout");
            let any = self.receive()?;
            self.retry()?;
            for i in 0..self.responses.len() {
                if self.flights.len() >= SEND_WINDOW {
                    break;
                }
                let r = &self.responses[i];
                if r.prefix() == r.limit && r.limit < 25 && self.grant_acked[i] == r.limit {
                    let next = (r.limit + self.step).min(25);
                    self.queue(Work::Grant(i, next))?;
                    self.responses[i].grant(next)?;
                }
                if i % 16 == 15 {
                    self.receive()?;
                }
            }
            if self.completed == self.responses.len() && !self.released {
                if self.mode == "reorder" {
                    for (pn, plain) in std::mem::take(&mut self.held).into_iter().rev() {
                        self.process(pn, &plain, true)?;
                        self.process(pn, &plain, true)?;
                    }
                    self.replayed = true;
                }
                for (lo, hi) in self.withheld.0.clone() {
                    self.eligible.insert(lo, hi)?;
                }
                self.released = true;
                self.send_acks()?;
            }
            if self.released && self.flights.is_empty() && !fenced {
                self.queue(Work::Fence)?;
                fenced = true;
            }
            if self.fence_acked && self.flights.is_empty() {
                break;
            }
            if last_ping.elapsed() >= Duration::from_millis(50)
                && !self.flights.iter().any(|f| f.work == Work::Ping)
            {
                self.queue(Work::Ping)?;
                last_ping = Instant::now();
            }
            if !any {
                std::thread::yield_now();
            }
        }
        ensure!(
            self.completed == self.responses.len() && self.request_acked.iter().all(|&a| a),
            "incomplete accounting"
        );
        for r in &self.responses {
            r.latency()?;
        }
        self.send_acks()?;
        ensure!(self.acked_wire.0 == self.seen.0, "missing final packet ACK");
        Ok(())
    }
    fn report(&self, error: Option<String>) -> Value {
        json!({"phase":if error.is_some(){"failed"}else{"done"},"error":error,"mode":self.mode,"step":self.step,"count":self.responses.len(),
            "interval":self.interval,"workload_start_ns":self.workload_start_ns,"workload_end_ns":self.workload_end_ns,
            "udp":udp_evidence::interval(&self.udp_before,&self.socket),"port":self.socket.local_addr().unwrap().port(),
            "completed":self.completed,"control_bytes":self.control.count_ones(),"bootstrap_acked":self.bootstrap_acked,"fence_acked":self.fence_acked,
            "streams":self.responses.iter().enumerate().map(|(i,r)|json!({"id":i*4,"limit":r.limit,"seen":r.seen,"fin":r.fin,"started_ns":r.started,"completed_ns":r.completed,"latency_ns":r.latency().ok(),"frames":r.frames,"duplicates":r.duplicates,"request_acked":self.request_acked[i],"grant_acked":self.grant_acked[i]})).collect::<Vec<_>>(),
            "sent_work":self.sent,"frames":self.frames,"acked_work":self.acked_work,"unacked_work":self.flights.len(),
            "received_ranges":self.seen.0,"acked_packet_ranges":self.acked_wire.0,"server_ack_ranges":self.acked_by_server.0,"withheld_ranges":self.withheld.0,
            "sent_packets":self.sent_packets,"received_packets":self.received_packets,"handshake_sent":self.handshake_sent,"handshake_received":self.handshake_received,
            "retries":self.retries,"ack_packets":self.ack_packets,"duplicate_packets":self.duplicate_packets,"dropped_response_packets":self.dropped,"dropped_grants":self.dropped_grants,"replayed":self.replayed,"max_ack_ranges":self.max_ack_ranges})
    }
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 6 || (a.len() == 7 && a[6] == "--controlled"),
        "usage: peer PORT COUNT STEP each|withheld|sparse|loss|reorder TIMEOUT_SECONDS [--controlled]"
    );
    let secs: u64 = a[5].parse()?;
    ensure!((1..=60).contains(&secs), "invalid timeout");
    let timeout = Duration::from_secs(secs);
    let controlled = a.len() == 7;
    let mut peer = Peer::connect(a[1].parse()?, a[2].parse()?, a[3].parse()?, a[4].clone())?;
    let result = (|| -> Result<()> {
        peer.bootstrap(timeout)?;
        if controlled {
            credit_control::emit(
                json!({"phase":"ready","port":peer.socket.local_addr()?.port(),"bootstrap_acked":peer.bootstrap_acked,"control_bytes":3,"started_requests":peer.responses.iter().filter(|r|r.started.is_some()).count(),"udp":udp_evidence::interval(&peer.udp_before,&peer.socket)}),
            )?;
            credit_control::command(0, "start", timeout)?;
        }
        let start = credit_control::Start::now()?;
        peer.workload_start_ns = Some(peer.now());
        let result = peer.run(timeout);
        peer.workload_end_ns = Some(peer.now());
        peer.interval = Some(start.finish()?);
        result
    })();
    credit_control::emit(peer.report(result.as_ref().err().map(|e| format!("{e:#}"))))?;
    if controlled {
        credit_control::command(0, "exit", timeout)?;
    }
    result
}
