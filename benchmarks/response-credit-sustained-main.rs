//! Sustained, bounded native response-credit workload. Not a production client.
#![allow(dead_code)]
#![recursion_limit = "256"]
mod clock;
mod credit_control;
mod credit_ledger;
mod quic;
mod response_ledger;
mod tls;
mod udp_evidence;
mod waves;
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
use response_ledger::{Copies, RESPONSE};
use serde_json::{Value, json};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};
use waves::{Delivery, Grants, Ready, Waves};

const REQUEST: &[u8] = b"\x01\x10\x00\x00\xd1\xd7\x50\x09localhost\xc1";
const MAX_EVENTS: usize = 131072;
const MAX_FLIGHTS: usize = 64;
const BATCH: usize = 32;
fn model<T>(result: std::result::Result<T, &'static str>) -> Result<T> {
    result.map_err(anyhow::Error::msg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    Bootstrap,
    Request(u64),
    Grant(u64, u64),
    Ping,
    Fence,
}
impl Work {
    fn fields(self) -> (u8, u64, u64) {
        match self {
            Self::Bootstrap => (0, 3, 3),
            Self::Request(s) => (1, s, 0),
            Self::Grant(s, n) => (2, s, n),
            Self::Ping => (3, 0, 0),
            Self::Fence => (4, 0, 0),
        }
    }
    fn append(self, b: &mut Vec<u8>) {
        match self {
            Self::Bootstrap => {
                b.push(0x13);
                put_varint(b, 1);
                b.push(0x11);
                put_varint(b, 3);
                put_varint(b, 3);
                frame::put_stream(b, 2, 0, false, &[0, 4, 0]);
                frame::put_stream(b, 6, 0, false, &[2]);
                frame::put_stream(b, 10, 0, false, &[3]);
            }
            Self::Request(s) => frame::put_stream(b, s, 0, true, REQUEST),
            Self::Grant(s, n) => {
                b.push(0x11);
                put_varint(b, s);
                put_varint(b, n);
            }
            Self::Ping | Self::Fence => b.push(1),
        }
    }
}
struct Flight {
    work: Vec<Work>,
    copies: Copies,
}
type Sent = (u64, u8, u64, u64, bool, bool);
type Received = (u64, u64, u64, Vec<u8>, bool, u8);
struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    udp_before: Value,
    waves: Waves,
    schedule: String,
    mode: String,
    trace: bool,
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
    fence_acked: bool,
    ack_pending: bool,
    released: bool,
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
    max_flights: usize,
    completed: usize,
    request_acks: usize,
    grant_acks: usize,
    grants: usize,
    blocked_streams: u64,
    blocked_data: u64,
    interval: Option<Value>,
    workload_start_ns: Option<u64>,
    workload_end_ns: Option<u64>,
}
impl Peer {
    fn connect(
        port: u16,
        count: usize,
        window: usize,
        schedule: String,
        mode: String,
        trace: bool,
    ) -> Result<Self> {
        let grants = match schedule.as_str() {
            "byte" => Grants::Bytes(1),
            "two-byte" => Grants::Bytes(2),
            "two-fragment" => Grants::TwoFragments,
            "full" => Grants::Full,
            _ => bail!("invalid schedule"),
        };
        ensure!(
            (1..=512).contains(&window) && (window..=1 << 22).contains(&count),
            "invalid workload"
        );
        ensure!(
            ["each", "withheld", "sparse", "loss", "reorder"].contains(&mode.as_str()),
            "invalid mode"
        );
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket2::SockRef::from(&socket).set_recv_buffer_size(4 << 20)?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_millis(10)))?;
        let udp_before = udp_evidence::snapshot(&socket);
        let mut conn = Connection::connect(
            tls::client_config(b"h3")?,
            "localhost",
            LocalParamsInput {
                // Aggregate credit is explicit and sufficient for every byte, including SETTINGS.
                initial_max_data: count as u64 * 25 + 3,
                initial_max_stream_data: model(grants.initial())?,
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
            max_data >= 5
                && stream_limit >= REQUEST.len() as u64
                && uni_count >= 3
                && uni_limit >= 3,
            "insufficient request/control credit"
        );
        let waves = model(Waves::new(
            grants,
            window,
            count,
            REQUEST.len() as u64,
            5,
            max_data,
            streams,
        ))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            conn,
            wire,
            udp_before,
            waves,
            schedule,
            mode,
            trace,
            epoch: Instant::now(),
            flights: Vec::with_capacity(MAX_FLIGHTS),
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
            fence_acked: false,
            ack_pending: false,
            released: false,
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
            max_flights: 0,
            completed: 0,
            request_acks: 0,
            grant_acks: 0,
            grants: 0,
            blocked_streams: 0,
            blocked_data: 0,
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
    fn transmit(&mut self, work: &[Work], retry: bool) -> Result<u64> {
        ensure!(
            !work.is_empty() && work.len() <= BATCH,
            "invalid packet work batch"
        );
        let mut payload = Vec::with_capacity(1000);
        for w in work {
            w.append(&mut payload);
        }
        ensure!(payload.len() <= 1000, "work batch exceeds datagram budget");
        let drop = self.mode == "loss"
            && work.iter().any(|w| matches!(w, Work::Grant(..)))
            && self.dropped_grants == 0;
        let pn = self.send(&payload, drop)?;
        if self.trace {
            ensure!(
                self.sent.len() + work.len() <= MAX_EVENTS,
                "work transcript exhausted"
            );
            for w in work {
                let (k, s, n) = w.fields();
                self.sent.push((pn, k, s, n, !drop, retry));
            }
        }
        Ok(pn)
    }
    fn queue(&mut self, work: Vec<Work>) -> Result<()> {
        ensure!(self.flights.len() < MAX_FLIGHTS, "flight history exhausted");
        let now = self.now();
        let pn = self.transmit(&work, false)?;
        for w in &work {
            match *w {
                Work::Request(s) => model(self.waves.start(s, now))?,
                Work::Grant(s, n) => {
                    model(self.waves.grant(s, n))?;
                    self.grants += 1;
                }
                _ => {}
            }
        }
        self.flights.push(Flight {
            work,
            copies: Copies::new(pn, now),
        });
        self.max_flights = self.max_flights.max(self.flights.len());
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
                let work = self.flights[i].work.clone();
                let pn = self.transmit(&work, true)?;
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
            for w in self.flights.swap_remove(i).work {
                if self.trace {
                    ensure!(
                        self.acked_work.len() < MAX_EVENTS,
                        "ACK transcript exhausted"
                    );
                    self.acked_work.push(w.fields());
                }
                match w {
                    Work::Bootstrap => self.bootstrap_acked = true,
                    Work::Request(s) => {
                        model(self.waves.ack_request(s))?;
                        self.request_acks += 1;
                    }
                    Work::Grant(s, n) => {
                        model(self.waves.ack_grant(s, n))?;
                        self.grant_acks += 1;
                    }
                    Work::Fence => self.fence_acked = true,
                    Work::Ping => {}
                }
            }
        }
        Ok(())
    }
    fn process(&mut self, pn: u64, plain: &[u8], replay: bool) -> Result<()> {
        let frames: Vec<_> = frame::Iter::new(plain).collect::<Result<_>>()?;
        let response = frames
            .iter()
            .any(|f| matches!(f, Frame::Stream{id,..} if id&3==0));
        let drop = !replay
            && response
            && ["loss", "reorder"].contains(&self.mode.as_str())
            && self.dropped < 2;
        let duplicate = self.seen.contains(pn);
        let eliciting = frames.iter().any(Frame::ack_eliciting);
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
                    let index = model(self.waves.index(*id))?;
                    let limit = if let Some(i) = index {
                        ensure!(
                            self.waves.slots[i].started.is_some(),
                            "response before request"
                        );
                        self.waves.slots[i].limit
                    } else {
                        25
                    };
                    (RESPONSE, limit)
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
                if self.trace {
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
            self.ack_pending |= eliciting;
            return Ok(());
        }
        self.seen.insert(pn, pn)?;
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
                    if model(self.waves.receive(id, offset, data, fin, now))? == Delivery::Complete
                    {
                        self.completed += 1;
                    }
                }
                Frame::MaxData(n) => model(self.waves.max_data(n))?,
                Frame::MaxStreams { uni: false, limit } => model(self.waves.max_streams(limit))?,
                Frame::MaxStreams { uni: true, .. } | Frame::MaxStreamData { .. } => {}
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
        self.ack_pending |= eliciting;
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
            let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
            self.process(pn, plain, false)?;
            any = true;
        }
        if self.ack_pending {
            self.send_acks()?;
        }
        Ok(any)
    }
    fn send_acks(&mut self) -> Result<()> {
        self.max_ack_ranges = self.max_ack_ranges.max(self.eligible.0.len());
        for bytes in ack_chunks(&self.eligible, 1000)? {
            self.send(&bytes, false)?;
            self.ack_packets += 1;
        }
        self.acked_wire.clone_from(&self.eligible);
        self.ack_pending = false;
        Ok(())
    }
    fn bootstrap(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        self.queue(vec![Work::Bootstrap])?;
        while !self.bootstrap_acked || self.control != 7 {
            ensure!(Instant::now() < deadline, "control bootstrap timeout");
            if !self.receive()? {
                std::thread::yield_now();
            }
            self.retry()?;
        }
        self.send_acks()
    }
    fn release(&mut self) -> Result<()> {
        if self.mode == "reorder" && !self.replayed {
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
        self.send_acks()
    }
    fn run(&mut self, timeout: Duration) -> Result<()> {
        ensure!(
            self.bootstrap_acked && self.control == 7,
            "unbootstrapped measurement"
        );
        let deadline = Instant::now() + timeout;
        let mut last_ping = Instant::now();
        let mut fenced = false;
        loop {
            ensure!(
                Instant::now() < deadline,
                "response/grant/ACK/credit timeout"
            );
            let any = self.receive()?;
            self.retry()?;
            if !self.waves.slots.is_empty()
                && self.waves.slots.iter().all(|s| s.completed.is_some())
                && !self.released
            {
                self.release()?;
            }
            if !self.waves.slots.is_empty()
                && self
                    .waves
                    .slots
                    .iter()
                    .all(|s| s.completed.is_some() && s.request_acked && s.grant_acked == 25)
            {
                model(self.waves.retire())?;
            }
            if self.waves.slots.is_empty() && self.waves.samples.len() < self.waves.sample_budget {
                let count = self
                    .waves
                    .window
                    .min(self.waves.sample_budget - self.waves.samples.len());
                match model(self.waves.begin(count))? {
                    Ready::Started { first, count } => {
                        self.released = false;
                        for chunk in (0..count).collect::<Vec<_>>().chunks(BATCH) {
                            self.queue(
                                chunk
                                    .iter()
                                    .map(|i| Work::Request(first + *i as u64 * 4))
                                    .collect(),
                            )?;
                        }
                    }
                    Ready::StreamCredit => self.blocked_streams += 1,
                    Ready::DataCredit => self.blocked_data += 1,
                }
            }
            let mut pending = Vec::with_capacity(BATCH);
            for i in 0..self.waves.slots.len() {
                if self.flights.len() == MAX_FLIGHTS {
                    break;
                }
                let s = &self.waves.slots[i];
                if s.started.is_some()
                    && u64::from(s.seen.trailing_ones()) == s.limit
                    && s.grant_acked == s.limit
                    && let Some(next) = self.waves.grants.next(s.limit)
                {
                    pending.push(Work::Grant((self.waves.retired + i as u64) * 4, next));
                }
                if pending.len() == BATCH {
                    self.queue(std::mem::replace(&mut pending, Vec::with_capacity(BATCH)))?;
                }
            }
            if !pending.is_empty() {
                self.queue(pending)?;
            }
            if self.waves.samples.len() == self.waves.sample_budget
                && self.flights.is_empty()
                && !fenced
            {
                self.queue(vec![Work::Fence])?;
                fenced = true;
            }
            if self.fence_acked && self.flights.is_empty() {
                break;
            }
            if last_ping.elapsed() >= Duration::from_millis(50)
                && self.flights.len() < MAX_FLIGHTS
                && !self.flights.iter().any(|f| f.work.contains(&Work::Ping))
            {
                self.queue(vec![Work::Ping])?;
                last_ping = Instant::now();
            }
            if !any {
                std::thread::yield_now();
            }
        }
        ensure!(
            self.completed == self.waves.sample_budget
                && self.request_acks == self.completed
                && self.grant_acks == self.grants,
            "incomplete accounting"
        );
        self.send_acks()?;
        ensure!(self.acked_wire.0 == self.seen.0, "missing final packet ACK");
        Ok(())
    }
    fn report(&self, error: Option<String>) -> Value {
        json!({"phase":if error.is_some(){"failed"}else{"done"},"error":error,"schedule":self.schedule,"mode":self.mode,"trace":self.trace,
            "count":self.waves.sample_budget,"window":self.waves.window,"completed":self.completed,"retired":self.waves.retired,
            "response_bytes":self.waves.received_bytes(),"late_duplicates":self.waves.late_duplicates,
            "request_acks":self.request_acks,"grants":self.grants,"grant_acks":self.grant_acks,
            "request_bytes_reserved":self.waves.reserved_data,"max_data":self.waves.max_data,"max_streams":self.waves.max_streams,
            "blocked_streams":self.blocked_streams,"blocked_data":self.blocked_data,"max_flights":self.max_flights,
            "interval":self.interval,"workload_start_ns":self.workload_start_ns,"workload_end_ns":self.workload_end_ns,
            "udp":udp_evidence::interval(&self.udp_before,&self.socket),"port":self.socket.local_addr().unwrap().port(),
            "control_bytes":self.control.count_ones(),"bootstrap_acked":self.bootstrap_acked,"fence_acked":self.fence_acked,
            "samples":self.waves.samples.iter().map(|s|(s.stream,s.started_ns,s.completed_ns)).collect::<Vec<_>>(),
            "active_streams":self.waves.slots.iter().enumerate().map(|(i,s)|json!({
                "id":(self.waves.retired+i as u64)*4,"started_ns":s.started,"completed_ns":s.completed,
                "seen":s.seen,"fin":s.fin,"limit":s.limit,"request_acked":s.request_acked,"grant_acked":s.grant_acked})).collect::<Vec<_>>(),
            "sent_work":self.sent,"frames":self.frames,"acked_work":self.acked_work,"unacked_work":self.flights.len(),
            "received_ranges":self.seen.0,"acked_packet_ranges":self.acked_wire.0,"server_ack_ranges":self.acked_by_server.0,"withheld_ranges":self.withheld.0,
            "sent_packets":self.sent_packets,"received_packets":self.received_packets,"handshake_sent":self.handshake_sent,"handshake_received":self.handshake_received,
            "retries":self.retries,"ack_packets":self.ack_packets,"duplicate_packets":self.duplicate_packets,"dropped_response_packets":self.dropped,"dropped_grants":self.dropped_grants,"replayed":self.replayed,"max_ack_ranges":self.max_ack_ranges})
    }
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() >= 7
            && a[7..]
                .iter()
                .all(|s| ["--controlled", "--trace"].contains(&s.as_str())),
        "usage: peer PORT COUNT WINDOW byte|two-byte|two-fragment|full each|withheld|sparse|loss|reorder TIMEOUT_SECONDS [--controlled] [--trace]"
    );
    let secs: u64 = a[6].parse()?;
    ensure!((1..=120).contains(&secs), "invalid timeout");
    let timeout = Duration::from_secs(secs);
    let controlled = a[7..].iter().any(|s| s == "--controlled");
    let trace = a[7..].iter().any(|s| s == "--trace");
    let mut peer = Peer::connect(
        a[1].parse()?,
        a[2].parse()?,
        a[3].parse()?,
        a[4].clone(),
        a[5].clone(),
        trace,
    )?;
    let result = (|| -> Result<()> {
        peer.bootstrap(timeout)?;
        if controlled {
            credit_control::emit(
                json!({"phase":"ready","port":peer.socket.local_addr()?.port(),"bootstrap_acked":peer.bootstrap_acked,"control_bytes":3,"started_requests":peer.waves.next,"udp":udp_evidence::interval(&peer.udp_before,&peer.socket)}),
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
    if controlled {
        credit_control::emit(json!({"phase":"stopped","interval":peer.interval,
            "sent_packets":peer.sent_packets,"received_packets":peer.received_packets,
            "handshake_sent":peer.handshake_sent,"handshake_received":peer.handshake_received}))?;
        credit_control::command(0, "report", timeout)?;
    }
    credit_control::emit(peer.report(result.as_ref().err().map(|e| format!("{e:#}"))))?;
    if controlled {
        credit_control::command(0, "exit", timeout)?;
    }
    result
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn batches_preserve_absolute_ids_across_varint_boundaries() {
        for first in [0, 60, 16380, (1 << 24) - 128] {
            for grants in [false, true] {
                let mut payload = Vec::new();
                for i in 0..BATCH {
                    let id = first + i as u64 * 4;
                    if grants {
                        Work::Grant(id, 25)
                    } else {
                        Work::Request(id)
                    }
                    .append(&mut payload);
                }
                assert!(payload.len() <= 1000);
                let frames = frame::Iter::new(&payload)
                    .collect::<Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(frames.len(), BATCH);
                for (i, frame) in frames.into_iter().enumerate() {
                    let expected_id = first + i as u64 * 4;
                    match frame {
                        Frame::Stream {
                            id,
                            offset,
                            data,
                            fin,
                        } if !grants => {
                            assert_eq!((id, offset, fin), (expected_id, 0, true));
                            assert_eq!(data, REQUEST);
                        }
                        Frame::MaxStreamData { id, limit } if grants => {
                            assert_eq!((id, limit), (expected_id, 25))
                        }
                        frame => panic!("wrong serialized work: {frame:?}"),
                    }
                }
            }
        }
    }
}
