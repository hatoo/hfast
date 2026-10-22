//! Fixed work on every live connection, with TLS outside the measured phase.
#![allow(dead_code)]
mod clock;
mod crypto_schedule;
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
    conn::{Connection, Event, LocalParamsInput},
    frame::{self, Frame},
};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    net::UdpSocket,
    sync::Arc,
    time::{Duration, Instant},
};

const REQUEST: &[u8] = b"\x01\x10\x00\x00\xd1\xd7\x50\x09localhost\xc1";
const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";
const DEADLINE: Duration = Duration::from_secs(5);

struct Window {
    first: u64,
    seen: Vec<bool>,
    start: Instant,
}
impl Window {
    fn response(&mut self, id: u64, offset: u64, fin: bool, data: &[u8]) -> Result<u64> {
        ensure!(
            id >= self.first && (id - self.first).is_multiple_of(4),
            "unsolicited stream"
        );
        let index = ((id - self.first) / 4) as usize;
        ensure!(
            index < self.seen.len() && !self.seen[index],
            "duplicate/unsolicited response"
        );
        ensure!(
            offset == 0 && fin && data == RESPONSE,
            "wrong response bytes/status/FIN"
        );
        self.seen[index] = true;
        Ok(self.start.elapsed().as_nanos().max(1) as u64)
    }
    fn complete(&self) -> bool {
        self.seen.iter().all(|seen| *seen)
    }
}

struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    sent: u64,
    received: u64,
    last: u64,
    next_stream: u64,
    stream_limit: u64,
    max_data: u64,
    sent_data: u64,
    requests: usize,
    responses: usize,
    fences: usize,
    close_sent: bool,
    pending_acks: Vec<u64>,
    window: Option<Window>,
    latencies: Vec<u64>,
}
impl Peer {
    fn connect(port: u16, config: Arc<rustls::ClientConfig>) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_nonblocking(true)?;
        let mut conn = Connection::connect(
            config,
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
        let mut buf = [0; 65536];
        let mut sent = 0;
        let mut received = 0;
        let deadline = Instant::now() + DEADLINE;
        loop {
            wire.clear();
            while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
                ensure!(
                    socket.send(&wire)? == wire.len(),
                    "partial handshake datagram"
                );
                sent += 1;
                wire.clear();
            }
            if conn.probe_ready() {
                break;
            }
            let n = receive(&socket, &mut buf, deadline)?;
            received += 1;
            conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?;
            while let Some(event) = conn.poll_event() {
                if let Event::Lost(reason) = event {
                    bail!("TLS/QUIC failed: {reason}");
                }
            }
        }
        ensure!(conn.churn_tls_completed(), "incomplete TLS");
        let (stream_limit, max_data, last) = conn.probe_limits();
        let mut peer = Self {
            socket,
            conn,
            wire,
            sent,
            received,
            last,
            next_stream: 0,
            stream_limit,
            max_data,
            sent_data: 5,
            requests: 0,
            responses: 0,
            fences: 0,
            close_sent: false,
            pending_acks: Vec::new(),
            window: None,
            latencies: Vec::new(),
        };
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, last)], 0);
        frame::put_stream(&mut payload, 2, 0, false, &[0, 4, 0]);
        frame::put_stream(&mut payload, 6, 0, false, &[2]);
        frame::put_stream(&mut payload, 10, 0, false, &[3]);
        peer.send(&payload, true)?;
        peer.finish_acks()?;
        Ok(peer)
    }
    fn send(&mut self, payload: &[u8], ack_eliciting: bool) -> Result<()> {
        let pn = self.conn.probe_seal(payload, &mut self.wire)?;
        ensure!(
            self.socket.send(&self.wire)? == self.wire.len(),
            "partial datagram"
        );
        self.sent += 1;
        if ack_eliciting {
            self.pending_acks.push(pn);
        }
        Ok(())
    }
    fn recv(&mut self, deadline: Instant) -> Result<()> {
        let mut buf = [0; 65536];
        let n = receive(&self.socket, &mut buf, deadline)?;
        self.received += 1;
        let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
        // This timing workload rejects loss/reordering/duplicates, rather than
        // silently performing a different amount of transport work.
        ensure!(
            pn == self.last + 1,
            "lost/reordered/duplicate response packet"
        );
        self.last = pn;
        for parsed in frame::Iter::new(plain) {
            match parsed? {
                Frame::Ack {
                    largest,
                    first_range,
                    ranges,
                    ..
                } => {
                    let ranges: Vec<_> =
                        frame::AckRanges::new(largest, first_range, ranges).collect();
                    self.pending_acks
                        .retain(|pn| !ranges.iter().any(|(a, b)| (a..=b).contains(&pn)));
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } if id & 3 == 0 => {
                    let latency = self
                        .window
                        .as_mut()
                        .context("response outside request window")?
                        .response(id, offset, fin, data)?;
                    self.responses += 1;
                    self.latencies.push(latency);
                }
                Frame::Stream { id, .. } if id & 3 == 3 => {}
                Frame::MaxStreams { uni: false, limit } => {
                    ensure!(limit >= self.stream_limit, "decreasing stream limit");
                    self.stream_limit = limit;
                }
                Frame::MaxData(limit) => {
                    self.max_data = self.max_data.max(limit);
                }
                Frame::Padding
                | Frame::Ping
                | Frame::HandshakeDone
                | Frame::MaxStreams { uni: true, .. }
                | Frame::NewConnectionId { .. } => {}
                other => bail!("unexpected response frame {other:?}"),
            }
        }
        Ok(())
    }
    fn finish_acks(&mut self) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        while !self.pending_acks.is_empty() {
            self.recv(deadline)?;
        }
        Ok(())
    }
    fn request(&mut self, count: usize) -> Result<()> {
        ensure!(
            self.window.is_none() && self.pending_acks.is_empty(),
            "unfinished round"
        );
        ensure!(
            self.next_stream / 4 + count as u64 <= self.stream_limit,
            "stream credit exceeded"
        );
        ensure!(
            self.sent_data + (count * REQUEST.len()) as u64 <= self.max_data,
            "data credit exceeded"
        );
        let mut payload = Vec::with_capacity(1200);
        frame::put_ack(&mut payload, &[(0, self.last)], 0);
        for i in 0..count {
            frame::put_stream(
                &mut payload,
                self.next_stream + 4 * i as u64,
                0,
                true,
                REQUEST,
            );
        }
        self.window = Some(Window {
            first: self.next_stream,
            seen: vec![false; count],
            start: Instant::now(),
        });
        self.send(&payload, true)?;
        self.next_stream += 4 * count as u64;
        self.sent_data += (count * REQUEST.len()) as u64;
        self.requests += count;
        Ok(())
    }
    fn responses(&mut self) -> Result<()> {
        let deadline = Instant::now() + DEADLINE;
        while !self
            .window
            .as_ref()
            .context("missing request window")?
            .complete()
        {
            self.recv(deadline)?;
        }
        // Keep the complete window until after the fence to reject duplicates.
        Ok(())
    }
    fn fence(&mut self) -> Result<()> {
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, self.last)], 0);
        frame::put_ping(&mut payload);
        self.send(&payload, true)
    }
    fn finish_round(&mut self) -> Result<()> {
        self.finish_acks()?;
        self.window = None;
        self.fences += 1;
        Ok(())
    }
    fn final_packet(&mut self, close: bool) -> Result<()> {
        ensure!(
            self.window.is_none() && self.pending_acks.is_empty(),
            "unfinished final work"
        );
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, self.last)], 0);
        if close {
            frame::put_close(&mut payload, 0x100, b"persistent workload complete");
        }
        self.send(&payload, false)?;
        self.close_sent |= close;
        Ok(())
    }
    fn report(&self, samples: bool) -> Result<Value> {
        let mut value = json!({"port": self.socket.local_addr()?.port(),
            "tls_completed": self.conn.churn_tls_completed(), "requests": self.requests,
            "responses": self.responses, "next_stream": self.next_stream,
            "fences": self.fences, "pending_acks": self.pending_acks.len(),
            "pending_responses": self.requests-self.responses, "close_sent": self.close_sent,
            "sent_datagrams": self.sent, "received_datagrams": self.received});
        if samples {
            value["latencies_ns"] = json!(self.latencies);
        }
        Ok(value)
    }
}

fn receive(socket: &UdpSocket, buf: &mut [u8], deadline: Instant) -> Result<usize> {
    loop {
        ensure!(
            Instant::now() < deadline,
            "missing handshake/response/ACK fence"
        );
        match socket.recv(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            Err(e) => return Err(e.into()),
        }
    }
}
fn rounds(peers: &mut [Peer], rounds: usize, window: usize) -> Result<()> {
    for _ in 0..rounds {
        for p in &mut *peers {
            p.request(window)?;
        }
        for p in &mut *peers {
            p.responses()?;
        }
        for p in &mut *peers {
            p.fence()?;
        }
        for p in &mut *peers {
            p.finish_round()?;
        }
    }
    for p in peers {
        p.final_packet(false)?;
    }
    Ok(())
}
fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}
fn command(expected: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut bytes = Vec::new();
    loop {
        ensure!(Instant::now() < deadline, "controller timeout");
        let mut fd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut fd, 1, 100) };
        ensure!(ready >= 0, "controller poll failed");
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        ensure!(
            unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) } == 1,
            "controller disconnected"
        );
        if byte == b'\n' {
            ensure!(bytes == expected.as_bytes(), "wrong controller phase");
            return Ok(());
        }
        bytes.push(byte);
        ensure!(bytes.len() <= 32, "oversized command");
    }
}
fn reports(peers: &[Peer], samples: bool) -> Result<Vec<Value>> {
    peers.iter().map(|p| p.report(samples)).collect()
}
fn run(peers: &mut Vec<Peer>, phase: &mut &'static str) -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: peer PORT PEERS ROUNDS WINDOW WARMUP"
    );
    let port = args[1].parse()?;
    let count: usize = args[2].parse()?;
    let measured: usize = args[3].parse()?;
    let window: usize = args[4].parse()?;
    let warmup: usize = args[5].parse()?;
    ensure!(
        (1..=128).contains(&count) && (1..=32).contains(&window),
        "invalid peer/window bound"
    );
    ensure!(
        (1..=100_000).contains(&measured)
            && (1..=1000).contains(&warmup)
            && count * window * (measured + warmup) <= 1_000_000,
        "unbounded work"
    );
    let config = tls::client_config(b"h3")?;
    for index in 0..count {
        peers.push(
            Peer::connect(port, config.clone()).with_context(|| format!("TLS peer {index}"))?,
        );
    }
    *phase = "warmup";
    rounds(peers, warmup, window)?;
    emit(json!({"phase":"ready", "peers":reports(peers, false)?, "failed":0}))?;
    command("start")?;
    *phase = "measured";
    let start = Instant::now();
    rounds(peers, measured, window)?;
    let seconds = start.elapsed().as_secs_f64();
    // Keep sample serialization and its CPU cost outside the measured phase.
    emit(
        json!({"phase":"done", "failed":0, "peers":count, "requests":count*measured*window,
        "responses":count*measured*window, "seconds":seconds}),
    )?;
    command("report")?;
    *phase = "report";
    emit(json!({"phase":"reported", "failed":0, "peers":reports(peers, true)?}))?;
    command("close")?;
    *phase = "close";
    for p in &mut *peers {
        p.final_packet(true)?;
    }
    emit(json!({"phase":"closed", "failed":0, "peers":reports(peers, false)?}))?;
    command("exit")?;
    Ok(())
}
fn main() {
    let mut peers = Vec::new();
    let mut phase = "handshake";
    if let Err(error) = run(&mut peers, &mut phase) {
        let _ = emit(json!({"phase":"failed", "work_phase":phase, "failed":1,
            "error":format!("{error:#}"), "peers":reports(&peers, true).unwrap_or_default()}));
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    #[test]
    fn every_stream_requires_exact_body_fin_and_one_completion() {
        let mut w = Window {
            first: 8,
            seen: vec![false; 2],
            start: Instant::now(),
        };
        for (id, offset, fin, data) in [
            (4, 0, true, RESPONSE),
            (9, 0, true, RESPONSE),
            (16, 0, true, RESPONSE),
            (8, 1, true, RESPONSE),
            (8, 0, false, RESPONSE),
            (8, 0, true, b"wrong".as_slice()),
        ] {
            assert!(w.response(id, offset, fin, data).is_err());
            assert_eq!(w.seen, vec![false; 2]);
        }
        assert!(w.response(12, 0, true, RESPONSE).unwrap() > 0);
        assert!(!w.complete());
        assert!(w.response(12, 0, true, RESPONSE).is_err());
        w.response(8, 0, true, RESPONSE).unwrap();
        assert!(w.complete());
    }
    #[test]
    fn one_complete_peer_cannot_mask_another_incomplete_peer() {
        let mut peers: Vec<_> = (0..128)
            .map(|_| Window {
                first: 0,
                seen: vec![false; 2],
                start: Instant::now(),
            })
            .collect();
        for p in &mut peers {
            p.response(0, 0, true, RESPONSE).unwrap();
        }
        for p in &mut peers[..127] {
            p.response(4, 0, true, RESPONSE).unwrap();
        }
        assert!(!peers.iter().all(Window::complete));
        assert!(peers[0].response(4, 0, true, RESPONSE).is_err());
        peers[127].response(4, 0, true, RESPONSE).unwrap();
        assert!(peers.iter().all(Window::complete));
    }
}
