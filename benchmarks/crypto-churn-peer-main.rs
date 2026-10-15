//! Bounded full TLS/HTTP connections on one stable UDP address per producer.
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
use crypto_schedule::{Mode, Plan};
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

const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";
const DEADLINE: Duration = Duration::from_secs(5);

struct Socket {
    udp: UdpSocket,
    sent: u64,
    received: u64,
}
impl Socket {
    fn ledger(&self) -> Value {
        json!({"sent_datagrams": self.sent, "received_datagrams": self.received})
    }
}

#[derive(Default)]
struct Oracle {
    tls: bool,
    responses: usize,
}

#[derive(Default)]
struct Attempt {
    tls: bool,
    request: bool,
    responses: usize,
    close: bool,
}
impl Attempt {
    fn failure(&self, phase: &str, completed: usize, latencies: &[u64], failed_ns: u64) -> Value {
        json!({"phase": "failed", "work_phase": phase, "failed": 1,
            "offered": completed + 1, "completed": completed,
            "tls_completed": completed + usize::from(self.tls),
            "requests": completed + usize::from(self.request),
            "responses": completed + self.responses,
            "close_sent": completed + usize::from(self.close),
            "latencies_ns": latencies, "failed_latency_ns": failed_ns})
    }
}
impl Oracle {
    fn response(&mut self, id: u64, offset: u64, fin: bool, data: &[u8]) -> Result<()> {
        ensure!(self.tls, "response before TLS completion");
        ensure!(
            self.responses == 0 && id == 0,
            "duplicate/unsolicited response"
        );
        ensure!(
            offset == 0 && fin && data == RESPONSE,
            "incorrect response bytes/status/FIN"
        );
        self.responses += 1;
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        ensure!(
            self.tls && self.responses == 1,
            "missing TLS/HTTP completion"
        );
        Ok(())
    }
}

fn receive(socket: &mut Socket, buf: &mut [u8], deadline: Instant) -> Result<usize> {
    loop {
        match socket.udp.recv(buf) {
            Ok(n) => {
                socket.received += 1;
                return Ok(n);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                ensure!(
                    Instant::now() < deadline,
                    "missing handshake/response/fence"
                );
                std::hint::spin_loop();
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn send(socket: &mut Socket, wire: &[u8]) -> Result<()> {
    ensure!(socket.udp.send(wire)? == wire.len(), "partial datagram");
    socket.sent += 1;
    Ok(())
}

fn connection(
    socket: &mut Socket,
    config: Arc<rustls::ClientConfig>,
    mode: Mode,
    attempt: &mut Attempt,
) -> Result<[Plan; 2]> {
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
    conn.churn_schedule(mode);
    let mut wire = Vec::with_capacity(1200);
    let mut buf = [0; 65536];
    let deadline = Instant::now() + DEADLINE;
    loop {
        wire.clear();
        while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
            send(socket, &wire)?;
            wire.clear();
        }
        if conn.probe_ready() {
            break;
        }
        // This timing fixture requires no loss/retransmission. A missing packet
        // is an error, never a silently retried, different workload.
        let n = receive(socket, &mut buf, deadline)?;
        conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?;
        while let Some(event) = conn.poll_event() {
            if let Event::Lost(reason) = event {
                bail!("TLS/QUIC failed: {reason}");
            }
        }
    }
    attempt.tls = conn.churn_tls_completed();
    let plans = conn.churn_verify()?;
    let mut oracle = Oracle {
        tls: true,
        responses: 0,
    };
    let (limit, _, mut last) = conn.probe_limits();
    ensure!(limit >= 1, "no request credit");
    let mut payload = Vec::new();
    frame::put_ack(&mut payload, &[(0, last)], 0);
    frame::put_stream(&mut payload, 2, 0, false, &[0, 4, 0]);
    frame::put_stream(&mut payload, 6, 0, false, &[2]);
    frame::put_stream(&mut payload, 10, 0, false, &[3]);
    // Static QPACK: GET, https, :authority=localhost, path=/.
    frame::put_stream(
        &mut payload,
        0,
        0,
        true,
        b"\x01\x10\x00\x00\xd1\xd7\x50\x09localhost\xc1",
    );
    conn.probe_seal(&payload, &mut wire)?;
    send(socket, &wire)?;
    attempt.request = true;
    let mut fence = None;
    loop {
        let n = receive(socket, &mut buf, deadline)?;
        let (pn, plain) = conn.probe_open(&mut buf[..n])?;
        ensure!(pn == last + 1, "lost/reordered/duplicate response packet");
        last = pn;
        let mut fenced = false;
        for frame in frame::Iter::new(plain) {
            match frame? {
                Frame::Ack {
                    largest,
                    first_range,
                    ranges,
                    ..
                } => {
                    fenced |= fence.is_some_and(|sent| {
                        frame::AckRanges::new(largest, first_range, ranges)
                            .any(|(first, last)| (first..=last).contains(&sent))
                    });
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } if id & 3 == 0 => {
                    oracle.response(id, offset, fin, data)?;
                    attempt.responses += 1;
                }
                Frame::Stream { id, .. } if id & 3 == 3 => {}
                Frame::Padding
                | Frame::Ping
                | Frame::HandshakeDone
                | Frame::MaxStreams { .. }
                | Frame::MaxData(_)
                | Frame::NewConnectionId { .. } => {}
                other => bail!("unexpected response frame {other:?}"),
            }
        }
        if fenced {
            oracle.complete()?;
            break;
        }
        if oracle.responses == 1 && fence.is_none() {
            payload.clear();
            frame::put_ack(&mut payload, &[(0, last)], 0);
            frame::put_ping(&mut payload);
            fence = Some(conn.probe_seal(&payload, &mut wire)?);
            send(socket, &wire)?;
        }
    }
    payload.clear();
    frame::put_ack(&mut payload, &[(0, last)], 0);
    frame::put_close(&mut payload, 0x100, b"churn complete");
    conn.probe_seal(&payload, &mut wire)?;
    send(socket, &wire)?;
    attempt.close = true;
    Ok(plans)
}

fn run_connection(
    socket: &mut Socket,
    config: Arc<rustls::ClientConfig>,
    mode: Mode,
    phase: &str,
    completed: usize,
    latencies: &[u64],
) -> Result<([Plan; 2], u64)> {
    let start = Instant::now();
    let mut attempt = Attempt::default();
    let result = connection(socket, config, mode, &mut attempt);
    let elapsed = start.elapsed().as_nanos() as u64;
    match result {
        Ok(plans) => Ok((plans, elapsed)),
        Err(error) => {
            let mut report = attempt.failure(phase, completed, latencies, elapsed);
            report["error"] = json!(format!("{error:#}"));
            report["ledger"] = socket.ledger();
            emit(report)?;
            Err(error)
        }
    }
}

fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}

fn command(expected: &str) -> Result<()> {
    let mut text = String::new();
    ensure!(
        io::stdin().read_line(&mut text)? > 0 && text.trim() == expected,
        "controller phase mismatch"
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 5, "usage: peer PORT MODE CONNECTIONS WARMUP");
    let port: u16 = args[1].parse()?;
    let mode = Mode::parse(&args[2])?;
    let count: usize = args[3].parse()?;
    let warmup: usize = args[4].parse()?;
    ensure!(
        (1..=1_000_000).contains(&count) && (1..=100_000).contains(&warmup),
        "unbounded workload"
    );
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    udp.connect(("127.0.0.1", port))?;
    udp.set_nonblocking(true)?;
    let mut socket = Socket {
        udp,
        sent: 0,
        received: 0,
    };
    let config = tls::client_config(b"h3")?;
    for i in 0..warmup {
        run_connection(&mut socket, config.clone(), mode, "warmup", i, &[])
            .with_context(|| format!("warmup {i}"))?;
    }
    emit(
        json!({"phase": "ready", "port": socket.udp.local_addr()?.port(),
        "warmup": warmup, "ledger": socket.ledger()}),
    )?;
    command("start")?;
    let start = Instant::now();
    let mut latencies = Vec::with_capacity(count);
    let mut sample = None;
    let mut crypto_packets = 0;
    let mut crypto_bytes = 0;
    for i in 0..count {
        let (plans, elapsed) =
            run_connection(&mut socket, config.clone(), mode, "measured", i, &latencies)
                .with_context(|| format!("measured connection {i}/{count}"))?;
        latencies.push(elapsed);
        for plan in &plans {
            crypto_packets += plan.sent.len();
            crypto_bytes += plan.sent.iter().map(|s| s.stop - s.start).sum::<usize>();
        }
        if sample.is_none() {
            sample = Some(plans);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    emit(
        json!({"phase": "done", "offered": count, "completed": count,
        "requests": count, "responses": count, "tls_completed": count,
        "close_sent": count, "failed": 0, "latencies_ns": latencies,
        "ledger": socket.ledger(),
        "seconds": elapsed, "crypto_packets": crypto_packets, "crypto_bytes": crypto_bytes,
        "epochs": sample.unwrap().iter().map(Plan::json).collect::<Vec<_>>() }),
    )?;
    command("validate")?;
    // Reusing the same address with fresh keys and no retry proves the last
    // measured close was consumed. hfast routes connections by this address.
    run_connection(&mut socket, config, mode, "retirement", 0, &[])
        .context("final retirement handshake")?;
    emit(json!({"phase": "validated", "retirement_probes": 1,
        "replacements_verified": warmup + count, "maximum_server_addresses": 1,
        "port": socket.udp.local_addr()?.port(), "failed": 0, "ledger": socket.ledger()}))?;
    command("exit")?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    #[test]
    fn failed_fence_preserves_partial_counts_and_every_completed_latency() {
        let attempt = Attempt {
            tls: true,
            request: true,
            responses: 1,
            close: false,
        };
        let report = attempt.failure("measured", 3, &[10, 20, 30], 99);
        assert_eq!(report["offered"], 4);
        assert_eq!(report["completed"], 3);
        assert_eq!(report["requests"], 4);
        assert_eq!(report["responses"], 4);
        assert_eq!(report["tls_completed"], 4);
        assert_eq!(report["close_sent"], 3);
        assert_eq!(report["latencies_ns"], json!([10, 20, 30]));
        assert_eq!(report["failed_latency_ns"], 99);
        assert_eq!(report["failed"], 1);
    }

    #[test]
    fn exact_response_requires_tls_bytes_fin_and_unique_stream() {
        assert!(Oracle::default().complete().is_err());
        assert!(Oracle::default().response(0, 0, true, RESPONSE).is_err());
        let mut oracle = Oracle {
            tls: true,
            responses: 0,
        };
        assert!(oracle.complete().is_err());
        assert!(oracle.response(0, 0, false, RESPONSE).is_err());
        assert!(oracle.response(4, 0, true, RESPONSE).is_err());
        assert!(oracle.response(0, 1, true, RESPONSE).is_err());
        let mut corrupt = RESPONSE.to_vec();
        corrupt[4] ^= 1;
        assert!(oracle.response(0, 0, true, &corrupt).is_err());
        oracle.response(0, 0, true, RESPONSE).unwrap();
        oracle.complete().unwrap();
        assert!(oracle.response(0, 0, true, RESPONSE).is_err());
    }

    #[test]
    fn handshake_verifier_rejects_unfinished_tls() {
        let mut conn = Connection::connect(
            tls::client_config(b"h3").unwrap(),
            "localhost",
            LocalParamsInput {
                initial_max_data: 1000,
                initial_max_stream_data: 1000,
                initial_max_streams_uni: 16,
                max_idle_timeout_ms: 1000,
                handshake_timeout_ms: 1000,
            },
        )
        .unwrap();
        conn.churn_schedule(Mode::Normal);
        assert!(conn.churn_verify().is_err());
    }
}
