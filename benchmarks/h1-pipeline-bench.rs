//! Byte-verifying HTTP/1 pipeline benchmark with a fixed request count.
//!
//! Compile: rustc --edition=2024 -O benchmarks/h1-pipeline-bench.rs -o /tmp/h1-pipeline-bench
//! Run against a separately started hfast: /tmp/h1-pipeline-bench PORT CONNECTIONS PIPELINE ROUNDS
//! Each connection validates a warmup, then sends PIPELINE requests and reads
//! exactly that many constant responses per round. The JSON separates warmup
//! from measured requests. Compare immutable servers with the same arguments,
//! CPU affinity, alternating order and an independent confirmation series.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args[1].parse().unwrap();
    let connections: usize = args[2].parse().unwrap();
    let pipeline: usize = args[3].parse().unwrap();
    let rounds: usize = args[4].parse().unwrap();
    let warm_rounds = 4096_usize.div_ceil(pipeline);
    let start = Arc::new(Barrier::new(connections + 1));
    let mut workers = Vec::new();
    for _ in 0..connections {
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_nodelay(true).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let request = REQUEST.repeat(pipeline);
            let expected = RESPONSE.repeat(pipeline);
            let mut received = vec![0; expected.len()];
            let mut exchange = || {
                socket.write_all(&request).unwrap();
                socket.read_exact(&mut received).unwrap();
                assert_eq!(received, expected, "wrong response bytes or order");
            };
            for _ in 0..warm_rounds {
                exchange();
            }
            start.wait();
            for _ in 0..rounds {
                exchange();
            }
            socket.set_nonblocking(true).unwrap();
            let mut extra = [0];
            match socket.peek(&mut extra) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("unexpected extra response or EOF: {other:?}"),
            }
            rounds * pipeline
        }));
    }
    let began = Instant::now();
    start.wait();
    // Exclude connection establishment and all validated warmup exchanges.
    let measured = Instant::now();
    let requests: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
    let seconds = measured.elapsed().as_secs_f64();
    assert_eq!(requests, connections * rounds * pipeline);
    println!(
        "{{\"connections\":{connections},\"pipeline\":{pipeline},\"rounds\":{rounds},\"requests\":{requests},\"errors\":0,\"warmup_requests\":{},\"response_bytes\":{},\"request_bytes\":{},\"seconds\":{seconds},\"warmup_seconds\":{},\"rps\":{}}}",
        connections * warm_rounds * pipeline,
        requests * RESPONSE.len(),
        requests * REQUEST.len(),
        measured.duration_since(began).as_secs_f64(),
        requests as f64 / seconds
    );
}
