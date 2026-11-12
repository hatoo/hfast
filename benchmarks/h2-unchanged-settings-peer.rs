//! A fixed HTTP/2 workload: repeat unchanged settings on blocked streams,
//! then release every body. Validate every frame and retain every latency.
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FIELDS: &[u8] = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33";
const REPEATS: usize = 1024;
const BODY: &[u8] = b"Hello, World!";

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&((payload.len() as u32) << 8 | u32::from(kind)).to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}
fn expect(socket: &mut impl Read, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let mut header = [0; 9];
    socket.read_exact(&mut header).unwrap();
    assert_eq!(
        u32::from_be_bytes(header[..4].try_into().unwrap()),
        (payload.len() as u32) << 8 | u32::from(kind)
    );
    assert_eq!(header[4], flags);
    assert_eq!(u32::from_be_bytes(header[5..].try_into().unwrap()), stream);
    let mut body = [0; 64];
    socket.read_exact(&mut body[..payload.len()]).unwrap();
    assert_eq!(&body[..payload.len()], payload);
}
fn run(port: u16, count: usize, batch: usize, blocked: bool) -> Vec<u64> {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_nodelay(true).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut socket = BufReader::new(socket);
    let mut wire = PREFACE.to_vec();
    frame(
        &mut wire,
        4,
        0,
        0,
        &[0, 4, 0, 0, 0, if blocked { 0 } else { 13 }],
    );
    socket.get_mut().write_all(&wire).unwrap();
    expect(
        &mut socket,
        4,
        0,
        0,
        &[0, 3, 127, 255, 255, 255, 0, 4, 127, 255, 255, 255],
    );
    expect(&mut socket, 4, 1, 0, &[]);
    wire.clear();
    frame(&mut wire, 4, 1, 0, &[]);
    // Enough connection credit to exercise the bulk drain for every prefix.
    frame(&mut wire, 8, 0, 0, &((13 * count) as u32).to_be_bytes());
    socket.get_mut().write_all(&wire).unwrap();
    let mut starts = Vec::with_capacity(count);
    let mut samples = Vec::with_capacity(count);
    for start in (0..count).step_by(batch) {
        let end = (start + batch).min(count);
        wire.clear();
        for i in start..end {
            frame(
                &mut wire,
                1,
                5,
                (i as u32) * 2 + 1,
                b"\x82\x86\x84\x01\x09localhost",
            );
        }
        let begin = Instant::now();
        starts.resize(end, begin);
        socket.get_mut().write_all(&wire).unwrap();
        for (i, begin) in starts.iter().enumerate().take(end).skip(start) {
            expect(&mut socket, 1, 4, i as u32 * 2 + 1, FIELDS);
            if !blocked {
                expect(&mut socket, 0, 1, i as u32 * 2 + 1, BODY);
                samples.push(begin.elapsed().as_nanos() as u64);
            }
        }
    }
    if blocked {
        wire.clear();
        for _ in 0..REPEATS {
            frame(&mut wire, 4, 0, 0, &[0, 4, 0, 0, 0, 0]);
        }
        socket.get_mut().write_all(&wire).unwrap();
        for _ in 0..REPEATS {
            expect(&mut socket, 4, 1, 0, &[]);
        }
        wire.clear();
        frame(&mut wire, 4, 0, 0, &[0, 4, 0, 0, 0, 13]);
        socket.get_mut().write_all(&wire).unwrap();
        expect(&mut socket, 4, 1, 0, &[]);
        for (i, begin) in starts.iter().enumerate() {
            expect(&mut socket, 0, 1, i as u32 * 2 + 1, BODY);
            samples.push(begin.elapsed().as_nanos() as u64);
        }
    }
    assert_eq!(samples.len(), count);
    wire.clear();
    frame(&mut wire, 6, 0, 0, b"complete");
    socket.get_mut().write_all(&wire).unwrap();
    expect(&mut socket, 6, 1, 0, b"complete");
    socket.get_ref().shutdown(Shutdown::Write).unwrap();
    let mut extra = Vec::new();
    socket.read_to_end(&mut extra).unwrap();
    assert!(extra.is_empty(), "extra response bytes");
    samples
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        7,
        "port count batch rounds blocked|ordinary samples-file"
    );
    let port = args[1].parse().unwrap();
    let count: usize = args[2].parse().unwrap();
    let batch: usize = args[3].parse().unwrap();
    let rounds: usize = args[4].parse().unwrap();
    let blocked = match args[5].as_str() {
        "blocked" => true,
        "ordinary" => false,
        _ => panic!("mode"),
    };
    assert!((1..=65536).contains(&count) && batch > 0 && rounds > 0);
    // Same full-workload warmup for every binary; exclude its samples and time.
    run(port, count, batch, blocked);
    println!("warmup-complete");
    std::io::stdin().read_exact(&mut [0]).unwrap();
    let mut samples = Vec::with_capacity(count * rounds);
    let start = Instant::now();
    for _ in 0..rounds {
        samples.extend(run(port, count, batch, blocked));
    }
    let seconds = start.elapsed().as_secs_f64();
    let mut bytes = Vec::with_capacity(samples.len() * 8);
    for sample in &samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    std::fs::write(&args[6], &bytes).unwrap();
    samples.sort_unstable();
    let p99 = samples[(samples.len() - 1) * 99 / 100];
    println!(
        "{{\"requests\":{},\"responses\":{},\"status200\":{},\"samples\":{},\"body_bytes\":{},\"errors\":0,\"seconds\":{},\"rps\":{},\"p99_ns\":{},\"count\":{},\"batch\":{},\"rounds\":{},\"blocked\":{}}}",
        count * rounds,
        samples.len(),
        samples.len(),
        samples.len(),
        13 * samples.len(),
        seconds,
        samples.len() as f64 / seconds,
        p99,
        count,
        batch,
        rounds,
        blocked
    );
}
