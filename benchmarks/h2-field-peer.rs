//! Fixed legal field blocks, exact responses, complete latency samples and EOF fences.
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const HEADERS: &[u8] = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33";
const SETTINGS: &[u8] = &[0, 3, 127, 255, 255, 255, 0, 4, 127, 255, 255, 255];
const MAX_PIPELINE: usize = 64;
const CREDIT_BATCH: u32 = 32_768;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    wire.push(flags);
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn integer(mut n: usize, out: &mut Vec<u8>) {
    if n < 127 {
        out.push(n as u8);
        return;
    }
    out.push(127);
    n -= 127;
    while n >= 128 {
        out.push(n as u8 | 128);
        n >>= 7;
    }
    out.push(n as u8);
}

fn request(size: usize) -> (Vec<u8>, Vec<usize>) {
    // Static method/scheme/path, literal authority and non-indexed x-fill.
    let prefix = b"\x82\x86\x84\x01\x09localhost\x00\x06x-fill";
    let mut block = Vec::new();
    for n in (size.saturating_sub(32)..size).rev() {
        block.clear();
        block.extend_from_slice(prefix);
        integer(n, &mut block);
        if block.len() + n == size {
            block.resize(size, b'x');
            break;
        }
    }
    assert_eq!(block.len(), size, "field block size must be at least 32");
    let mut wire = Vec::new();
    let mut offsets = Vec::new();
    let count = size.div_ceil(16_384);
    for (i, payload) in block.chunks(16_384).enumerate() {
        offsets.push(wire.len() + 5);
        wire.extend_from_slice(&frame(
            if i == 0 { 1 } else { 9 },
            u8::from(i == 0) | if i + 1 == count { 4 } else { 0 },
            1,
            payload,
        ));
    }
    (wire, offsets)
}

struct Peer {
    socket: BufReader<TcpStream>,
    sent: usize,
    received: usize,
    writes: usize,
    credit_updates: usize,
    returned_credit: u64,
}
impl Peer {
    fn write(&mut self, wire: &[u8], chunk: usize) {
        for part in wire.chunks(chunk) {
            self.socket.get_mut().write_all(part).unwrap();
            self.sent += part.len();
            self.writes += 1;
        }
    }
    fn expect(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        // All expected frames are small. Keep the response path allocation-free.
        let mut expected = [0; 64];
        let len = 9 + payload.len();
        expected[..4]
            .copy_from_slice(&((payload.len() as u32) << 8 | u32::from(kind)).to_be_bytes());
        expected[4] = flags;
        expected[5..9].copy_from_slice(&stream.to_be_bytes());
        expected[9..len].copy_from_slice(payload);
        let mut observed = [0; 64];
        self.socket
            .read_exact(&mut observed[..len])
            .expect("missing/truncated response");
        assert_eq!(
            observed[..len],
            expected[..len],
            "unexpected response/frame order"
        );
        self.received += len;
    }
    fn connect(port: u16) -> Self {
        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.set_nodelay(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut p = Self {
            socket: BufReader::new(socket),
            sent: 0,
            received: 0,
            writes: 0,
            credit_updates: 0,
            returned_credit: 0,
        };
        p.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", usize::MAX);
        p.write(&frame(4, 0, 0, &[0, 1, 0, 0, 0, 0]), usize::MAX);
        p.expect(4, 0, 0, SETTINGS);
        p.expect(4, 1, 0, b"");
        p.write(&frame(4, 1, 0, b""), usize::MAX);
        p
    }
    fn finish(&mut self) {
        self.write(&frame(6, 0, 0, b"complete"), usize::MAX);
        self.expect(6, 1, 0, b"complete");
        self.socket.get_ref().shutdown(Shutdown::Write).unwrap();
        let mut trailing = Vec::new();
        self.socket.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty(), "unexpected frames after final fence");
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() == 6 || args.len() == 7,
        "port block_bytes write_chunk requests_per_connection connections [pipeline=1]"
    );
    let port: u16 = args[1].parse().unwrap();
    let size: usize = args[2].parse().unwrap();
    let chunk: usize = args[3].parse().unwrap();
    let count: usize = args[4].parse().unwrap();
    let connections: usize = args[5].parse().unwrap();
    let pipeline: usize = args.get(6).map_or(1, |s| s.parse().unwrap());
    assert!(
        (32..=1_048_576).contains(&size)
            && chunk > 0
            && count > 0
            && count < (1 << 30)
            && connections > 0
            && (1..=MAX_PIPELINE).contains(&pipeline)
    );
    let start = Arc::new(Barrier::new(connections + 1));
    let handles: Vec<_> = (0..connections)
        .map(|id| {
            let start = start.clone();
            let mut peer = Peer::connect(port);
            let (mut wire, offsets) = request(size);
            std::thread::spawn(move || {
                let mut latencies = Vec::with_capacity(count);
                let mut credit = 0_u32;
                let mut pending = Vec::with_capacity(pipeline);
                start.wait();
                let begin = Instant::now();
                for first in (0..count).step_by(pipeline) {
                    pending.clear();
                    // Reuse one field block, not a pipeline-sized payload copy.
                    for i in first..(first + pipeline).min(count) {
                        let time = Instant::now();
                        let stream = (2 * i + 1) as u32;
                        for &at in &offsets {
                            wire[at..at + 4].copy_from_slice(&stream.to_be_bytes());
                        }
                        pending.push((stream, time));
                        peer.write(&wire, chunk);
                    }
                    for &(stream, time) in &pending {
                        peer.expect(1, 4, stream, HEADERS);
                        peer.expect(0, 1, stream, b"Hello, World!");
                        latencies.push(time.elapsed().as_nanos() as u64);
                        credit += 13;
                    }
                    // At most 64*13 bytes per group: outstanding responses fit
                    // below the initial 65535-byte window even before an update.
                    if credit >= CREDIT_BATCH {
                        peer.write(&frame(8, 0, 0, &credit.to_be_bytes()), usize::MAX);
                        peer.credit_updates += 1;
                        peer.returned_credit += u64::from(credit);
                        credit = 0;
                    }
                }
                let seconds = begin.elapsed().as_secs_f64();
                peer.finish();
                let ledger = format!(
                    "{{\"id\":{id},\"requests\":{},\"samples\":{},\"last_stream\":{},\"field_bytes\":{},\"sent_bytes\":{},\"received_bytes\":{},\"application_writes\":{},\"credit_updates\":{},\"returned_credit\":{}}}",
                    latencies.len(), latencies.len(), 2 * count - 1, count * size,
                    peer.sent, peer.received, peer.writes, peer.credit_updates, peer.returned_credit
                );
                (latencies, seconds, peer.sent, peer.received, peer.writes, ledger)
            })
        })
        .collect();
    start.wait();
    let mut samples = Vec::with_capacity(count * connections);
    let (mut elapsed, mut sent, mut received, mut writes) = (0_f64, 0, 0, 0);
    let mut ledgers = Vec::with_capacity(connections);
    for handle in handles {
        let (latencies, seconds, tx, rx, calls, ledger) = handle.join().unwrap();
        samples.extend(latencies);
        elapsed = elapsed.max(seconds);
        sent += tx;
        received += rx;
        writes += calls;
        ledgers.push(ledger);
    }
    assert_eq!(samples.len(), count * connections);
    println!(
        "{{\"requests\":{},\"errors\":0,\"block_bytes\":{},\"chunk\":{},\"connections\":{},\"pipeline\":{},\"elapsed_seconds\":{},\"rps\":{},\"sent_bytes\":{},\"received_bytes\":{},\"application_writes\":{},\"peers\":[{}],\"latencies_ns\":{:?}}}",
        samples.len(),
        size,
        chunk,
        connections,
        pipeline,
        elapsed,
        samples.len() as f64 / elapsed,
        sent,
        received,
        writes,
        ledgers.join(","),
        samples
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legal_frames_preserve_exact_block_sizes_and_final_flags() {
        for size in [32, 127, 16_384, 16_385, 1_048_576] {
            let (wire, offsets) = request(size);
            let mut at = 0;
            let mut total = 0;
            for (i, &stream_at) in offsets.iter().enumerate() {
                assert_eq!(stream_at, at + 5);
                let n = (u32::from_be_bytes(wire[at..at + 4].try_into().unwrap()) >> 8) as usize;
                assert!((1..=16_384).contains(&n));
                assert_eq!(wire[at + 3], if i == 0 { 1 } else { 9 });
                assert_eq!(wire[at + 4] & 4 != 0, i + 1 == offsets.len());
                assert_eq!(wire[at + 4] & 1 != 0, i == 0);
                at += 9 + n;
                total += n;
            }
            assert_eq!(at, wire.len());
            assert_eq!(total, size);
        }
    }
}
