//! Sustained, credit-aware HTTP/2 uploads with exact responses and final fences.
use std::collections::VecDeque;
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

const WINDOW: u32 = 65_535;
const BATCH: u32 = 32_768;
const PAYLOAD: usize = 16_384;
const UPLOAD: usize = 1_048_576;
const RESPONSE_HEADERS: &[u8] = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33";
const SERVER_SETTINGS: &[u8] = &[0, 3, 127, 255, 255, 255, 0, 4, 127, 255, 255, 255];

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

#[derive(Default)]
struct Oracle {
    settings: bool,
    settings_ack: bool,
    window: u32,
    uncredited: u32,
    grants: VecDeque<u32>,
    requests: VecDeque<u32>,
    response_body: bool,
    responses: usize,
    sent_payload: usize,
    granted: usize,
    updates: usize,
    fence: Option<[u8; 8]>,
    fenced: bool,
}

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}

impl Oracle {
    fn new() -> Self {
        Self {
            window: WINDOW,
            ..Self::default()
        }
    }

    fn sent_data(&mut self, size: usize) -> Result<(), String> {
        require(self.settings && self.settings_ack, "DATA before handshake")?;
        require(
            size <= self.window as usize,
            "outgoing connection window exceeded",
        )?;
        self.window -= size as u32;
        self.sent_payload += size;
        self.uncredited += size as u32;
        if self.uncredited >= BATCH {
            self.grants.push_back(self.uncredited);
            self.uncredited = 0;
        }
        Ok(())
    }

    fn receive(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<(), String> {
        require(!self.fenced, "frame after final fence")?;
        match kind {
            4 => {
                require(stream == 0, "SETTINGS stream")?;
                if flags == 0 {
                    require(
                        !self.settings && payload == SERVER_SETTINGS,
                        "server SETTINGS",
                    )?;
                    self.settings = true;
                } else {
                    require(
                        flags == 1 && self.settings && !self.settings_ack && payload.is_empty(),
                        "SETTINGS ACK",
                    )?;
                    self.settings_ack = true;
                }
            }
            8 => {
                require(
                    stream == 0 && flags == 0 && payload.len() == 4,
                    "WINDOW_UPDATE framing",
                )?;
                let increment = u32::from_be_bytes(payload.try_into().unwrap());
                require(
                    increment > 0 && increment <= WINDOW,
                    "WINDOW_UPDATE increment",
                )?;
                require(
                    self.grants.front() == Some(&increment),
                    "missing, duplicated or excessive credit",
                )?;
                require(
                    self.window + increment <= WINDOW,
                    "credit exceeds initial window",
                )?;
                self.grants.pop_front();
                self.window += increment;
                self.granted += increment as usize;
                self.updates += 1;
            }
            1 => {
                require(
                    self.requests.front() == Some(&stream) && !self.response_body,
                    "response HEADERS stream/order",
                )?;
                require(
                    flags == 4 && payload == RESPONSE_HEADERS,
                    "response HEADERS bytes",
                )?;
                self.response_body = true;
            }
            0 => {
                require(
                    self.requests.front() == Some(&stream) && self.response_body,
                    "response DATA stream/order",
                )?;
                require(
                    flags == 1 && payload == b"Hello, World!",
                    "response DATA bytes",
                )?;
                self.response_body = false;
                self.requests.pop_front();
                self.responses += 1;
            }
            6 => {
                require(
                    stream == 0
                        && flags == 1
                        && self.fence.as_ref().map(|v| &v[..]) == Some(payload),
                    "unexpected PING/fence",
                )?;
                require(
                    self.sent_payload == UPLOAD && self.requests.is_empty() && self.responses == 17,
                    "premature fence/response completion",
                )?;
                require(
                    self.grants.is_empty()
                        && self.uncredited == 0
                        && self.granted == UPLOAD
                        && self.window == WINDOW,
                    "missing credit at fence",
                )?;
                self.fenced = true;
            }
            _ => return Err(format!("unexpected frame type {kind}")),
        }
        Ok(())
    }
}

fn read_frame(
    peer: &mut BufReader<TcpStream>,
    oracle: &mut Oracle,
    bytes: &mut usize,
    payload: &mut Vec<u8>,
) {
    let mut h = [0; 9];
    peer.read_exact(&mut h)
        .expect("missing server frame/credit");
    let len = (u32::from_be_bytes([h[0], h[1], h[2], 0]) >> 8) as usize;
    assert!(len <= PAYLOAD, "oversized server frame");
    assert_eq!(h[5] & 0x80, 0, "unexpected reserved stream bit");
    let stream = u32::from_be_bytes(h[5..9].try_into().unwrap());
    payload.resize(len, 0);
    peer.read_exact(payload).expect("truncated server frame");
    *bytes += 9 + len;
    oracle.receive(h[3], h[4], stream, payload).unwrap();
}

fn write(peer: &mut BufReader<TcpStream>, wire: &[u8], chunk: usize, bytes: &mut usize) {
    for part in wire.chunks(chunk) {
        peer.get_mut().write_all(part).unwrap();
        *bytes += part.len();
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 5, "ADDRESS CYCLES WRITE_BYTES PAD_BYTES");
    let cycles: usize = args[2].parse().unwrap();
    let chunk: usize = args[3].parse().unwrap();
    let padding: u8 = args[4].parse().unwrap();
    assert!(cycles > 0 && chunk > 0);
    let mut data = vec![0xa5; PAYLOAD];
    if padding != 0 {
        data[0] = padding;
        data[PAYLOAD - padding as usize..].fill(0);
    }
    let mut sent = 0;
    let mut received = 0;
    let mut updates = 0;
    let mut latencies = Vec::with_capacity(cycles);
    let mut wire = Vec::with_capacity(WINDOW as usize + 1024);
    let mut payload = Vec::with_capacity(128);
    let start = Instant::now();
    for cycle in 0..cycles {
        let begin = Instant::now();
        let stream = TcpStream::connect(&args[1]).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut peer = BufReader::new(stream);
        let mut oracle = Oracle::new();
        wire.clear();
        wire.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        frame(&mut wire, 4, 0, 0, &[]);
        write(&mut peer, &wire, chunk, &mut sent);
        while !oracle.settings_ack {
            read_frame(&mut peer, &mut oracle, &mut received, &mut payload);
        }
        wire.clear();
        frame(&mut wire, 4, 1, 0, &[]);
        for packet in 0..UPLOAD / PAYLOAD {
            if oracle.window < PAYLOAD as u32 {
                write(&mut peer, &wire, chunk, &mut sent);
                wire.clear();
                while oracle.window < PAYLOAD as u32 {
                    read_frame(&mut peer, &mut oracle, &mut received, &mut payload);
                }
            }
            let stream = 1 + 2 * (packet / 4) as u32;
            if packet % 4 == 0 {
                frame(&mut wire, 1, 4, stream, b"\x83\x86\x84\x01\x09localhost");
                oracle.requests.push_back(stream);
            }
            frame(
                &mut wire,
                0,
                u8::from(packet % 4 == 3) | if padding != 0 { 8 } else { 0 },
                stream,
                &data,
            );
            oracle.sent_data(PAYLOAD).unwrap();
        }
        frame(&mut wire, 1, 5, 33, b"\x82\x86\x84\x01\x09localhost");
        oracle.requests.push_back(33);
        let token = (cycle as u64).to_be_bytes();
        frame(&mut wire, 6, 0, 0, &token);
        write(&mut peer, &wire, chunk, &mut sent);
        oracle.fence = Some(token);
        while !oracle.fenced {
            read_frame(&mut peer, &mut oracle, &mut received, &mut payload);
        }
        // No more requests follow this validated fence. Half-close so the
        // server drains its queued output and supplies an observable boundary.
        // Checking only BufReader::buffer() misses bytes that arrive later.
        peer.get_mut().shutdown(Shutdown::Write).unwrap();
        // Keep the read timeout and require real EOF before accepting a cycle.
        let mut extra = [0];
        assert_eq!(
            peer.read(&mut extra).expect("missing final EOF"),
            0,
            "bytes after final fence"
        );
        assert_eq!(oracle.updates, UPLOAD / BATCH as usize);
        updates += oracle.updates;
        latencies.push(begin.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    let mut sorted = latencies.clone();
    sorted.sort_unstable();
    let q = |p: usize, scale: usize| sorted[(cycles - 1) * p / scale];
    let mean = latencies.iter().map(|&n| n as f64).sum::<f64>() / cycles as f64;
    println!(
        "{{\"cycles\":{cycles},\"fences\":{cycles},\"eofs\":{cycles},\"responses\":{},\"errors\":0,\"upload_bytes\":{},\"sent_bytes\":{sent},\"received_bytes\":{received},\"updates\":{updates},\"padding\":{padding},\"elapsed_ns\":{elapsed},\"cycles_per_second\":{},\"mean_cycle_ns\":{mean},\"p50_cycle_ns\":{},\"p99_cycle_ns\":{},\"p999_cycle_ns\":{},\"max_cycle_ns\":{},\"cycle_latencies_ns\":{latencies:?}}}",
        cycles * 17,
        cycles * UPLOAD,
        cycles as f64 * 1e9 / elapsed as f64,
        q(50, 100),
        q(99, 100),
        q(999, 1000),
        sorted[cycles - 1]
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Oracle {
        let mut o = Oracle::new();
        o.receive(4, 0, 0, SERVER_SETTINGS).unwrap();
        o.receive(4, 1, 0, &[]).unwrap();
        o
    }

    #[test]
    fn legal_credit_is_batched_and_exact() {
        let mut o = ready();
        for _ in 0..32 {
            o.sent_data(PAYLOAD).unwrap();
            o.sent_data(PAYLOAD).unwrap();
            o.receive(8, 0, 0, &BATCH.to_be_bytes()).unwrap();
        }
        assert_eq!(o.window, WINDOW);
        assert_eq!(o.granted, UPLOAD);
        assert_eq!(o.updates, 32);
    }

    #[test]
    fn zero_excess_wrong_stream_duplicate_and_missing_credit_are_rejected() {
        for (stream, amount) in [(0, 0), (0, BATCH + 1), (1, BATCH), (0, 0x8000_8000)] {
            let mut o = ready();
            o.sent_data(2 * PAYLOAD).unwrap();
            assert!(o.receive(8, 0, stream, &amount.to_be_bytes()).is_err());
        }
        let mut o = ready();
        o.sent_data(2 * PAYLOAD).unwrap();
        o.receive(8, 0, 0, &BATCH.to_be_bytes()).unwrap();
        assert!(o.receive(8, 0, 0, &BATCH.to_be_bytes()).is_err());
        let mut o = ready();
        o.sent_data(3 * PAYLOAD).unwrap();
        assert!(
            o.sent_data(PAYLOAD).is_err(),
            "missing credit must stop transmission"
        );
    }

    #[test]
    fn early_fence_missing_credit_and_response_corruption_are_rejected() {
        let mut o = ready();
        o.fence = Some([0; 8]);
        assert!(o.receive(6, 1, 0, &[0; 8]).is_err());
        o.sent_payload = UPLOAD;
        o.responses = 17;
        assert!(o.receive(6, 1, 0, &[0; 8]).is_err());
        o.granted = UPLOAD;
        o.receive(6, 1, 0, &[0; 8]).unwrap();
        assert!(o.receive(8, 0, 0, &BATCH.to_be_bytes()).is_err());
        let mut o = ready();
        o.requests.push_back(1);
        assert!(o.receive(1, 4, 3, RESPONSE_HEADERS).is_err());
        o.receive(1, 4, 1, RESPONSE_HEADERS).unwrap();
        assert!(o.receive(0, 1, 1, b"Hello, World?").is_err());
        o.receive(0, 1, 1, b"Hello, World!").unwrap();
        assert_eq!(o.responses, 1);
    }
}
