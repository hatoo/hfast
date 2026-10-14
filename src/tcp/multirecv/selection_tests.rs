use super::tests::{h1_pair, pair, response, ring, until};
use super::*;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    bytes.push(flags);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn settings() -> Vec<u8> {
    frame(
        4,
        0,
        0,
        &[0, 3, 0x7f, 0xff, 0xff, 0xff, 0, 4, 0x7f, 0xff, 0xff, 0xff],
    )
}

fn h2_response(stream: u32) -> Vec<u8> {
    [
        frame(
            1,
            4,
            stream,
            b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33",
        ),
        frame(0, 1, stream, b"Hello, World!"),
    ]
    .concat()
}

#[test]
fn every_preface_byte_and_h2_request_stays_on_single_reads() {
    let mut worker = Worker::new(ring(2));
    let epoch = worker.io.pool.epoch;
    let (key, mut peer) = pair(&mut worker);
    assert!(worker.socket(key).unwrap().poll_active);
    assert!(worker.receives.is_empty());
    for (i, byte) in crate::h2::PREFACE.iter().enumerate() {
        peer.write_all(&[*byte]).unwrap();
        until(&mut worker, |w| w.receives.len() == i + 1);
        let socket = worker.socket(key).unwrap();
        assert!(!socket.recv_active && socket.poll_active);
        if i + 1 < crate::h2::PREFACE.len() {
            assert!(matches!(socket.conn.proto, Proto::Unknown));
            assert_eq!(socket.conn.inbuf, &crate::h2::PREFACE[..i + 1]);
        } else {
            assert!(matches!(socket.conn.proto, Proto::H2(_)));
        }
    }
    let mut bytes = vec![0; settings().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, settings());
    for stream in [1, 3, 5] {
        let before = worker.receives.len();
        peer.write_all(&frame(1, 5, stream, b"\x82\x84\x86"))
            .unwrap();
        until(&mut worker, |w| w.receives.len() > before);
        let mut bytes = vec![0; h2_response(stream).len()];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, h2_response(stream));
    }
    assert!(worker.receives.iter().all(|&(k, multi)| k == key && !multi));
    assert_eq!(
        worker.io.pool.epoch, epoch,
        "H2 must not consume the H1 buffer pool"
    );
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).is_none());
    assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn shared_method_prefix_switches_once_after_positive_classification() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = pair(&mut worker);
    for (i, byte) in b"PRI".iter().enumerate() {
        peer.write_all(&[*byte]).unwrap();
        until(&mut worker, |w| w.receives.len() == i + 1);
        let s = worker.socket(key).unwrap();
        assert!(matches!(s.conn.proto, Proto::Unknown) && !s.recv_active && s.poll_active);
    }
    peer.write_all(b"NT / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    until(&mut worker, |w| w.sockets.get(key).unwrap().recv_active);
    assert_eq!(
        worker.receives,
        [(key, false); 4]
            .into_iter()
            .chain([(key, true)])
            .collect::<Vec<_>>()
    );
    assert!(!worker.socket(key).unwrap().poll_active);
    let mut bytes = vec![0; response().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    peer.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).is_none());
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    assert!(worker.receives[4..].iter().all(|&(_, multi)| multi));
}

#[test]
fn mixed_protocols_drain_queued_input_and_half_close_with_two_buffers() {
    let mut worker = Worker::new(ring(2));
    let mut peers = Vec::new();
    for n in 0..38 {
        let (key, mut peer) = pair(&mut worker);
        let (input, expected) = if n % 2 == 0 {
            (
                b"GET / HTTP/1.1\r\nHost: queued\r\n\r\n".repeat(601),
                response().repeat(601),
            )
        } else {
            let mut input = crate::h2::PREFACE.to_vec();
            let mut expected = settings();
            for stream in (1..1202).step_by(2) {
                input.extend_from_slice(&frame(1, 5, stream, &[0x82; 32]));
                expected.extend_from_slice(&h2_response(stream));
            }
            (input, expected)
        };
        assert!(input.len() > CHUNK);
        peer.write_all(&input).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        peer.set_nonblocking(true).unwrap();
        peers.push((key, peer, expected, Vec::new(), false));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while peers.iter().any(|p| !p.4) {
        worker.step(-1, false);
        for (_, peer, expected, observed, eof) in &mut peers {
            if *eof {
                continue;
            }
            let mut bytes = [0; 16384];
            match peer.read(&mut bytes) {
                Ok(0) => {
                    *eof = true;
                    assert_eq!(observed, expected);
                }
                Ok(n) => {
                    observed.extend_from_slice(&bytes[..n]);
                    assert!(observed.len() <= expected.len());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                result => panic!("unexpected read {result:?}"),
            }
        }
        assert!(
            Instant::now() < deadline,
            "mixed protocol progress deadline"
        );
    }
    assert!(worker.sockets.is_empty());
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
    for (i, (key, ..)) in peers.iter().enumerate() {
        let ops: Vec<bool> = worker
            .receives
            .iter()
            .filter(|&&(k, _)| k == *key)
            .map(|&(_, multi)| multi)
            .collect();
        assert!(!ops[0]);
        if i % 2 == 0 {
            assert!(ops.len() >= 2 && ops[1..].iter().all(|&multi| multi));
        } else {
            assert!(ops.iter().all(|&multi| !multi));
        }
    }
}

#[test]
fn retired_unknown_poll_cannot_read_from_a_replacement() {
    let mut worker = Worker::new(ring(2));
    let (old, _peer) = pair(&mut worker);
    submit(worker.io.ring(), 0);
    worker.retire(old);
    let (new, mut peer) = pair(&mut worker);
    worker.event(Event {
        token: old | POLL,
        result: libc::POLLIN as i32,
        more: false,
        buffer: None,
    });
    assert!(worker.single.is_empty());
    peer.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    until(&mut worker, |w| {
        w.receives.iter().any(|&(k, multi)| k == new && multi)
    });
    let mut bytes = vec![0; response().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    assert!(worker.receives.iter().all(|&(k, _)| k == new));
}

#[test]
fn mixed_read_barrier_queues_multishot_bytes_without_consuming_them() {
    let mut worker = Worker::new(ring(2));
    let (h1, mut peer1) = h1_pair(&mut worker);
    let (h2, mut peer2) = pair(&mut worker);
    peer1.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    peer2.write_all(crate::h2::PREFACE).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !worker.pending.iter().any(|e| e.token == h2 | POLL)
        || !worker.pending.iter().any(|e| e.token == h1 | RECV)
    {
        submit(worker.io.ring(), 0);
        worker.drain();
        assert!(Instant::now() < deadline);
    }
    let pos = worker
        .pending
        .iter()
        .position(|e| e.token == h2 | POLL)
        .unwrap();
    let event = worker.pending.remove(pos).unwrap();
    worker.event(event);
    worker.read_batch();
    assert!(matches!(
        worker.socket(h2).unwrap().conn.proto,
        Proto::H2(_)
    ));
    assert!(worker.socket(h1).unwrap().conn.outbuf.is_empty());
    assert!(
        worker
            .pending
            .iter()
            .any(|e| e.token == h1 | RECV && e.buffer.is_some())
    );
    assert!(worker.io.pool.owned.iter().any(|&b| b));
    // The manual read phase has touched h2; put its output on the next batch's
    // ready list without fabricating a second live kernel poll.
    worker.socket(h2).unwrap().queued = false;
    worker.pending.push_back(Event {
        token: h2 | POLL,
        result: libc::POLLOUT as i32,
        more: false,
        buffer: None,
    });
    worker.step(-1, false);
    let mut bytes = vec![0; response().len()];
    peer1.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    let mut bytes = vec![0; settings().len()];
    peer2.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, settings());
}
