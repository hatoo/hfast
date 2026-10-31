use super::selection_tests::{frame, h2_response, settings};
use super::tests::{pair, ring, until};
use super::*;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn h2_pair(worker: &mut Worker) -> (u64, UnixStream) {
    let (key, mut peer) = pair(worker);
    peer.write_all(crate::h2::PREFACE).unwrap();
    until(worker, |w| w.sockets.get(key).unwrap().recv_active);
    let mut bytes = vec![0; settings().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, settings());
    assert!(!worker.socket(key).unwrap().poll_active);
    (key, peer)
}

fn read_bytes(worker: &mut Worker, peer: &mut UnixStream, expected: &[u8]) {
    peer.set_nonblocking(true).unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    let mut observed = Vec::new();
    while observed.len() < expected.len() {
        worker.step(-1, false);
        let mut bytes = [0; 16384];
        match peer.read(&mut bytes) {
            Ok(0) => panic!("early EOF after {} bytes", observed.len()),
            Ok(n) => observed.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected read {result:?}"),
        }
        assert!(Instant::now() < end, "H2 response progress deadline");
    }
    assert_eq!(observed, expected);
    peer.set_nonblocking(false).unwrap();
}

#[test]
fn h2_exhaustion_rearms_split_headers_and_continuations_before_eof() {
    let mut worker = Worker::new(ring(2));
    let mut peers = (0..19).map(|_| h2_pair(&mut worker)).collect::<Vec<_>>();
    for (_, peer) in &mut peers {
        // No END_HEADERS: a response must wait for the continuation, even when
        // its bytes arrive in a later receive operation after pool exhaustion.
        peer.write_all(&frame(1, 1, 1, b"\x82\x84\x86")).unwrap();
    }
    let end = Instant::now() + Duration::from_secs(5);
    while !worker.pending.iter().any(|e| e.result == -libc::ENOBUFS) {
        submit(worker.io.ring(), 0);
        worker.drain();
        assert!(Instant::now() < end, "expected H2 pool exhaustion");
    }
    assert!(worker.io.pool.owned.iter().all(|&b| b));
    assert!(worker.sockets.iter().all(|(_, s)| s.conn.outbuf.is_empty()));
    for (_, peer) in &mut peers {
        peer.write_all(&frame(9, 4, 1, b"\x87")).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
    }
    until(&mut worker, |w| {
        w.sockets.is_empty() && w.pending.is_empty() && w.starved.is_empty()
    });
    for (key, mut peer) in peers {
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, h2_response(1), "connection {key}");
        let ops: Vec<_> = worker.receives.iter().filter(|&&(k, _)| k == key).collect();
        assert!(!ops[0].1 && ops[1..].iter().all(|op| op.1));
    }
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
    assert_eq!(worker.io.pool.tail, worker.io.pool.published);
}

#[test]
fn zero_stream_window_waits_for_a_fragmented_multishot_credit_frame() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h2_pair(&mut worker);
    let mut request = frame(4, 0, 0, &[0, 4, 0, 0, 0, 0]);
    request.extend_from_slice(&frame(1, 5, 1, b"\x82\x84\x86"));
    peer.write_all(&request).unwrap();
    let response = h2_response(1);
    let headers = &response[..response.len() - 22];
    read_bytes(
        &mut worker,
        &mut peer,
        &[frame(4, 1, 0, &[]), headers.to_vec()].concat(),
    );
    assert!(worker.socket(key).unwrap().conn.outbuf.is_empty());
    assert!(worker.socket(key).unwrap().recv_active);
    assert!(!worker.socket(key).unwrap().poll_active);

    let credit = frame(8, 0, 1, &13_u32.to_be_bytes());
    peer.write_all(&credit[..5]).unwrap();
    until(&mut worker, |w| {
        w.sockets.get(key).unwrap().conn.inbuf.len() == 5
    });
    assert!(worker.socket(key).unwrap().conn.outbuf.is_empty());
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    peer.set_nonblocking(false).unwrap();
    peer.write_all(&credit[5..]).unwrap();
    read_bytes(&mut worker, &mut peer, &frame(0, 1, 1, b"Hello, World!"));
    assert!(worker.socket(key).unwrap().conn.inbuf.is_empty());
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).is_none());
    assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    assert!(worker.receives[1..].iter().all(|&(_, multi)| multi));
}

#[test]
fn retired_h2_data_and_duplicate_terminal_cqes_cannot_change_a_reused_slot() {
    let mut worker = Worker::new(ring(2));
    let (old, mut peer) = h2_pair(&mut worker);
    peer.write_all(&frame(1, 5, 1, b"\x82\x84\x86")).unwrap();
    submit(worker.io.ring(), 1);
    worker.drain();
    assert!(
        worker
            .pending
            .iter()
            .any(|e| e.token == old | RECV && e.buffer.is_some())
    );
    worker.retire(old);
    let (new, mut replacement) = pair(&mut worker);
    assert_ne!(old, new);
    assert_eq!(worker.sockets.iter().count(), 1);
    let single = worker.single.clone();
    for _ in 0..2 {
        worker.event(Event {
            token: old | RECV,
            result: 0,
            more: false,
            buffer: None,
        });
        worker.event(Event {
            token: old | POLL,
            result: libc::POLLIN as i32,
            more: false,
            buffer: None,
        });
    }
    assert!(!worker.socket(new).unwrap().conn.read_eof);
    assert_eq!(worker.single, single, "stale polls must not enqueue reads");
    replacement.write_all(crate::h2::PREFACE).unwrap();
    read_bytes(&mut worker, &mut replacement, &settings());
    assert!(worker.socket(new).unwrap().recv_active);
    assert!(worker.socket(new).unwrap().conn.outbuf.is_empty());
    replacement
        .write_all(&frame(1, 5, 1, b"\x82\x84\x86"))
        .unwrap();
    read_bytes(&mut worker, &mut replacement, &h2_response(1));
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}

#[test]
fn h2_receive_buffers_wait_while_a_send_borrows_the_output_vector() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h2_pair(&mut worker);
    let expected = h2_response(1);
    worker.socket(key).unwrap().conn.outbuf = expected.clone();
    let socket = worker.socket(key).unwrap();
    let pointer = socket.conn.outbuf.as_ptr();
    let entry = opcode::Send::new(
        types::Fd(socket.fd.as_raw_fd()),
        pointer,
        expected.len() as u32,
    )
    .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
    .build()
    .user_data(key | SEND);
    unsafe { push(worker.io.ring(), &entry) };
    worker.writes.clear();
    peer.write_all(&frame(1, 5, 3, b"\x82\x84\x86")).unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    while worker.writes.is_empty() || !worker.pending.iter().any(|e| e.buffer.is_some()) {
        submit(worker.io.ring(), 0);
        worker.drain();
        assert_eq!(worker.socket(key).unwrap().conn.outbuf, expected);
        assert_eq!(worker.socket(key).unwrap().conn.outbuf.as_ptr(), pointer);
        assert!(Instant::now() < end);
    }
    assert_eq!(worker.writes, [(key, expected.len() as i32)]);
    assert!(worker.io.pool.owned.iter().any(|&b| b));
    let mut bytes = vec![0; expected.len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, expected);
    // The real send CQE has retired the pointer borrow. Only now may the vector
    // be cleared and the queued receive append another response.
    worker.socket(key).unwrap().conn.outbuf.clear();
    read_bytes(&mut worker, &mut peer, &h2_response(3));
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}

#[test]
fn protocol_error_drains_partial_output_and_goaway_before_cancelling_h2_receive() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h2_pair(&mut worker);
    let fd = worker.socket(key).unwrap().fd.as_raw_fd();
    let size: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                size_of_val(&size) as _,
            )
        },
        0
    );
    let mut input = Vec::new();
    let mut expected = Vec::new();
    for stream in (1..2000).step_by(2) {
        input.extend_from_slice(&frame(1, 5, stream, b"\x82\x84\x86"));
        expected.extend_from_slice(&h2_response(stream));
    }
    // Zero connection credit is a protocol error. A subsequent request must
    // never create a response after the ordered GOAWAY.
    input.extend_from_slice(&frame(8, 0, 0, &[0; 4]));
    input.extend_from_slice(&frame(1, 5, 2001, b"\x82\x84\x86"));
    expected.extend_from_slice(&frame(7, 0, 0, &[0, 0, 7, 207, 0, 0, 0, 1]));
    peer.write_all(&input).unwrap();
    until(&mut worker, |w| w.sockets.get(key).unwrap().closing());
    let socket = worker.socket(key).unwrap();
    assert!(socket.conn.out_off > 0 && socket.conn.out_off < socket.conn.outbuf.len());
    assert_eq!(socket.conn.outbuf, expected);
    let receives = worker.receives.len();
    read_bytes(&mut worker, &mut peer, &expected);
    until(&mut worker, |w| w.sockets.get(key).is_none());
    // Retirement queues cancellation; the next worker turn submits it and
    // releases the kernel's last socket reference before the peer observes EOF.
    worker.step(-1, false);
    assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    assert_eq!(
        worker.receives.len(),
        receives,
        "closing must not rearm input"
    );
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}
