use super::*;
use crate::tcp::Proto;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

pub(super) fn ring(count: usize) -> ReceiveRing {
    ReceiveRing::new(IoUring::new(8).unwrap(), count)
        .ok()
        .unwrap()
}

pub(super) fn until(worker: &mut Worker, condition: impl Fn(&Worker) -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !condition(worker) {
        worker.step(-1, false);
        assert!(
            Instant::now() < end,
            "receive progress deadline: epoch={} retry_epoch={} remaining={} starved={:?} owned={:?} pending={} sockets={:?}",
            worker.io.pool.epoch,
            worker.retry_epoch,
            worker.retry_remaining,
            worker.starved,
            worker.io.pool.owned,
            worker.pending.len(),
            worker
                .sockets
                .iter()
                .map(|(key, s)| (
                    key,
                    s.recv_active,
                    s.recv_epoch,
                    s.starved,
                    s.poll_active,
                    matches!(s.conn.proto, Proto::Unknown),
                    s.conn.inbuf.len()
                ))
                .collect::<Vec<_>>()
        );
        std::thread::yield_now();
    }
}

pub(super) fn pair(worker: &mut Worker) -> (u64, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let key = worker.insert(socket.into());
    (key, peer)
}

pub(super) fn response() -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::h1::respond(&mut bytes);
    bytes
}

pub(super) fn h1_pair(worker: &mut Worker) -> (u64, UnixStream) {
    let (key, mut peer) = pair(worker);
    peer.write_all(b"GET / HTTP/1.1\r\nHost: warmup\r\n\r\n")
        .unwrap();
    until(worker, |w| w.sockets.get(key).unwrap().recv_active);
    let mut bytes = vec![0; response().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    (key, peer)
}

#[test]
fn the_kernel_support_probe_retires_and_recycles_every_buffer() {
    let mut io = ring(2);
    assert!(io.supported());
    assert!(io.pool.owned.iter().all(|&b| !b));
    assert_eq!(io.ring().completion().count(), 0);
    // Also exercise the original ring's reuse after unregistering the pool.
    let mut fallback = io.fallback();
    let entry = opcode::Nop::new().build().user_data(99);
    unsafe {
        push(&mut fallback, &entry);
    }
    submit(&mut fallback, 1);
    let c = fallback.completion().next().unwrap();
    assert_eq!(c.user_data(), 99);
    assert_eq!(c.result(), 0);
}

#[test]
fn buffers_are_not_reused_until_bytes_are_consumed_and_returned() {
    let mut io = ring(2);
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let entry = opcode::RecvMulti::new(types::Fd(socket.as_raw_fd()), GROUP)
        .build()
        .user_data(RECV | 1);
    unsafe {
        push(io.ring(), &entry);
    }
    peer.write_all(b"first").unwrap();
    submit(io.ring(), 1);
    let c = io.ring().completion().next().unwrap();
    let first = io.pool.claim(c.result(), c.flags()).unwrap();
    assert!(cqueue::more(c.flags()));
    peer.write_all(b"second").unwrap();
    submit(io.ring(), 1);
    let c = io.ring().completion().next().unwrap();
    let second = io.pool.claim(c.result(), c.flags()).unwrap();
    assert_ne!(first, second);
    assert_eq!(io.pool.bytes(first, 5), b"first");
    assert_eq!(io.pool.bytes(second, 6), b"second");
    peer.write_all(b"third").unwrap();
    submit(io.ring(), 1);
    let c = io.ring().completion().next().unwrap();
    assert_eq!(c.result(), -libc::ENOBUFS);
    assert!(!cqueue::more(c.flags()));
    assert!(io.pool.claim(c.result(), c.flags()).is_none());
    // Starvation must not modify either userspace-owned slice.
    assert_eq!(io.pool.bytes(first, 5), b"first");
    assert_eq!(io.pool.bytes(second, 6), b"second");
    io.pool.release(first);
    io.pool.publish();
    unsafe {
        push(io.ring(), &entry);
    }
    submit(io.ring(), 1);
    let c = io.ring().completion().next().unwrap();
    assert_eq!(io.pool.claim(c.result(), c.flags()), Some(first));
    assert_eq!(io.pool.bytes(first, 5), b"third");
    assert_eq!(io.pool.bytes(second, 6), b"second");
    io.pool.release(first);
    io.pool.release(second);
    io.pool.publish();
}

#[test]
#[should_panic(expected = "completed twice")]
fn duplicate_buffer_completion_cannot_alias_a_borrow() {
    let mut pool = Pool::new(2).unwrap();
    pool.claim(1, 1);
    pool.claim(1, 1);
}

#[test]
#[should_panic(expected = "returned twice")]
fn duplicate_return_is_rejected() {
    let mut pool = Pool::new(2).unwrap();
    pool.release(0);
}

#[test]
#[should_panic(expected = "positive receive without a buffer")]
fn missing_buffer_flag_is_rejected() {
    let mut pool = Pool::new(2).unwrap();
    pool.claim(1, 0);
}

#[test]
fn publication_wraps_the_u16_tail_without_losing_buffer_identity() {
    let mut pool = Pool::new(2).unwrap();
    for i in 0..131072 {
        let id = (i % 2) as u16;
        assert_eq!(pool.claim(1, 1 | (u32::from(id) << 16)), Some(id));
        pool.release(id);
        pool.publish();
    }
    assert_eq!(pool.tail, 2);
    assert_eq!(pool.epoch, 131074);
    assert_eq!(unsafe { (*pool.descriptors).tail }, 2);
}

#[test]
fn tiny_pool_rearms_after_exhaustion_and_preserves_fragmented_requests() {
    let mut worker = Worker::new(ring(2));
    let mut peers = Vec::new();
    for _ in 0..19 {
        let (key, mut peer) = pair(&mut worker);
        peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
        peers.push((key, peer));
    }
    until(&mut worker, |w| {
        peers
            .iter()
            .all(|(key, _)| matches!(&w.sockets.get(*key).unwrap().conn.proto, Proto::H1 { .. }))
    });
    for (_, peer) in &mut peers {
        peer.write_all(b"\r\n").unwrap();
    }
    let expected = response();
    // Nonblocking polling lets every socket progress while the two buffers rotate.
    let mut received = vec![Vec::new(); peers.len()];
    for (_, p) in &peers {
        p.set_nonblocking(true).unwrap();
    }
    let end = Instant::now() + Duration::from_secs(5);
    while received.iter().any(|b| b.len() < expected.len()) {
        worker.step(-1, false);
        for (i, (_, p)) in peers.iter_mut().enumerate() {
            let mut b = [0; 1024];
            match p.read(&mut b) {
                Ok(n) => received[i].extend_from_slice(&b[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                result => panic!("unexpected read {result:?}"),
            }
        }
        assert!(Instant::now() < end);
    }
    assert!(received.iter().all(|b| b == &expected));
}

#[test]
fn eof_queued_with_data_preserves_all_responses_before_retirement() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = pair(&mut worker);
    let request = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    peer.write_all(&request.repeat(600)).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).is_none());
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, response().repeat(600));
}

#[test]
fn read_eof_preserves_partial_sends_and_discards_an_incomplete_body() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = pair(&mut worker);
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
    let mut requests = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".repeat(800);
    requests.extend_from_slice(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\npart");
    peer.write_all(&requests).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).unwrap().conn.read_eof);
    let socket = worker.socket(key).unwrap();
    assert!(socket.closing());
    assert!(!socket.recv_active && !socket.starved);
    assert!(socket.poll_active);
    assert!(socket.conn.out_off > 0 && socket.conn.out_off < socket.conn.outbuf.len());
    assert!(matches!(
        socket.conn.proto,
        Proto::H1 {
            remaining_body: 3,
            ..
        }
    ));
    let receive_epoch = socket.recv_epoch;
    peer.set_nonblocking(true).unwrap();
    let mut observed = Vec::new();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        worker.step(-1, false);
        if let Some(socket) = worker.socket(key) {
            assert!(socket.conn.read_eof && !socket.recv_active);
            assert_eq!(socket.recv_epoch, receive_epoch, "EOF must not rearm input");
        }
        let mut bytes = [0; 16384];
        match peer.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => observed.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected read {result:?}"),
        }
        assert!(Instant::now() < end, "EOF output drain deadline");
    }
    assert_eq!(observed, response().repeat(800));
    assert!(worker.sockets.get(key).is_none());
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}

#[test]
fn exhausted_receives_rearm_to_observe_eof_and_retire_every_connection() {
    let mut worker = Worker::new(ring(2));
    let mut peers = Vec::new();
    for _ in 0..19 {
        peers.push(h1_pair(&mut worker));
    }
    for (_, peer) in &mut peers {
        peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: incomplete")
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
    }
    // Withhold completed buffers until at least one real receive exhausts the
    // pool. This proves the EOF path actually crosses a terminal ENOBUFS CQE.
    let end = Instant::now() + Duration::from_secs(5);
    while !worker.pending.iter().any(|e| e.result == -libc::ENOBUFS) {
        submit(worker.io.ring(), 0);
        worker.drain();
        assert!(Instant::now() < end, "expected receive buffer exhaustion");
        std::thread::yield_now();
    }
    assert!(worker.io.pool.owned.iter().all(|&b| b));
    until(&mut worker, |w| {
        w.sockets.is_empty() && w.pending.is_empty() && w.starved.is_empty()
    });
    for (key, mut peer) in peers {
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, response(), "connection {key}");
    }
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
    assert_eq!(worker.io.pool.tail, worker.io.pool.published);
}

#[test]
fn late_completions_cannot_modify_a_reused_descriptor() {
    let mut worker = Worker::new(ring(2));
    let (old, mut peer) = h1_pair(&mut worker);
    let old_fd = worker.socket(old).unwrap().fd.as_raw_fd();
    peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    submit(worker.io.ring(), 1);
    worker.drain();
    assert!(worker.pending.iter().any(|e| e.buffer.is_some()));
    worker.retire(old);
    let (socket, mut new_peer) = UnixStream::pair().unwrap();
    // Force descriptor replacement even when the test runner opens other fds.
    let replacement = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, old_fd) };
    assert!(replacement >= 0);
    // Even if the runner took the original fd, the old operation identity must
    // remain retired. The churn fixture also exercises real TCP descriptor reuse.
    let new = worker.insert(unsafe { OwnedFd::from_raw_fd(replacement) });
    new_peer
        .write_all(b"GET / HTTP/1.1\r\nHost: b\r\n\r\n")
        .unwrap();
    let stale = old;
    worker.event(Event {
        token: stale | RECV,
        result: 0,
        more: false,
        buffer: None,
    });
    assert!(!worker.socket(new).unwrap().conn.read_eof);
    until(&mut worker, |w| {
        matches!(&w.sockets.get(new).unwrap().conn.proto, Proto::H1 { .. })
    });
    new_peer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = vec![0; response().len()];
    new_peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}

#[test]
fn receive_cqes_wait_behind_the_send_buffer_barrier() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h1_pair(&mut worker);
    peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    submit(worker.io.ring(), 1);
    worker.drain();
    assert_eq!(worker.socket(key).unwrap().conn.outbuf.len(), 0);
    assert!(worker.io.pool.owned.iter().any(|&b| b));
    // drain only queues: parsing/outbuf mutation is exclusively in the next step.
    worker.step(-1, false);
    let mut bytes = vec![0; response().len()];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, response());
}

#[test]
fn starvation_is_retried_only_after_a_buffer_publication() {
    let mut worker = Worker::new(ring(2));
    let (key, _peer) = h1_pair(&mut worker);
    let attempted = worker.io.pool.epoch;
    worker.socket(key).unwrap().starved = true;
    worker.starved.push_back((key, attempted));
    for _ in 0..100 {
        worker.retry_starved();
    }
    assert_eq!(worker.starved.len(), 1);
    assert!(worker.socket(key).unwrap().starved);
}

#[test]
fn an_asynchronously_rejected_multishot_probe_leaves_fallback_usable() {
    let mut io = ring(2);
    // MSG_WAITALL is invalid for RecvMulti and is rejected via a real CQE.
    assert!(!io.probe(libc::MSG_WAITALL));
    assert!(io.pool.owned.iter().all(|&b| !b));
    let mut fallback = io.fallback();
    let (socket, mut peer) = UnixStream::pair().unwrap();
    peer.write_all(b"fallback").unwrap();
    let mut bytes = [0; 8];
    let recv = opcode::Recv::new(types::Fd(socket.as_raw_fd()), bytes.as_mut_ptr(), 8)
        .build()
        .user_data(1);
    unsafe {
        push(&mut fallback, &recv);
    }
    submit(&mut fallback, 1);
    assert_eq!(fallback.completion().next().unwrap().result(), 8);
    assert_eq!(&bytes, b"fallback");
}

#[test]
fn partial_send_and_eagain_preserve_queued_output_while_receives_continue() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h1_pair(&mut worker);
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
    let mut expected: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    worker.socket(key).unwrap().conn.outbuf = expected.clone();
    worker.pending.push_back(Event {
        token: key | POLL,
        result: libc::POLLOUT as i32,
        more: false,
        buffer: None,
    });
    worker.step(-1, false);
    let first = worker.socket(key).unwrap().conn.out_off;
    assert!(first > 0 && first < expected.len(), "partial send required");
    assert!(worker.socket(key).unwrap().poll_active);
    // New input triggers another attempted send against the full send buffer.
    peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    until(&mut worker, |w| {
        w.writes
            .iter()
            .any(|&(k, r)| k == key && r == -libc::EAGAIN)
    });
    assert_eq!(worker.socket(key).unwrap().conn.out_off, first);
    expected.extend_from_slice(&response());
    peer.set_nonblocking(true).unwrap();
    let mut observed = Vec::new();
    let end = Instant::now() + Duration::from_secs(5);
    while observed.len() < expected.len() {
        let mut bytes = [0; 16384];
        match peer.read(&mut bytes) {
            Ok(n) => observed.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected read {result:?}"),
        }
        worker.step(-1, false);
        assert!(Instant::now() < end);
    }
    assert_eq!(observed, expected);
    assert!(worker.socket(key).unwrap().conn.outbuf.is_empty());
}

#[test]
fn interrupted_receive_wait_preserves_buffer_ownership() {
    use std::sync::atomic::AtomicUsize;
    static SIGNALS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn signal(_: libc::c_int) {
        SIGNALS.fetch_add(1, Ordering::Relaxed);
    }
    struct Restore(libc::sigaction);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::sigaction(libc::SIGUSR2, &self.0, std::ptr::null_mut());
            }
        }
    }
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = signal as *const () as usize;
    let mut previous = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR2, &action, &mut previous) },
        0
    );
    let _restore = Restore(previous);
    let target = unsafe { libc::pthread_self() };
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = h1_pair(&mut worker);
    worker.writes.clear();
    // Submit before blocking so the signal exercises the EINTR return path;
    // an enter that submitted an SQE can instead return its submitted count.
    submit(worker.io.ring(), 0);
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR2) }, 0);
            std::thread::sleep(Duration::from_millis(20));
            peer.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
                .unwrap();
            let mut bytes = vec![0; response().len()];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, response());
        });
        worker.step(-1, true);
        // A signal can also make GETEVENTS return success with an empty CQ.
        // The worker loop must keep driving until the actual receive arrives.
        until(&mut worker, |w| {
            w.writes.iter().any(|&(k, result)| k == key && result > 0)
        });
    });
    assert_eq!(SIGNALS.load(Ordering::Relaxed), 1);
}

#[test]
fn read_eof_preserves_partial_sends_and_discards_an_incomplete_field_block() {
    let mut worker = Worker::new(ring(2));
    let (key, mut peer) = pair(&mut worker);
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
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut wire = ((payload.len() as u32) << 8 | u32::from(kind))
            .to_be_bytes()
            .to_vec();
        wire.push(flags);
        wire.extend_from_slice(&stream.to_be_bytes());
        wire.extend_from_slice(payload);
        wire
    }
    let mut requests = crate::h2::PREFACE.to_vec();
    let mut expected = vec![
        0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 3, 127, 255, 255, 255, 0, 4, 127, 255, 255, 255,
    ];
    for stream in (1..2000).step_by(2) {
        requests.extend_from_slice(&frame(1, 5, stream, b"\x82\x86\x84"));
        expected.extend_from_slice(&frame(
            1,
            4,
            stream,
            b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33",
        ));
        expected.extend_from_slice(&frame(0, 1, stream, b"Hello, World!"));
    }
    requests.extend_from_slice(&frame(1, 1, 2001, b"start"));
    let unfinished = frame(9, 4, 2001, &[b'x'; 16_384]);
    requests.extend_from_slice(&unfinished[..unfinished.len() - 1]);
    peer.write_all(&requests).unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.get(key).unwrap().conn.read_eof);
    let socket = worker.socket(key).unwrap();
    assert!(socket.closing());
    assert!(!socket.recv_active && !socket.starved);
    assert!(socket.poll_active);
    assert!(socket.conn.out_off > 0 && socket.conn.out_off < socket.conn.outbuf.len());
    assert!(matches!(socket.conn.proto, Proto::H2(_)));
    assert_eq!(socket.conn.outbuf, expected);
    let receive_epoch = socket.recv_epoch;
    peer.set_nonblocking(true).unwrap();
    let mut observed = Vec::new();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        worker.step(-1, false);
        if let Some(socket) = worker.socket(key) {
            assert!(socket.conn.read_eof && !socket.recv_active);
            assert_eq!(socket.recv_epoch, receive_epoch, "EOF must not rearm input");
        }
        let mut bytes = [0; 16384];
        match peer.read(&mut bytes) {
            Ok(0) => break,
            Ok(n) => observed.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            result => panic!("unexpected read {result:?}"),
        }
        assert!(Instant::now() < end, "EOF output drain deadline");
    }
    assert_eq!(observed, expected);
    assert!(worker.sockets.get(key).is_none());
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}
