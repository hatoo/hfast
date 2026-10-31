use super::tests::ring;
use super::*;
use std::io::Read;
use std::time::{Duration, Instant};

#[test]
fn zero_wait_and_full_sq_run_multishot_work_before_republishing_buffers() {
    let mut io = ring(2);
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let receive = opcode::RecvMulti::new(types::Fd(socket.as_raw_fd()), GROUP)
        .build()
        .user_data(RECV | 1);
    unsafe { push(io.ring(), &receive) };
    submit(io.ring(), 0);
    for round in 0..32_u8 {
        let bytes = [round; 17];
        peer.write_all(&bytes).unwrap();
        // The ninth NOP enters through push's SQ-pressure path. Deferred
        // receive work must run there even if ready completions already exist.
        for token in 100..109 {
            let nop = opcode::Nop::new().build().user_data(token);
            unsafe { push(io.ring(), &nop) };
        }
        let end = Instant::now() + Duration::from_secs(2);
        let mut nops = Vec::new();
        let mut observed = Vec::new();
        while nops.len() < 9 || observed.len() < bytes.len() {
            submit(io.ring(), 0);
            let completions: Vec<_> = io.ring().completion().collect();
            for c in completions {
                if c.user_data() == RECV | 1 {
                    assert!(c.result() > 0 && cqueue::more(c.flags()));
                    let id = io.pool.claim(c.result(), c.flags()).unwrap();
                    observed.extend_from_slice(io.pool.bytes(id, c.result() as usize));
                    io.pool.release(id);
                    io.pool.publish();
                } else {
                    assert_eq!(c.result(), 0);
                    nops.push(c.user_data());
                }
            }
            assert!(Instant::now() < end, "deferred multishot was stranded");
        }
        nops.sort_unstable();
        assert_eq!(nops, (100..109).collect::<Vec<_>>());
        assert_eq!(observed, bytes);
        assert!(io.pool.owned.iter().all(|&owned| !owned));
    }
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        submit(io.ring(), 0);
        let completion = io.ring().completion().next();
        if let Some(c) = completion {
            assert_eq!(c.user_data(), RECV | 1);
            assert_eq!(c.result(), 0);
            assert!(!cqueue::more(c.flags()));
            if let Some(id) = io.pool.claim(c.result(), c.flags()) {
                io.pool.release(id);
                io.pool.publish();
            }
            break;
        }
        assert!(Instant::now() < end, "deferred EOF was stranded");
    }
    assert!(io.ring().completion().is_empty());
}

fn each_worker(mut test: impl FnMut(Worker)) {
    // Exercise the ordinary fallback, production deferred setup, and optional
    // task-work notification. A false taskrun() is meaningful only in the last.
    for mode in 0..3 {
        let mut builder = IoUring::builder();
        if mode != 0 {
            builder
                .setup_single_issuer()
                .setup_coop_taskrun()
                .setup_defer_taskrun();
        }
        if mode == 2 {
            builder.setup_taskrun_flag();
        }
        let ring = match builder.build(8) {
            Ok(ring) => ring,
            Err(e) if mode != 0 && e.raw_os_error() == Some(libc::EINVAL) => {
                eprintln!("kernel lacks task-work setup {mode}; ordinary setup tested");
                continue;
            }
            Err(e) => panic!("task-work setup {mode}: {e}"),
        };
        test(Worker::new(ReceiveRing::new(ring, 2).ok().unwrap()));
    }
}

fn backlog_step(worker: &mut Worker) {
    // Old-generation events are harmless but consume the bounded event budget.
    // Keep some queued across every turn, without creating reads or sends that
    // would incidentally enter the kernel and hide a missing step entry.
    while worker.pending.len() < 2 * BATCH + 1 {
        worker.pending.push_back(Event {
            token: POLL | !KIND,
            result: libc::POLLIN as i32,
            more: false,
            buffer: None,
        });
    }
    assert!(worker.sockets.get(!KIND).is_none());
    worker.step(-1, true);
    assert!(!worker.pending.is_empty(), "the backlog must stay nonempty");
}

fn backlog_until(worker: &mut Worker, done: impl Fn(&Worker) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done(worker) {
        backlog_step(worker);
        assert!(
            Instant::now() < deadline,
            "late input stranded behind backlog"
        );
        std::thread::yield_now();
    }
}

#[test]
fn late_poll_progresses_while_the_worker_backlog_stays_nonempty() {
    each_worker(|mut worker| {
        let (key, mut peer) = tests::pair(&mut worker);
        // Arm while the peer is silent, then leave only an old ready backlog.
        submit(worker.io.ring(), 0);
        worker.drain();
        backlog_step(&mut worker);
        assert!(worker.io.ring().submission().is_empty());
        assert!(worker.socket(key).unwrap().poll_active);
        peer.write_all(b"GET / HTTP/1.1\r\nHost: late\r\n\r\n")
            .unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        backlog_until(&mut worker, |w| w.sockets.get(key).is_none());
        backlog_step(&mut worker); // Submit any retirement cancellation.
        let mut observed = Vec::new();
        peer.read_to_end(&mut observed).unwrap();
        assert_eq!(observed, tests::response());
        assert!(worker.io.pool.owned.iter().all(|&owned| !owned));
    });
}

#[test]
fn late_multishot_fragments_reuse_buffers_behind_a_persistent_backlog() {
    use super::selection_tests::{frame, h2_response, settings};
    each_worker(|mut worker| {
        let (h1, mut peer1) = tests::h1_pair(&mut worker);
        let (h2, mut peer2) = tests::pair(&mut worker);
        peer2.write_all(crate::h2::PREFACE).unwrap();
        tests::until(&mut worker, |w| w.sockets.get(h2).unwrap().recv_active);
        let mut initial = vec![0; settings().len()];
        peer2.read_exact(&mut initial).unwrap();
        assert_eq!(initial, settings());
        // Submit both multishot receives before providing any of the late data.
        submit(worker.io.ring(), 0);
        worker.drain();
        assert!(worker.pending.is_empty());
        backlog_step(&mut worker);
        assert!(worker.io.ring().submission().is_empty());
        for key in [h1, h2] {
            let s = worker.socket(key).unwrap();
            assert!(s.recv_active && !s.poll_active && s.conn.outbuf.is_empty());
        }

        for stream in (1..16).step_by(2) {
            let request = frame(1, 5, stream, b"\x82\x84\x86");
            let epoch = worker.io.pool.epoch;
            peer1.write_all(b"GET / HTTP/1.1\r\nHost: ").unwrap();
            peer2.write_all(&request[..7]).unwrap();
            backlog_until(&mut worker, |w| w.io.pool.epoch >= epoch + 2);
            assert_eq!(worker.socket(h2).unwrap().conn.inbuf, &request[..7]);
            for peer in [&mut peer1, &mut peer2] {
                peer.set_nonblocking(true).unwrap();
                assert_eq!(
                    peer.read(&mut [0]).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                peer.set_nonblocking(false).unwrap();
            }

            let epoch = worker.io.pool.epoch;
            peer1.write_all(b"late\r\n\r\n").unwrap();
            peer2.write_all(&request[7..]).unwrap();
            backlog_until(&mut worker, |w| w.io.pool.epoch >= epoch + 2);
            for (peer, expected) in [
                (&mut peer1, tests::response()),
                (&mut peer2, h2_response(stream)),
            ] {
                let mut observed = vec![0; expected.len()];
                peer.read_exact(&mut observed).unwrap();
                assert_eq!(observed, expected);
            }
            assert!(worker.socket(h2).unwrap().conn.inbuf.is_empty());
            assert!(worker.io.pool.owned.iter().all(|&owned| !owned));
            assert_eq!(worker.io.pool.tail, worker.io.pool.published);
        }
        for peer in [&peer1, &peer2] {
            peer.shutdown(std::net::Shutdown::Write).unwrap();
        }
        backlog_until(&mut worker, |w| w.sockets.is_empty());
        backlog_step(&mut worker);
        for peer in [&mut peer1, &mut peer2] {
            let mut extra = Vec::new();
            peer.read_to_end(&mut extra).unwrap();
            assert!(
                extra.is_empty(),
                "unexpected response after the last request"
            );
        }
        assert!(worker.io.pool.owned.iter().all(|&owned| !owned));
        assert_eq!(worker.io.pool.tail, worker.io.pool.published);
    });
}

#[test]
fn overflow_is_flushed_while_the_worker_backlog_stays_nonempty() {
    each_worker(|mut worker| {
        assert!(worker.io.ring().params().is_feature_nodrop());
        assert_eq!(worker.io.ring().params().cq_entries(), 16);
        backlog_step(&mut worker);
        // NOP completions use distinct retired-generation poll tokens. They
        // neither touch a live socket nor trigger another submission barrier.
        let token_base = POLL | (1 << 40);
        for batch in 0..3 {
            for i in 0..8 {
                let entry = opcode::Nop::new()
                    .build()
                    .user_data(token_base + batch * 8 + i);
                unsafe { push(worker.io.ring(), &entry) };
            }
            submit(worker.io.ring(), 0);
        }
        assert!(worker.io.ring().submission().cq_overflow());
        let mut seen: Vec<_> = worker
            .io
            .ring()
            .completion()
            .map(|c| {
                assert_eq!(c.result(), 0);
                c.user_data()
            })
            .collect();
        assert_eq!(seen.len(), 16);
        assert!(worker.io.ring().submission().is_empty());
        backlog_step(&mut worker);
        assert!(
            !worker.io.ring().submission().cq_overflow(),
            "overflow stranded behind backlog"
        );
        seen.extend(
            worker
                .pending
                .iter()
                .filter(|e| e.token != POLL | !KIND)
                .map(|e| {
                    assert_eq!(e.result, 0);
                    e.token
                }),
        );
        seen.sort_unstable();
        assert_eq!(seen, (token_base..token_base + 24).collect::<Vec<_>>());
        assert_eq!(worker.io.ring().completion().overflow(), 0);
    });
}
