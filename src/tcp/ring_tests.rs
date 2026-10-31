//! Real kernel tests for the worker's completion barriers, on both setup paths.
use super::*;
use io_uring::{IoUring, opcode, types};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn each_ring(entries: u32, mut test: impl FnMut(IoUring)) {
    test(IoUring::new(entries).expect("plain io_uring"));
    match IoUring::builder()
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .build(entries)
    {
        Ok(ring) => test(ring),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            eprintln!("kernel lacks deferred task work; plain path tested");
        }
        Err(e) => panic!("deferred io_uring: {e}"),
    }
}

#[test]
fn successful_setup_does_not_try_the_fallback() {
    let mut attempts = Vec::new();
    let _ring = build_ring_with(|deferred| {
        attempts.push(deferred);
        IoUring::new(2)
    })
    .unwrap();
    assert_eq!(attempts, [true]);
}

#[test]
fn zero_wait_flushes_real_completion_overflow_without_losing_tokens() {
    each_ring(8, |mut ring| {
        assert!(ring.params().is_feature_nodrop());
        let capacity = ring.params().cq_entries() as usize;
        assert_eq!(capacity, 16);
        for batch in 0..3 {
            for i in 0..8 {
                let entry = opcode::Nop::new().build().user_data((batch * 8 + i) as u64);
                unsafe { push(&mut ring, &entry) };
            }
            submit(&mut ring, 0);
        }
        assert!(ring.submission().cq_overflow());
        let mut tokens: Vec<_> = ring
            .completion()
            .map(|c| {
                assert_eq!(c.result(), 0);
                c.user_data()
            })
            .collect();
        assert_eq!(tokens.len(), capacity);
        assert!(ring.submission().is_empty());
        submit(&mut ring, 0);
        tokens.extend(ring.completion().map(|c| {
            assert_eq!(c.result(), 0);
            c.user_data()
        }));
        tokens.sort_unstable();
        assert_eq!(tokens, (0..24).collect::<Vec<_>>());
        assert!(!ring.submission().cq_overflow());
        assert_eq!(ring.completion().overflow(), 0);
    });
}

#[test]
fn unsupported_flags_fall_back_to_a_working_plain_ring() {
    let mut attempts = Vec::new();
    let mut ring = build_ring_with(|deferred| {
        attempts.push(deferred);
        if deferred {
            Err(std::io::Error::from_raw_os_error(libc::EINVAL))
        } else {
            IoUring::new(2)
        }
    })
    .unwrap();
    assert_eq!(attempts, [true, false]);
    let entry = opcode::Nop::new().build().user_data(IO | 7);
    unsafe { push(&mut ring, &entry) };
    let mut ready = VecDeque::new();
    let mut completions = Vec::new();
    wait_batch(&mut ring, 1, &mut ready, &mut completions);
    assert_eq!(completions, [(7, 0)]);
    assert!(ready.is_empty());
}

#[test]
fn setup_errors_are_not_hidden_by_an_unrelated_fallback() {
    for error in [libc::EPERM, libc::ENOMEM, libc::EMFILE, libc::ENOSYS] {
        let mut attempts = Vec::new();
        let result = build_ring_with(|deferred| {
            attempts.push(deferred);
            Err(std::io::Error::from_raw_os_error(error))
        });
        assert_eq!(result.err().unwrap().raw_os_error(), Some(error));
        assert_eq!(attempts, [true]);
    }
    let result = build_ring_with(|deferred| {
        Err(std::io::Error::from_raw_os_error(if deferred {
            libc::EINVAL
        } else {
            libc::EMFILE
        }))
    });
    assert_eq!(result.err().unwrap().raw_os_error(), Some(libc::EMFILE));
}

#[test]
fn interrupted_wait_keeps_the_io_buffer_live_until_completion() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SIGNALS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn count_signal(_: libc::c_int) {
        SIGNALS.fetch_add(1, Ordering::Relaxed);
    }
    struct Restore(libc::sigaction);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut()) };
        }
    }
    // SIGUSR1 is otherwise unused by these tests. Only this test thread is
    // signalled, with SA_RESTART off so a blocked enter can return EINTR.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = count_signal as *const () as usize;
    let mut previous = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) },
        0
    );
    let _restore = Restore(previous);
    each_ring(2, |mut ring| {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let target = unsafe { libc::pthread_self() };
        let before = SIGNALS.load(Ordering::Relaxed);
        let mut received = [0; 4];
        let read = opcode::Recv::new(types::Fd(socket.as_raw_fd()), received.as_mut_ptr(), 4)
            .build()
            .user_data(IO | 7);
        unsafe { push(&mut ring, &read) };
        submit(&mut ring, 0);
        let mut ready = VecDeque::new();
        let mut completions = Vec::new();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR1) }, 0);
                std::thread::sleep(Duration::from_millis(20));
                peer.write_all(b"wake").unwrap();
            });
            wait_batch(&mut ring, 1, &mut ready, &mut completions);
        });
        assert_eq!(SIGNALS.load(Ordering::Relaxed), before + 1);
        assert!(ready.is_empty());
        assert_eq!(completions, [(7, 4)]);
        assert_eq!(&received, b"wake");
    });
}

#[test]
fn zero_wait_runs_poll_task_work_with_an_existing_ready_queue() {
    each_ring(2, |mut ring| {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        arm_poll(&mut ring, socket.as_raw_fd(), libc::POLLIN, 27);
        submit(&mut ring, 0);
        let mut ready = VecDeque::from([(19, libc::POLLOUT as i32)]);
        let mut completions = Vec::new();
        // This becomes ready after submission; only zero-wait enters may make
        // progress, just as when the worker keeps finding old ready sockets.
        peer.write_all(b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while ready.len() < 2 {
            submit(&mut ring, 0);
            drain_completions(&mut ring, &mut ready, &mut completions);
            assert!(Instant::now() < deadline, "deferred poll was stranded");
        }
        assert_eq!(ready.pop_front(), Some((19, libc::POLLOUT as i32)));
        assert_eq!(ready.pop_front(), Some((27, libc::POLLIN as i32)));
        assert!(completions.is_empty());
    });
}

#[test]
fn sq_pressure_and_interleaved_polls_preserve_the_io_barrier() {
    each_ring(2, |mut ring| {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let (empty, _peer) = UnixStream::pair().unwrap();
        peer.write_all(b"batch").unwrap();
        let mut received = [0; 5];
        let mut unused = [0; 1];
        arm_poll(&mut ring, socket.as_raw_fd(), libc::POLLIN, 29);
        let read = opcode::Recv::new(types::Fd(socket.as_raw_fd()), received.as_mut_ptr(), 5)
            .flags(libc::MSG_DONTWAIT)
            .build()
            .user_data(IO | 3);
        let again = opcode::Recv::new(types::Fd(empty.as_raw_fd()), unused.as_mut_ptr(), 1)
            .flags(libc::MSG_DONTWAIT)
            .build()
            .user_data(IO | 5);
        unsafe {
            push(&mut ring, &read);
            // The third entry must submit the full two-entry SQ first.
            push(&mut ring, &again);
        }
        let mut ready = VecDeque::new();
        let mut completions = Vec::new();
        wait_batch(&mut ring, 2, &mut ready, &mut completions);
        completions.sort_unstable();
        assert_eq!(completions, [(3, 5), (5, -libc::EAGAIN)]);
        assert_eq!(&received, b"batch");
        assert_eq!(ready, [(29, libc::POLLIN as i32)]);
        // The poll was one-shot: a new read requires an explicit rearm.
        submit(&mut ring, 0);
        assert!(ring.completion().is_empty());
    });
}

#[test]
fn partial_sends_and_eagain_keep_every_byte_until_completion() {
    each_ring(2, |mut ring| {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let size: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            },
            0
        );
        let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let mut observed = Vec::new();
        let mut ready = VecDeque::new();
        let mut completions = Vec::new();
        let mut sent = 0;
        while sent < data.len() {
            let send = opcode::Send::new(
                types::Fd(socket.as_raw_fd()),
                data[sent..].as_ptr(),
                (data.len() - sent) as _,
            )
            .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
            .build()
            .user_data(IO | 2);
            unsafe { push(&mut ring, &send) };
            wait_batch(&mut ring, 1, &mut ready, &mut completions);
            let n = completions[0].1;
            assert!(n > 0);
            if sent == 0 {
                assert!((n as usize) < data.len(), "expected a partial send");
                let blocked = opcode::Send::new(types::Fd(socket.as_raw_fd()), data.as_ptr(), 1)
                    .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
                    .build()
                    .user_data(IO | 4);
                unsafe { push(&mut ring, &blocked) };
                wait_batch(&mut ring, 1, &mut ready, &mut completions);
                assert_eq!(completions, [(4, -libc::EAGAIN)]);
            }
            let old = observed.len();
            observed.resize(old + n as usize, 0);
            peer.read_exact(&mut observed[old..]).unwrap();
            sent += n as usize;
        }
        assert_eq!(observed, data);
        assert!(ready.is_empty());
    });
}

#[test]
fn retiring_poll_and_read_before_close_allows_fd_reuse() {
    each_ring(2, |mut ring| {
        let mut ready = VecDeque::new();
        let mut completions = Vec::new();
        for generation in 0..128_u8 {
            let (socket, mut peer) = UnixStream::pair().unwrap();
            arm_poll(
                &mut ring,
                socket.as_raw_fd(),
                libc::POLLIN,
                generation as u64,
            );
            submit(&mut ring, 0);
            peer.write_all(&[generation]).unwrap();
            submit(&mut ring, 1);
            drain_completions(&mut ring, &mut ready, &mut completions);
            assert_eq!(
                ready.pop_front(),
                Some((generation as u64, libc::POLLIN as i32))
            );
            assert!(ready.is_empty());
            let mut byte = [0];
            let read = opcode::Recv::new(types::Fd(socket.as_raw_fd()), byte.as_mut_ptr(), 1)
                .flags(libc::MSG_DONTWAIT)
                .build()
                .user_data(IO);
            unsafe { push(&mut ring, &read) };
            wait_batch(&mut ring, 1, &mut ready, &mut completions);
            assert_eq!(completions, [(0, 1)]);
            assert_eq!(byte, [generation]);
            assert!(ready.is_empty());
            // Drop only after both operations have completed. Subsequent pairs
            // may reuse these descriptors without inheriting a live poll.
        }
    });
}
