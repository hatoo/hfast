use super::*;

fn bytes(start: usize, count: usize) -> Vec<u8> {
    (start..start + count)
        .map(|i| (i.wrapping_mul(197) ^ (i >> 8)) as u8)
        .collect()
}

#[test]
fn reclamation_waits_for_a_large_prefix_and_preserves_every_pending_byte() {
    for (sent, pending, compact) in [
        (16 * 1024 - 1, 1, false),
        (16 * 1024, 1, true),
        (16 * 1024, 16 * 1024 + 1, false),
        (16 * 1024, 16 * 1024, true),
        (128 * 1024, 96 * 1024, true),
    ] {
        let data = bytes(0, sent + pending);
        let mut conn = Conn::new();
        conn.outbuf.extend_from_slice(&data);
        let ptr = conn.outbuf.as_ptr();
        let cap = conn.outbuf.capacity();
        assert!(conn.complete_send(sent as i32));
        assert_eq!(&conn.outbuf[conn.out_off..], &data[sent..]);
        assert_eq!(conn.out_off, if compact { 0 } else { sent });
        assert_eq!(conn.outbuf.as_ptr(), ptr, "reclamation must not allocate");
        assert_eq!(conn.outbuf.capacity(), cap);
        conn.outbuf.extend_from_slice(b"next response");
        let mut expected = data[sent..].to_vec();
        expected.extend_from_slice(b"next response");
        assert_eq!(&conn.outbuf[conn.out_off..], expected);
        assert!(conn.complete_send(expected.len() as i32));
        assert_eq!(conn.out_off, 0);
        assert!(conn.outbuf.is_empty());
    }
}

#[test]
fn retryable_and_fatal_completions_preserve_the_unsent_output() {
    for result in [
        -libc::EAGAIN,
        -libc::EINTR,
        0,
        -libc::EPIPE,
        -libc::ECONNRESET,
    ] {
        let mut conn = Conn::new();
        conn.outbuf = bytes(0, 40 * 1024);
        assert!(conn.complete_send(1024));
        let data = conn.outbuf.clone();
        let ptr = conn.outbuf.as_ptr();
        assert_eq!(
            conn.complete_send(result),
            result == -libc::EAGAIN || result == -libc::EINTR
        );
        assert_eq!(conn.outbuf, data);
        assert_eq!(conn.out_off, 1024);
        assert_eq!(conn.outbuf.as_ptr(), ptr);
    }
}

#[test]
fn continuously_pending_output_does_not_retain_historical_traffic() {
    let pending = 64 * 1024;
    let step = 4096;
    let mut conn = Conn::new();
    conn.outbuf = bytes(0, pending);
    let mut produced = pending;
    let mut sent = 0;
    let mut copied = 0;
    let mut compactions = 0;
    for _ in 0..4096 {
        conn.outbuf.extend_from_slice(&bytes(produced, step));
        produced += step;
        assert_eq!(
            &conn.outbuf[conn.out_off..conn.out_off + step],
            bytes(sent, step)
        );
        let before = conn.out_off;
        assert!(conn.complete_send(step as i32));
        sent += step;
        if conn.out_off < before + step {
            copied += pending;
            compactions += 1;
        }
        assert_eq!(conn.outbuf.len() - conn.out_off, pending);
        assert!(conn.outbuf.capacity() <= 2 * pending);
    }
    assert!(compactions > 1);
    assert!(
        copied <= sent,
        "copying must be amortized by completed sends"
    );
    assert_eq!(&conn.outbuf[conn.out_off..], bytes(sent, pending));
    assert!(conn.complete_send(pending as i32));
    assert!(conn.outbuf.is_empty());
    assert_eq!(conn.out_off, 0);
    let ptr = conn.outbuf.as_ptr();
    conn.outbuf.extend_from_slice(b"reused");
    assert_eq!(conn.outbuf, b"reused");
    assert_eq!(conn.outbuf.as_ptr(), ptr);
}

#[test]
fn mixed_appends_and_completions_match_a_byte_queue() {
    for seed in 1..=32u64 {
        let mut state = seed;
        let mut conn = Conn::new();
        let mut model = VecDeque::new();
        let mut produced = 0;
        let mut sent = 0;
        let mut copied = 0;
        for turn in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if model.is_empty() || state & 3 == 0 {
                let n = (state as usize >> 8) % 32768 + 1;
                let data = bytes(produced, n);
                produced += n;
                conn.outbuf.extend_from_slice(&data);
                model.extend(data);
            } else {
                let result = match turn % 19 {
                    0 => -libc::EAGAIN,
                    1 => -libc::EINTR,
                    _ => ((state as usize >> 8) % model.len() + 1) as i32,
                };
                let before = conn.out_off;
                if result > 0 {
                    for &actual in &conn.outbuf[before..before + result as usize] {
                        assert_eq!(Some(actual), model.pop_front());
                    }
                    sent += result as usize;
                }
                assert!(conn.complete_send(result));
                if result > 0 && conn.out_off < before + result as usize {
                    copied += conn.outbuf.len();
                }
            }
            assert!(
                conn.outbuf[conn.out_off..]
                    .iter()
                    .copied()
                    .eq(model.iter().copied())
            );
            assert_eq!(produced - sent, model.len());
            assert!(copied <= sent);
        }
        let n = model.len();
        if n > 0 {
            assert!(conn.complete_send(n as i32));
        }
        assert!(conn.outbuf.is_empty());
        assert_eq!(conn.out_off, 0);
    }
}

#[test]
fn fragmented_http1_requests_append_after_reclaimed_responses() {
    let mut expected = Vec::new();
    h1::respond(&mut expected);
    let response = expected.clone();
    let mut conn = Conn::new();
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    for _ in 0..1024 {
        assert!(consume(&mut conn, request));
    }
    expected = response.repeat(1024);
    let sent = expected.len() - 137;
    assert!(conn.complete_send(sent as i32));
    assert_eq!(conn.out_off, 0);
    assert!(consume(
        &mut conn,
        b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\ntest"
    ));
    assert_eq!(conn.outbuf, expected[sent..]);
    assert!(consume(
        &mut conn,
        b" bodyGET / HTTP/1.1\r\nHost: x\r\n\r\n"
    ));
    let mut suffix = expected[sent..].to_vec();
    suffix.extend_from_slice(&response.repeat(2));
    assert_eq!(conn.outbuf, suffix);
    assert!(conn.inbuf.is_empty());
}

/// Exercise the same kernel borrow/barrier as worker_ring, including genuine
/// partial sends and EAGAIN. A small socket send buffer forces backpressure.
#[test]
fn real_uring_partial_sends_keep_buffers_valid_and_bytes_in_order() {
    use io_uring::{opcode, types};
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let (writer, mut reader) = UnixStream::pair().unwrap();
    reader.set_nonblocking(true).unwrap();
    let size: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                writer.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as _,
            )
        },
        0
    );
    let mut ring = io_uring::IoUring::new(8).unwrap();
    let mut conn = Conn::new();
    let mut ready = VecDeque::new();
    let mut completions = Vec::new();
    let mut produced = 0;
    let mut received = Vec::new();
    let mut partials = 0;
    let mut retries = 0;
    let mut compactions = 0;
    let mut max_capacity = 0;
    let mut scratch = [0u8; 8192];
    for turn in 0..4096 {
        if turn < 256 && conn.outbuf.len() - conn.out_off < 64 * 1024 {
            conn.outbuf.extend_from_slice(&bytes(produced, 32768));
            produced += 32768;
        }
        let pending = conn.outbuf.len() - conn.out_off;
        if pending == 0 {
            break;
        }
        let entry = opcode::Send::new(
            types::Fd(writer.as_raw_fd()),
            unsafe { conn.outbuf.as_ptr().add(conn.out_off) },
            pending as _,
        )
        .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        .build()
        .user_data(IO);
        unsafe { push(&mut ring, &entry) };
        wait_batch(&mut ring, 1, &mut ready, &mut completions);
        assert_eq!(completions.len(), 1);
        assert!(ready.is_empty());
        let result = completions[0].1;
        if result > 0 && (result as usize) < pending {
            partials += 1;
        }
        if result == -libc::EAGAIN {
            retries += 1;
        }
        let old_off = conn.out_off;
        assert!(
            conn.complete_send(result),
            "unexpected send result {result}"
        );
        if result > 0 && !conn.outbuf.is_empty() && conn.out_off < old_off + result as usize {
            compactions += 1;
        }
        max_capacity = max_capacity.max(conn.outbuf.capacity());
        // Alternate withholding reads and fully draining the kernel queue.
        if turn % 2 == 1 || conn.outbuf.is_empty() {
            loop {
                match reader.read(&mut scratch) {
                    Ok(0) => panic!("unexpected EOF"),
                    Ok(n) => received.extend_from_slice(&scratch[..n]),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("receive: {e}"),
                }
            }
        }
    }
    assert!(conn.outbuf.is_empty(), "bounded loop must fully drain");
    assert_eq!(conn.out_off, 0);
    assert!(
        partials > 10 && retries > 10 && compactions > 10,
        "partial={partials}, EAGAIN={retries}, compact={compactions}"
    );
    assert!(max_capacity <= 256 * 1024, "capacity={max_capacity}");
    assert_eq!(received, bytes(0, produced));
}
