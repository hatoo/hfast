use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// The original assembly strategy is a semantic oracle, independent of the
// optimized path's frame-boundary decisions. The parser itself is unchanged.
fn buffered_consume(conn: &mut Conn, data: &[u8]) -> bool {
    if conn.inbuf.is_empty() {
        let Some(used) = conn.drive(data) else {
            return false;
        };
        conn.inbuf.extend_from_slice(&data[used..]);
    } else {
        let mut buf = std::mem::take(&mut conn.inbuf);
        buf.extend_from_slice(data);
        let used = conn.drive(&buf);
        conn.inbuf = buf;
        let Some(used) = used else {
            return false;
        };
        conn.inbuf.drain(..used);
    }
    true
}

fn compare(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> bool {
    let mut actual = Conn::new();
    let mut reference = Conn::new();
    for part in parts {
        let alive = consume(&mut actual, part.as_ref());
        assert_eq!(alive, buffered_consume(&mut reference, part.as_ref()));
        assert_eq!(actual.outbuf, reference.outbuf);
        assert_eq!(actual.out_off, reference.out_off);
        if !alive {
            // The worker drops the connection on false, including any input
            // after the rejected frame. None of that input is processed.
            return false;
        }
        assert_eq!(actual.inbuf, reference.inbuf);
        assert_eq!(
            std::mem::discriminant(&actual.proto),
            std::mem::discriminant(&reference.proto)
        );
    }
    true
}

fn requests() -> Vec<u8> {
    [
        h2::PREFACE.to_vec(),
        frame(4, 0, 0, &[0, 3, 0, 0, 0, 32]),
        frame(4, 1, 0, b""),
        frame(1, 5, 1, b"\x82\x86\x84"),
        frame(1, 0, 3, b"start"),
        frame(9, 0, 3, b""),
        frame(9, 0, 3, b"middle"),
        frame(9, 4, 3, b""),
        frame(0, 0, 3, b"body part"),
        frame(0, 1, 3, b"end"),
        frame(1, 5, 0x8000_0005, b"\x82\x86\x84"),
        frame(0xfd, 0xff, 0, b"ignored extension"),
        frame(6, 0, 0, b"12345678"),
        frame(6, 1, 0, b"abcdefgh"),
    ]
    .concat()
}

#[test]
fn every_split_matches_buffered_frames_and_output() {
    let input = requests();
    for split in 0..=input.len() {
        assert!(compare([&input[..split], b"", &input[split..], b""]));
    }
    for size in 1..=input.len() {
        assert!(compare(input.chunks(size)));
    }
}

#[test]
fn incomplete_and_invalid_frames_match_until_the_connection_closes() {
    for (prefix, bad) in [
        (vec![], frame(7, 0, 0, &[0; 8])),
        (vec![], frame(1, 5, 0, b"zero stream")),
        (vec![], frame(9, 4, 1, b"unexpected")),
        (frame(1, 0, 3, b"start"), frame(9, 4, 5, b"wrong")),
        (frame(1, 0, 3, b"start"), frame(6, 0, 0, b"12345678")),
        (frame(1, 0, 3, b"start"), frame(0xee, 0, 0, b"")),
    ] {
        let mut input = h2::PREFACE.to_vec();
        input.extend_from_slice(&frame(1, 5, 1, b"\x82\x86\x84"));
        input.extend_from_slice(&prefix);
        let before_error = input.len();
        input.extend_from_slice(&bad);
        let after_error = input.len();
        input.extend_from_slice(&frame(1, 5, 7, b"must not answer"));
        for split in 0..=input.len() {
            assert!(!compare([&input[..split], &input[split..]]));
        }
        for end in before_error..after_error {
            // Even an invalid frame must wait for its entire payload before
            // the unchanged parser can decide to close the connection.
            assert!(compare(input[..end].chunks(1)));
        }
        for size in 1..=bad.len() + 9 {
            assert!(!compare(input.chunks(size)));
        }
    }
}

fn next(seed: &mut u64) -> usize {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed as usize
}

#[test]
fn seeded_frame_streams_match_with_large_payloads_and_partial_tails() {
    for seed in 1..=32 {
        let mut rng = seed;
        let mut input = h2::PREFACE.to_vec();
        for stream in (1..128).step_by(2) {
            let size = [0, 1, 8, 53, 256, 16_384][next(&mut rng) % 6];
            let payload = vec![stream as u8; size];
            if next(&mut rng).is_multiple_of(2) {
                input.extend_from_slice(&frame(1, 1, stream, &payload));
                input.extend_from_slice(&frame(9, 4, stream, b""));
            } else {
                input.extend_from_slice(&frame(1, 5, stream, &payload));
            }
            input.extend_from_slice(&frame(0, 1, stream, &payload));
            input.extend_from_slice(&frame(6, 0, 0, &seed.to_be_bytes()));
        }
        let tail = frame(1, 5, 129, b"unfinished");
        input.extend_from_slice(&tail[..next(&mut rng) % tail.len()]);
        let mut at = 0;
        let parts = std::iter::from_fn(|| {
            if at == input.len() {
                return None;
            }
            let size = [1, 8, 9, 53, 4096, 16_384][next(&mut rng) % 6];
            let end = (at + size).min(input.len());
            let part = &input[at..end];
            at = end;
            Some(part)
        });
        assert!(compare(parts), "seed {seed}");
    }
}

#[test]
fn completing_one_frame_does_not_buffer_the_rest_of_the_receive() {
    let request = frame(1, 5, 1, b"\x82\x86\x84");
    let mut conn = Conn::new();
    assert!(consume(&mut conn, h2::PREFACE));
    conn.outbuf.clear();
    assert!(consume(&mut conn, &request[..5]));
    let mut rest = request[5..].to_vec();
    for stream in (3..4097).step_by(2) {
        rest.extend_from_slice(&frame(1, 5, stream, b"\x82\x86\x84"));
    }
    rest.extend_from_slice(&request[..2]);
    assert!(consume(&mut conn, &rest));
    assert_eq!(conn.inbuf, request[..2]);
    assert!(
        conn.inbuf.capacity() < 128,
        "capacity {}",
        conn.inbuf.capacity()
    );
    // Two response frames, 50 bytes in all, for each of the 2048 requests.
    assert_eq!(conn.outbuf.len(), 2048 * 50);
    assert!(consume(&mut conn, &request[2..]));
    assert!(conn.inbuf.is_empty());
    assert_eq!(conn.outbuf.len(), 2049 * 50);
}

#[test]
fn the_full_length_field_is_used_without_reserving_absent_payload() {
    let mut conn = Conn::new();
    assert!(consume(&mut conn, h2::PREFACE));
    conn.outbuf.clear();
    for byte in [0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 1, 2, 3] {
        assert!(consume(&mut conn, &[byte]));
    }
    assert_eq!(conn.inbuf.len(), 12);
    assert!(conn.inbuf.capacity() < 128);
    assert!(conn.outbuf.is_empty());
}

#[test]
fn preface_detection_http1_and_connection_reuse_are_unchanged() {
    for input in [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcdeGET /tail".as_slice(),
        b"PRINT / HTTP/1.1\r\nContent-Length: 0\r\n\r\nHEAD / HTTP/1.1\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n",
    ] {
        for split in 0..=input.len() {
            compare([&input[..split], b"", &input[split..]]);
        }
        for size in 1..=input.len() {
            compare(input.chunks(size));
        }
    }
    for end in 0..requests().len() {
        let mut abandoned = Conn::new();
        assert!(consume(&mut abandoned, &requests()[..end]));
        drop(abandoned);
        assert!(compare(requests().chunks(7)));
    }
}

#[test]
fn io_uring_receives_feed_the_same_carry_and_response_bytes() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let mut ring = io_uring::IoUring::new(2).unwrap();
    let mut actual = Conn::new();
    let mut reference = Conn::new();
    let input = requests();
    let mut scratch = [0u8; 53];
    for part in input.chunks(scratch.len()) {
        sender.write_all(part).unwrap();
        let mut received = 0;
        while received < part.len() {
            let entry = io_uring::opcode::Recv::new(
                io_uring::types::Fd(receiver.as_raw_fd()),
                scratch.as_mut_ptr(),
                (part.len() - received) as _,
            )
            .build();
            // scratch and receiver stay alive and untouched through the CQE.
            unsafe { ring.submission().push(&entry).unwrap() };
            ring.submit_and_wait(1).unwrap();
            let count = ring.completion().next().unwrap().result();
            assert!(count > 0);
            let data = &scratch[..count as usize];
            assert!(consume(&mut actual, data));
            assert!(buffered_consume(&mut reference, data));
            assert_eq!(actual.inbuf, reference.inbuf);
            assert_eq!(actual.outbuf, reference.outbuf);
            received += count as usize;
        }
    }
    assert!(actual.inbuf.is_empty());
}
