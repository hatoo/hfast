use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    wire.push(flags);
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn response(stream: u32) -> Vec<u8> {
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

fn connected() -> Conn {
    let mut conn = Conn::new();
    assert!(consume(&mut conn, h2::PREFACE));
    conn.outbuf.clear();
    conn
}

#[test]
fn every_field_payload_split_defers_the_response_until_the_final_byte() {
    for continuation in [false, true] {
        // Include the PADDED and PRIORITY forms. Their bytes are opaque to
        // this server just as on the original complete-frame path.
        for flags in [5, 0x0d, 0x25, 0x2d, 0x85] {
            let mut payload = vec![b'x'; 16_384];
            payload[0] = 3;
            let wire = frame(if continuation { 9 } else { 1 }, flags, 1, &payload);
            for split in 0..wire.len() {
                let mut conn = connected();
                if continuation {
                    assert!(consume(&mut conn, &frame(1, 1, 1, b"start")));
                }
                assert!(consume(&mut conn, &wire[..split]));
                assert!(conn.outbuf.is_empty(), "early response at {split}");
                assert!(consume(&mut conn, &[]));
                assert!(consume(&mut conn, &wire[split..wire.len() - 1]));
                assert!(conn.outbuf.is_empty());
                assert!(consume(&mut conn, &wire[wire.len() - 1..]));
                assert_eq!(conn.outbuf, response(1));
                assert!(conn.inbuf.is_empty());
            }
        }
    }
}

#[test]
fn invalid_fields_and_interleaving_fail_only_when_the_frame_is_complete() {
    let cases = [
        (false, frame(1, 4, 0, b"zero")),
        (false, frame(1, 4, 2, b"even")),
        (false, frame(9, 4, 1, b"unexpected")),
        (true, frame(9, 4, 3, b"wrong stream")),
        (true, frame(1, 4, 1, b"same stream")),
        (true, frame(1, 4, 3, b"other stream")),
        (true, frame(0, 1, 1, b"body")),
        (true, frame(4, 0, 0, &[0; 6])),
        (true, frame(6, 0, 0, b"12345678")),
        (true, frame(3, 0, 1, &[0; 4])),
        (true, frame(7, 0, 0, &[0; 8])),
    ];
    for (open, wire) in cases {
        for split in 0..wire.len() {
            let mut conn = connected();
            if open {
                assert!(consume(&mut conn, &frame(1, 0, 1, b"start")));
            }
            assert!(consume(&mut conn, &wire[..split]));
            assert!(consume(&mut conn, &wire[split..wire.len() - 1]));
            assert!(conn.outbuf.is_empty());
            assert!(!consume(&mut conn, &wire[wire.len() - 1..]));
            assert!(conn.outbuf.is_empty());
        }
    }
}

#[test]
fn fragmented_trailers_and_following_control_frames_preserve_exact_output() {
    let wire = [
        frame(1, 0, 1, b"start"),
        frame(9, 0, 1, b"middle"),
        frame(9, 4, 1, b"end"),
        frame(0, 0, 1, b"body"),
        frame(1, 1, 1, b"trailers"),
        frame(9, 4, 1, b"end trailers"),
        frame(4, 0, 0, b""),
        frame(6, 0, 0, b"12345678"),
        frame(3, 0, 1, &[0; 4]),
        frame(1, 5, 3, b"new"),
    ]
    .concat();
    let expected = [
        response(1),
        frame(4, 1, 0, b""),
        frame(6, 1, 0, b"12345678"),
        response(3),
    ]
    .concat();
    for chunk in 1..=wire.len() {
        let mut conn = connected();
        // Model output already partly sent: new replies must preserve its prefix.
        conn.outbuf.extend_from_slice(b"queued");
        conn.out_off = 3;
        for part in wire.chunks(chunk) {
            assert!(consume(&mut conn, part));
        }
        assert_eq!(conn.out_off, 3);
        assert_eq!(conn.outbuf, [b"queued".as_slice(), &expected].concat());
        assert!(!consume(&mut conn, &frame(7, 0, 0, &[0; 8])));
    }
}

#[test]
fn truncated_field_blocks_leave_only_prior_responses_at_half_close() {
    for continuation in [false, true] {
        let wire = frame(if continuation { 9 } else { 1 }, 4, 3, &[b'x'; 128]);
        for end in 0..wire.len() {
            let mut conn = connected();
            assert!(consume(&mut conn, &frame(1, 5, 1, b"complete")));
            if continuation {
                assert!(consume(&mut conn, &frame(1, 0, 3, b"start")));
            }
            conn.out_off = 7;
            for part in wire[..end].chunks(3) {
                assert!(consume(&mut conn, part));
            }
            conn.read_eof = true;
            assert!(conn.closing());
            assert_eq!(conn.outbuf, response(1));
            assert_eq!(conn.out_off, 7);
            // A replacement connection has no inherited pending frame/stream.
            let mut replacement = connected();
            assert!(consume(&mut replacement, &frame(1, 5, 1, b"replacement")));
            assert_eq!(replacement.outbuf, response(1));
        }
    }
}
