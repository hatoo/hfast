use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut result = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    result.push(flags);
    result.extend_from_slice(&stream.to_be_bytes());
    result.extend_from_slice(payload);
    result
}

// An independent wire expectation, including END_STREAM and content-length.
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

#[test]
fn fragmented_headers_respond_only_after_the_last_whole_continuation() {
    for end_stream in [0, FLAG_ACK_OR_END_STREAM] {
        for payload in [b"".as_slice(), b"header fragment".as_slice()] {
            let mut out = Vec::new();
            let mut conn = Conn::new(&mut out);
            out.clear();
            for part in [
                frame(HEADERS, end_stream, 7, payload),
                frame(CONTINUATION, 0, 7, b""),
                frame(CONTINUATION, 0, 7, payload),
            ] {
                assert_eq!(conn.drive(&part, &mut out), Some(part.len()));
                assert!(out.is_empty());
            }
            let last = frame(CONTINUATION, FLAG_END_HEADERS, 7, payload);
            for end in 0..last.len() {
                assert_eq!(conn.drive(&last[..end], &mut out), Some(0));
                assert!(out.is_empty());
            }
            assert_eq!(conn.drive(&last, &mut out), Some(last.len()));
            assert_eq!(out, response(7));
            out.clear();
            let body = frame(DATA, FLAG_ACK_OR_END_STREAM, 7, b"request body");
            assert_eq!(conn.drive(&body, &mut out), Some(body.len()));
            assert!(out.is_empty());
            assert_eq!(conn.drive(&[], &mut out), Some(0));
            // END_HEADERS completed this block; another continuation is invalid.
            assert_eq!(conn.drive(&last, &mut out), None);
            assert!(out.is_empty());
        }
    }
}

#[test]
fn every_receive_split_preserves_response_order_and_consumed_bytes() {
    let frames = [
        frame(HEADERS, FLAG_END_HEADERS, 1, b"first"),
        frame(HEADERS, 0, 3, b"a"),
        frame(CONTINUATION, 0, 3, b""),
        frame(CONTINUATION, FLAG_END_HEADERS, 3, b"b"),
        frame(DATA, FLAG_ACK_OR_END_STREAM, 3, b"body"),
        frame(HEADERS, FLAG_ACK_OR_END_STREAM, 5, b""),
        frame(CONTINUATION, FLAG_END_HEADERS, 5, b"last"),
        frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_ACK_OR_END_STREAM,
            7,
            b"tail",
        ),
    ];
    let wire = frames.concat();
    let expected = [response(1), response(3), response(5), response(7)].concat();
    let mut boundaries = vec![0];
    for part in &frames {
        boundaries.push(boundaries.last().unwrap() + part.len());
    }
    for split in 0..=wire.len() {
        let mut out = Vec::new();
        let mut conn = Conn::new(&mut out);
        out.clear();
        let used = conn.drive(&wire[..split], &mut out).unwrap();
        assert_eq!(
            used,
            *boundaries.iter().filter(|&&b| b <= split).max().unwrap()
        );
        assert_eq!(conn.drive(&wire[used..], &mut out), Some(wire.len() - used));
        assert_eq!(out, expected, "split {split}");
    }
    // Exercise a carried partial frame repeatedly, not just one split per input.
    for chunk in 1..=wire.len() {
        let mut out = Vec::new();
        let mut conn = Conn::new(&mut out);
        out.clear();
        let mut pending = Vec::new();
        for part in wire.chunks(chunk) {
            pending.extend_from_slice(part);
            let used = conn.drive(&pending, &mut out).unwrap();
            pending.drain(..used);
        }
        assert!(pending.is_empty());
        assert_eq!(out, expected, "chunk {chunk}");
    }
}

#[test]
fn continuation_rejects_interleaving_and_wrong_streams_without_responding() {
    for invalid in [
        frame(HEADERS, FLAG_END_HEADERS, 1, b"same stream"),
        frame(HEADERS, FLAG_END_HEADERS, 3, b"different stream"),
        frame(CONTINUATION, FLAG_END_HEADERS, 3, b"wrong stream"),
        frame(CONTINUATION, 0, 0, b"connection stream"),
        frame(DATA, FLAG_ACK_OR_END_STREAM, 1, b"early body"),
        frame(SETTINGS, 0, 0, b""),
        frame(PING, 0, 0, b"12345678"),
        frame(0x3, 0, 1, &[0; 4]),       // RST_STREAM
        frame(0x8, 0, 0, &[0, 0, 0, 1]), // WINDOW_UPDATE
        frame(0xff, 0, 1, b"extension"),
        frame(GOAWAY, 0, 0, &[0; 8]),
    ] {
        for coalesced in [false, true] {
            let mut out = Vec::new();
            let mut conn = Conn::new(&mut out);
            out.clear();
            let mut first = frame(HEADERS, 0, 1, b"pending");
            if coalesced {
                first.extend_from_slice(&invalid);
                assert_eq!(conn.drive(&first, &mut out), None);
            } else {
                assert_eq!(conn.drive(&first, &mut out), Some(first.len()));
                assert_eq!(conn.drive(&invalid, &mut out), None);
            }
            assert!(out.is_empty());
        }
    }
}

#[test]
fn unexpected_continuations_and_stream_zero_are_rejected() {
    for kind in [HEADERS, CONTINUATION] {
        for flags in [0, FLAG_END_HEADERS] {
            let mut out = Vec::new();
            let mut conn = Conn::new(&mut out);
            out.clear();
            assert_eq!(conn.drive(&frame(kind, flags, 0, b""), &mut out), None);
            assert!(out.is_empty());
        }
    }
    for flags in [0, FLAG_END_HEADERS] {
        let mut out = Vec::new();
        let mut conn = Conn::new(&mut out);
        out.clear();
        assert_eq!(
            conn.drive(&frame(CONTINUATION, flags, 1, b""), &mut out),
            None
        );
        assert!(out.is_empty());
    }
}

#[test]
fn reserved_bits_and_unknown_flags_do_not_change_continuation_identity() {
    let mut out = Vec::new();
    let mut conn = Conn::new(&mut out);
    out.clear();
    for part in [
        frame(HEADERS, 0x81, 0xffff_ffff, b"first"),
        frame(CONTINUATION, 0x80, 0x7fff_ffff, b"middle"),
        frame(CONTINUATION, 0xff, 0xffff_ffff, b"last"),
    ] {
        assert_eq!(conn.drive(&part, &mut out), Some(part.len()));
    }
    assert_eq!(out, response(0x7fff_ffff));
}

#[test]
fn dropping_an_incomplete_block_does_not_affect_a_new_connection() {
    let mut out = Vec::new();
    {
        let mut conn = Conn::new(&mut out);
        let part = frame(HEADERS, 0, 1, b"abandoned");
        assert_eq!(conn.drive(&part, &mut out), Some(part.len()));
    }
    out.clear();
    let mut conn = Conn::new(&mut out);
    out.clear();
    let whole = frame(HEADERS, FLAG_END_HEADERS, 1, b"new request");
    assert_eq!(conn.drive(&whole, &mut out), Some(whole.len()));
    assert_eq!(out, response(1));
}
