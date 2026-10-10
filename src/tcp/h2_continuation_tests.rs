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

fn request() -> Vec<u8> {
    [
        h2::PREFACE.to_vec(),
        frame(4, 0, 0, b""),
        frame(1, 0, 1, b"start"),
        frame(9, 0, 1, b""),
        frame(9, 4, 1, b"finish"),
        frame(0, 1, 1, b"request body"),
        frame(1, 1, 3, b"another"),
        frame(9, 4, 3, b""),
    ]
    .concat()
}

fn expected() -> Vec<u8> {
    let mut out = frame(
        4,
        0,
        0,
        &[0, 3, 0x7f, 0xff, 0xff, 0xff, 0, 4, 0x7f, 0xff, 0xff, 0xff],
    );
    out.extend_from_slice(&frame(4, 1, 0, b""));
    for stream in [1, 3] {
        out.extend_from_slice(&frame(
            1,
            4,
            stream,
            b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33",
        ));
        out.extend_from_slice(&frame(0, 1, stream, b"Hello, World!"));
    }
    out
}

#[test]
fn consume_handles_every_preface_and_continuation_split() {
    let input = request();
    let expected = expected();
    for split in 0..=input.len() {
        let mut conn = Conn::new();
        assert!(consume(&mut conn, &input[..split]));
        assert!(consume(&mut conn, &input[split..]));
        assert!(conn.inbuf.is_empty());
        assert_eq!(conn.outbuf, expected, "split {split}");
    }
    for chunk in 1..=input.len() {
        let mut conn = Conn::new();
        for part in input.chunks(chunk) {
            assert!(consume(&mut conn, part));
        }
        assert!(conn.inbuf.is_empty());
        assert_eq!(conn.outbuf, expected, "chunk {chunk}");
    }
}

#[test]
fn consume_closes_on_interleaving_even_with_carried_input() {
    for invalid in [frame(9, 4, 3, b"wrong stream"), frame(6, 0, 0, b"12345678")] {
        for split in 0..invalid.len() {
            let mut conn = Conn::new();
            assert!(consume(&mut conn, h2::PREFACE));
            assert!(consume(&mut conn, &frame(1, 0, 1, b"pending")));
            conn.outbuf.clear();
            assert!(consume(&mut conn, &invalid[..split]));
            assert!(!consume(&mut conn, &invalid[split..]));
            assert!(conn.outbuf.is_empty());
        }
    }
}

#[test]
fn credit_error_preserves_queued_output_until_tcp_finishes_writing() {
    let input = [
        h2::PREFACE.to_vec(),
        frame(4, 0, 0, &[0, 4, 0, 0, 0, 0]),
        frame(1, 5, 1, b"request"),
        frame(8, 0, 1, &[0, 0, 0, 5]),
        frame(8, 0, 0, &[0, 0, 0, 0]),
        frame(1, 5, 3, b"ignored after GOAWAY"),
    ]
    .concat();
    for chunk in 1..=input.len() {
        let mut conn = Conn::new();
        for part in input.chunks(chunk) {
            assert!(consume(&mut conn, part));
        }
        assert!(conn.inbuf.is_empty());
        assert!(matches!(&conn.proto, Proto::H2(h2) if h2.is_closing()));
        let suffix = [
            frame(1, 4, 1, b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33"),
            frame(0, 0, 1, b"Hello"),
            frame(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 1]),
        ]
        .concat();
        assert!(conn.outbuf.ends_with(&suffix));
        let saved = conn.outbuf.clone();
        conn.out_off = saved.len() - 3; // The last send wrote only part of GOAWAY.
        assert!(consume(&mut conn, &frame(8, 0, 1, &[0, 0, 0, 8])));
        assert_eq!(conn.outbuf, saved);
        assert_eq!(conn.out_off, saved.len() - 3);
    }
}
