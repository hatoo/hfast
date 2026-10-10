use super::*;

fn frame(kind: u8, flags: u8, stream: u32, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut wire = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(body);
    wire
}

fn request(stream: u32) -> Vec<u8> {
    frame(1, 5, stream, b"\x82\x86\x84")
}

fn setting(window: u32) -> Vec<u8> {
    frame(4, 0, 0, &[&[0, 4][..], &window.to_be_bytes()].concat())
}

fn credit(stream: u32, n: u32) -> Vec<u8> {
    frame(8, 0, stream, &n.to_be_bytes())
}

fn deliver(conn: &mut Conn, wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    assert_eq!(conn.drive(wire, &mut out), Some(wire.len()));
    out
}

fn fresh(window: u32) -> Conn {
    let mut conn = Conn::new(&mut Vec::new());
    assert_eq!(deliver(&mut conn, &setting(window)), frame(4, 1, 0, b""));
    conn
}

fn response_headers(stream: u32) -> Vec<u8> {
    frame(
        1,
        4,
        stream,
        b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33",
    )
}

fn goaway(stream: u32, error: u32) -> Vec<u8> {
    frame(
        7,
        0,
        0,
        &[stream.to_be_bytes(), error.to_be_bytes()].concat(),
    )
}

#[test]
fn zero_window_and_partial_grants_preserve_every_body_byte_and_fin() {
    let mut conn = fresh(0);
    assert_eq!(deliver(&mut conn, &request(1)), response_headers(1));
    assert_eq!(deliver(&mut conn, &credit(1, 1)), frame(0, 0, 1, b"H"));
    assert_eq!(
        deliver(&mut conn, &credit(1, 12)),
        frame(0, 1, 1, b"ello, World!")
    );
    assert!(conn.pending.is_empty());
    assert_eq!(conn.send_window, 65535 - 13);
    assert!(deliver(&mut conn, &credit(1, 1)).is_empty());
}

#[test]
fn exact_connection_boundary_and_fifo_resume_without_head_of_line_blocking() {
    let mut conn = fresh(65535);
    for stream in (1..=10081).step_by(2) {
        assert_eq!(
            deliver(&mut conn, &request(stream)),
            [
                response_headers(stream),
                frame(0, 1, stream, b"Hello, World!")
            ]
            .concat()
        );
    }
    assert_eq!(conn.send_window, 2);
    assert_eq!(
        deliver(&mut conn, &request(10083)),
        [response_headers(10083), frame(0, 0, 10083, b"He")].concat()
    );
    assert_eq!(deliver(&mut conn, &request(10085)), response_headers(10085));
    assert_eq!(deliver(&mut conn, &setting(0)), frame(4, 1, 0, b""));
    assert_eq!(deliver(&mut conn, &credit(0, 20)), b"");
    // The first pending stream is negative; the second must still progress.
    assert_eq!(
        deliver(&mut conn, &credit(10085, 13)),
        frame(0, 1, 10085, b"Hello, World!")
    );
    assert_eq!(conn.send_window, 7);
    assert_eq!(
        deliver(&mut conn, &credit(10083, 13)),
        frame(0, 0, 10083, b"llo, Wo")
    );
    assert_eq!(
        deliver(&mut conn, &credit(0, 4)),
        frame(0, 1, 10083, b"rld!")
    );
    assert!(conn.pending.is_empty());
}

#[test]
fn settings_reduction_retains_negative_credit_until_fully_repaid() {
    let mut conn = fresh(5);
    assert_eq!(
        deliver(&mut conn, &request(1)),
        [response_headers(1), frame(0, 0, 1, b"Hello")].concat()
    );
    deliver(&mut conn, &setting(0));
    assert_eq!(conn.pending[0].window, -5);
    assert!(deliver(&mut conn, &credit(1, 4)).is_empty());
    assert!(deliver(&mut conn, &credit(1, 1)).is_empty());
    assert_eq!(
        deliver(&mut conn, &credit(1, 8)),
        frame(0, 1, 1, b", World!")
    );
}

#[test]
fn settings_increases_wake_all_eligible_streams_and_apply_duplicates_in_order() {
    let mut conn = fresh(0);
    deliver(&mut conn, &request(1));
    deliver(&mut conn, &request(3));
    let duplicate = frame(4, 0, 0, &[0, 4, 0, 0, 0, 7, 0, 4, 0, 0, 0, 13]);
    assert_eq!(
        deliver(&mut conn, &duplicate),
        [
            frame(4, 1, 0, b""),
            frame(0, 1, 1, b"Hello, World!"),
            frame(0, 1, 3, b"Hello, World!")
        ]
        .concat()
    );
    assert_eq!(conn.send_window, 65535 - 26);
    assert!(conn.pending.is_empty());
}

#[test]
fn settings_never_replenish_the_connection_window() {
    let mut conn = fresh(0);
    conn.send_window = 0;
    deliver(&mut conn, &request(1));
    assert_eq!(deliver(&mut conn, &setting(65535)), frame(4, 1, 0, b""));
    assert_eq!(
        deliver(&mut conn, &credit(0, 13)),
        frame(0, 1, 1, b"Hello, World!")
    );
}

#[test]
fn reset_removes_only_its_unsent_suffix_and_never_refunds_sent_data() {
    let mut conn = fresh(5);
    deliver(&mut conn, &request(1));
    deliver(&mut conn, &request(3));
    assert!(deliver(&mut conn, &frame(3, 0, 1, &[0; 4])).is_empty());
    assert_eq!(conn.send_window, 65525);
    assert!(deliver(&mut conn, &credit(1, 100)).is_empty());
    assert_eq!(
        deliver(&mut conn, &credit(3, 8)),
        frame(0, 1, 3, b", World!")
    );
    assert!(conn.pending.is_empty());
}

#[test]
fn trailers_do_not_create_a_second_response_or_reset_credit() {
    let mut conn = fresh(0);
    deliver(&mut conn, &request(1));
    deliver(&mut conn, &request(3));
    assert!(deliver(&mut conn, &frame(1, 1, 1, b"trailer")).is_empty());
    assert!(deliver(&mut conn, &frame(9, 4, 1, b"last")).is_empty());
    assert_eq!(conn.pending.len(), 2);
    assert_eq!(
        deliver(&mut conn, &credit(1, 13)),
        frame(0, 1, 1, b"Hello, World!")
    );
    assert!(deliver(&mut conn, &request(1)).is_empty());
}

#[test]
fn ordinary_responses_never_allocate_pending_state() {
    let mut conn = fresh(65535);
    for stream in (1..200).step_by(2) {
        let wire = deliver(&mut conn, &request(stream));
        assert_eq!(
            wire,
            [
                response_headers(stream),
                frame(0, 1, stream, b"Hello, World!")
            ]
            .concat()
        );
    }
    assert_eq!(conn.pending.capacity(), 0);
    assert_eq!(conn.send_window, 65535 - 1300);
}

#[test]
fn zero_and_overflowing_stream_updates_reset_only_the_affected_stream() {
    for (initial, first, increment, error) in [(0, 0, 0, 1_u32), (65535, MAX_WINDOW - 65535, 1, 3)]
    {
        let mut conn = fresh(initial);
        conn.send_window = 0;
        deliver(&mut conn, &request(1));
        deliver(&mut conn, &request(3));
        if first != 0 {
            deliver(&mut conn, &credit(1, first));
        }
        assert_eq!(
            deliver(&mut conn, &credit(1, increment)),
            frame(3, 0, 1, &error.to_be_bytes())
        );
        assert!(!conn.is_closing());
        assert_eq!(conn.pending.len(), 1);
        assert_eq!(conn.pending[0].stream, 3);
        deliver(&mut conn, &setting(13));
        assert_eq!(
            deliver(&mut conn, &credit(0, 13)),
            frame(0, 1, 3, b"Hello, World!")
        );
    }
}

#[test]
fn connection_errors_send_one_goaway_and_ignore_later_requests() {
    let invalid = [
        (credit(0, 0), 1),
        (credit(0, MAX_WINDOW), 3),
        (credit(1, 1), 1),
        (frame(3, 0, 0, &[0; 4]), 1),
        (frame(3, 0, 1, &[0; 4]), 1),
        (frame(8, 0, 0, &[0; 3]), 6),
        (frame(8, 0, 1, &[0; 5]), 6),
        (frame(3, 0, 1, &[0; 5]), 6),
        (frame(4, 0, 1, b""), 1),
        (frame(4, 0, 0, &[0; 5]), 6),
        (frame(4, 1, 0, &[0; 6]), 6),
        (setting(MAX_WINDOW + 1), 3),
        (frame(4, 0, 0, &[0, 2, 0, 0, 0, 2]), 1),
        (frame(4, 0, 0, &[0, 5, 0, 0, 0, 1]), 1),
    ];
    for (wire, error) in invalid {
        let mut conn = fresh(65535);
        assert_eq!(deliver(&mut conn, &wire), goaway(0, error));
        assert!(conn.is_closing());
        assert!(deliver(&mut conn, &request(1)).is_empty());
    }
}

#[test]
fn settings_window_overflow_is_a_connection_error_even_before_a_later_reduction() {
    let mut conn = fresh(0);
    conn.send_window = 0;
    deliver(&mut conn, &request(1));
    deliver(&mut conn, &credit(1, MAX_WINDOW));
    let duplicate = frame(4, 0, 0, &[0, 4, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0]);
    assert_eq!(deliver(&mut conn, &duplicate), goaway(1, 3));
    assert!(conn.pending.is_empty());
}

#[test]
fn reserved_credit_bit_and_unknown_settings_are_ignored() {
    let mut conn = fresh(0);
    deliver(&mut conn, &request(1));
    assert_eq!(
        deliver(&mut conn, &credit(1, 0x8000000d)),
        frame(0, 1, 1, b"Hello, World!")
    );
    assert_eq!(
        deliver(&mut conn, &frame(4, 0, 0, &[99, 99, 255, 255, 255, 255])),
        frame(4, 1, 0, b"")
    );
}

#[test]
fn every_receive_split_preserves_credit_headers_continuations_and_body() {
    let wire = [
        setting(0),
        frame(1, 1, 1, b"start"),
        frame(9, 4, 1, b"end"),
        credit(1, 1),
        credit(1, 12),
        frame(6, 0, 0, b"12345678"),
    ]
    .concat();
    let expected = [
        frame(4, 1, 0, b""),
        response_headers(1),
        frame(0, 0, 1, b"H"),
        frame(0, 1, 1, b"ello, World!"),
        frame(6, 1, 0, b"12345678"),
    ]
    .concat();
    for chunk in 1..=wire.len() {
        let mut conn = Conn::new(&mut Vec::new());
        let mut out = Vec::new();
        let mut carry = Vec::new();
        for part in wire.chunks(chunk) {
            carry.extend_from_slice(part);
            let n = conn.drive(&carry, &mut out).unwrap();
            carry.drain(..n);
        }
        assert!(carry.is_empty());
        assert_eq!(out, expected, "chunk {chunk}");
        assert!(conn.pending.is_empty());
    }
}
