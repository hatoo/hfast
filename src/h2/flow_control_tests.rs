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

#[test]
fn blocked_responses_complete_in_order_reverse_and_permuted_with_cancellations() {
    for order in 0..3 {
        let mut conn = fresh(0);
        let count = 4096_u32;
        for stream in (1..2 * count).step_by(2) {
            assert_eq!(
                deliver(&mut conn, &request(stream)),
                response_headers(stream)
            );
        }
        let mut completed = 0;
        for i in 0..count {
            let index = match order {
                0 => i,
                1 => count - 1 - i,
                _ => (i * 4051 + 17) % count,
            };
            let stream = 2 * index + 1;
            if i % 4 == 0 {
                assert!(deliver(&mut conn, &frame(3, 0, stream, &[0; 4])).is_empty());
            } else {
                assert_eq!(
                    deliver(&mut conn, &credit(stream, 13)),
                    frame(0, 1, stream, BODY)
                );
                completed += 1;
            }
            // Neither a late update nor a duplicate reset may revive a stream.
            assert!(deliver(&mut conn, &credit(stream, 13)).is_empty());
            assert!(deliver(&mut conn, &frame(3, 0, stream, &[0; 4])).is_empty());
            assert_eq!(conn.pending.len(), (count - i - 1) as usize);
        }
        assert!(conn.pending.is_empty());
        assert_eq!(conn.send_window, INITIAL_WINDOW - 13 * completed);
    }
}

#[test]
fn repeated_retire_and_refill_reuses_bounded_capacity_and_survives_wrapped_growth() {
    let mut conn = fresh(0);
    let mut next = 1;
    for _ in 0..128 {
        deliver(&mut conn, &request(next));
        next += 2;
    }
    let capacity = conn.pending.capacity();
    let mut first = 1;
    for _ in 0..32 {
        for _ in 0..96 {
            assert_eq!(
                deliver(&mut conn, &credit(first, 13)),
                frame(0, 1, first, BODY)
            );
            first += 2;
        }
        for _ in 0..96 {
            assert_eq!(deliver(&mut conn, &request(next)), response_headers(next));
            next += 2;
        }
        assert_eq!(conn.pending.len(), 128);
        assert_eq!(conn.pending.capacity(), capacity);
        assert_eq!(
            conn.pending.iter().map(|p| p.stream).collect::<Vec<_>>(),
            (first..next).step_by(2).collect::<Vec<_>>()
        );
    }
    // Force a wrapped full queue, then grow it without losing logical order.
    assert_eq!(
        deliver(&mut conn, &credit(first, 13)),
        frame(0, 1, first, BODY)
    );
    first += 2;
    deliver(&mut conn, &request(next));
    next += 2;
    assert!(!conn.pending.as_slices().1.is_empty());
    for _ in 0..capacity {
        deliver(&mut conn, &request(next));
        next += 2;
    }
    let expected = std::iter::once(frame(4, 1, 0, b""))
        .chain(
            (first..next)
                .step_by(2)
                .map(|stream| frame(0, 1, stream, BODY)),
        )
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(deliver(&mut conn, &setting(13)), expected);
    assert!(conn.pending.is_empty());
    assert_eq!(conn.send_window, INITIAL_WINDOW - (next - 1) / 2 * 13);
}

#[test]
fn trickle_connection_grants_preserve_partial_bodies_across_queue_wraps() {
    for grant in [1, 12, 13, 14] {
        let mut conn = fresh(13);
        conn.send_window = 0;
        let mut next = 1;
        for _ in 0..128 {
            assert_eq!(deliver(&mut conn, &request(next)), response_headers(next));
            next += 2;
        }
        let capacity = conn.pending.capacity();
        let mut sent = 0_usize;
        let mut wrapped = false;
        for _ in 0..32 {
            let end = sent + 65 * BODY.len();
            while sent < end {
                let amount = grant.min(end - sent);
                let mut expected = Vec::new();
                let stop = sent + amount;
                while sent < stop {
                    let stream = (sent / BODY.len()) as u32 * 2 + 1;
                    let offset = sent % BODY.len();
                    let count = (BODY.len() - offset).min(stop - sent);
                    expected.extend(frame(
                        DATA,
                        u8::from(offset + count == BODY.len()),
                        stream,
                        &BODY[offset..offset + count],
                    ));
                    sent += count;
                }
                assert_eq!(deliver(&mut conn, &credit(0, amount as u32)), expected);
                assert_eq!(conn.send_window, 0);
            }
            for _ in 0..65 {
                assert_eq!(deliver(&mut conn, &request(next)), response_headers(next));
                next += 2;
            }
            assert_eq!(conn.pending.len(), 128);
            assert_eq!(conn.pending.capacity(), capacity);
            wrapped |= !conn.pending.as_slices().1.is_empty();
        }
        assert!(wrapped);
        let first = (sent / BODY.len()) as u32 * 2 + 1;
        let expected = (first..next)
            .step_by(2)
            .flat_map(|stream| frame(DATA, 1, stream, BODY))
            .collect::<Vec<_>>();
        assert_eq!(deliver(&mut conn, &credit(0, 128 * 13)), expected);
        assert!(conn.pending.is_empty());
        assert_eq!(conn.send_window, 0);
    }
}

#[test]
fn connection_resume_passes_partial_and_negative_heads_without_refunding_resets() {
    let mut conn = fresh(5);
    conn.send_window = 0;
    for stream in [1, 3, 5, 7, 9] {
        assert_eq!(
            deliver(&mut conn, &request(stream)),
            response_headers(stream)
        );
    }
    // The front consumes its five stream bytes; the fallback uses the final
    // two connection bytes on the next stream in the same resume call.
    assert_eq!(
        deliver(&mut conn, &credit(0, 7)),
        [frame(DATA, 0, 1, b"Hello"), frame(DATA, 0, 3, b"He")].concat()
    );
    deliver(&mut conn, &setting(0));
    assert_eq!(conn.pending[0].window, -5);
    assert_eq!(conn.pending[1].window, -2);
    assert!(deliver(&mut conn, &credit(3, 15)).is_empty());
    assert!(deliver(&mut conn, &credit(7, 13)).is_empty());
    assert_eq!(
        deliver(&mut conn, &credit(0, 14)),
        [frame(DATA, 1, 3, b"llo, World!"), frame(DATA, 0, 7, b"Hel")].concat()
    );
    assert_eq!(
        deliver(&mut conn, &credit(0, 30)),
        frame(DATA, 1, 7, b"lo, World!")
    );
    assert_eq!(conn.send_window, 20);
    assert!(deliver(&mut conn, &frame(RST_STREAM, 0, 1, &[0; 4])).is_empty());
    assert_eq!(conn.send_window, 20);
    assert_eq!(
        deliver(&mut conn, &setting(13)),
        [
            frame(SETTINGS, 1, 0, b""),
            frame(DATA, 1, 5, BODY),
            frame(DATA, 0, 9, b"Hello, ")
        ]
        .concat()
    );
    assert_eq!(conn.send_window, 0);
    assert_eq!(
        deliver(&mut conn, &credit(0, 6)),
        frame(DATA, 1, 9, b"World!")
    );
    assert!(conn.pending.is_empty());
    assert!(deliver(&mut conn, &credit(1, 13)).is_empty());
}

#[test]
fn wrapped_pending_queue_matches_credit_model_through_mixed_events() {
    use std::collections::BTreeMap;
    // Wider signed windows and an ordered map provide a storage-independent
    // model, including partially sent responses with negative stream credit.
    let mut model = BTreeMap::<u32, (i64, usize)>::new();
    let mut conn = fresh(0);
    let mut window = i64::from(INITIAL_WINDOW);
    let mut initial = 0_i64;
    let mut next = 1;
    for _ in 0..128 {
        deliver(&mut conn, &request(next));
        model.insert(next, (0, 0));
        next += 2;
    }
    for stream in (1..161).step_by(2) {
        assert_eq!(
            deliver(&mut conn, &credit(stream, 13)),
            frame(0, 1, stream, BODY)
        );
        model.remove(&stream);
        window -= 13;
    }
    for _ in 0..80 {
        deliver(&mut conn, &request(next));
        model.insert(next, (0, 0));
        next += 2;
    }
    assert!(!conn.pending.as_slices().1.is_empty());
    // Keep connection credit scarce so stream and SETTINGS grants must wait
    // for later connection updates, including partial final bodies.
    conn.send_window = 17;
    window = 17;
    let mut random = 0x59b3_7d91_u64;
    for step in 0..8192 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let stream = (random as u32 % ((next - 1) / 2)) * 2 + 1;
        let amount = (random >> 32) as u32 % 19 + 1;
        let mut eligible = Vec::new();
        let mut expected = Vec::new();
        let wire = match step % 11 {
            0..=2 => {
                let stream = next;
                next += 2;
                model.insert(stream, (initial, 0));
                expected.extend(response_headers(stream));
                eligible.push(stream);
                request(stream)
            }
            3 | 4 | 8 => {
                if let Some((credit, _)) = model.get_mut(&stream) {
                    *credit += i64::from(amount);
                    eligible.push(stream);
                }
                credit(stream, amount)
            }
            5 => {
                model.remove(&stream);
                frame(3, 0, stream, &[0; 4])
            }
            6 | 9 => {
                let changed = i64::from(amount % 14);
                for (credit, _) in model.values_mut() {
                    *credit += changed - initial;
                }
                initial = changed;
                eligible.extend(model.keys().copied());
                expected.extend(frame(4, 1, 0, b""));
                setting(initial as u32)
            }
            7 => {
                window += i64::from(amount);
                eligible.extend(model.keys().copied());
                credit(0, amount)
            }
            _ => {
                // A zero stream grant resets only an unfinished response.
                if model.remove(&stream).is_some() {
                    expected.extend(frame(3, 0, stream, &PROTOCOL_ERROR.to_be_bytes()));
                }
                credit(stream, 0)
            }
        };
        for stream in eligible {
            let (credit, sent) = model.get_mut(&stream).unwrap();
            let bytes = (*credit).min(window).max(0).min((13 - *sent) as i64) as usize;
            if bytes != 0 {
                expected.extend(frame(
                    0,
                    u8::from(*sent + bytes == 13),
                    stream,
                    &BODY[*sent..*sent + bytes],
                ));
                *sent += bytes;
                *credit -= bytes as i64;
                window -= bytes as i64;
            }
            if *sent == 13 {
                model.remove(&stream);
            }
        }
        assert_eq!(deliver(&mut conn, &wire), expected, "step {step}");
        assert_eq!(i64::from(conn.send_window), window);
        assert_eq!(i64::from(conn.initial_window), initial);
        assert_eq!(
            conn.pending
                .iter()
                .map(|p| (p.stream, (i64::from(p.window), usize::from(p.sent))))
                .collect::<BTreeMap<_, _>>(),
            model,
            "step {step}"
        );
    }
}
