use super::*;

#[test]
fn retiring_single_streams_keeps_live_slots_in_place_and_reuses_capacity() {
    let mut conn = connection();
    conn.streams_credit.told = 8192;
    for n in 0..4096 {
        conn.stream_mut(n * 4).unwrap().size = n;
    }
    let capacity = conn.streams.capacity();
    let last = &conn.streams[4095] as *const StreamSlot;
    for n in 0..4096 {
        let req = conn.stream_mut(n * 4).unwrap();
        assert_eq!(req.size, n);
        req.fin = true;
        req.send_done = true;
        conn.complete_stream(n * 4);
        assert_eq!(conn.base_stream, n + 1);
        assert_eq!(conn.finished, n + 1);
        assert_eq!(conn.streams.capacity(), capacity);
        if n < 4095 {
            assert_eq!(conn.streams.back().unwrap() as *const StreamSlot, last);
        }
    }
    assert!(conn.streams.is_empty());
    for n in 4096..8192 {
        assert_eq!(conn.stream_mut(n * 4).unwrap().size, 0);
    }
    assert_eq!(conn.streams.capacity(), capacity);
    assert!(conn.stream_mut(4095 * 4).is_none());
    assert!(conn.stream_mut(8192 * 4).is_none());
}

#[test]
fn stream_table_matches_absolute_id_model_through_wrap_growth_and_holes() {
    for seed in [7_u64, 29, 0x9e3779b9] {
        let mut rng = seed;
        let mut conn = connection();
        conn.streams = VecDeque::with_capacity(4);
        let mut model = Vec::new();
        let mut base = 0_usize;
        let mut told = 64;
        let mut wrapped = false;
        conn.streams_credit.told = told as u64;
        for step in 0..20000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if step % 97 == 0 {
                told = told.max(base + 129);
                conn.streams_credit.told = told as u64;
            }
            let n = match step % 5 {
                0 => base,
                1 => base.saturating_sub(1),
                _ => base + rng as usize % 137,
            };
            let kind = if step % 19 == 0 { 1 } else { 0 };
            let slot = conn.stream_slot_mut(n as u64 * 4 + kind);
            if n < base || n >= told || kind != 0 {
                assert!(slot.is_none());
            } else {
                model.resize(model.len().max(n + 1), 0_u8);
                let slot = slot.unwrap();
                if step % 3 == 0 || n == base {
                    model[n] = 2;
                    *slot = StreamSlot::Complete;
                } else if model[n] == 0 {
                    model[n] = 1;
                    *slot = StreamSlot::Active(Request {
                        size: n as u64 + 1,
                        ..Request::default()
                    });
                }
            }
            while model.get(base) == Some(&2) {
                base += 1;
            }
            conn.retire();
            assert_eq!(conn.base_stream as usize, base);
            assert_eq!(conn.streams.len(), model.len() - base);
            assert_eq!(conn.streams_credit.told as usize, told);
            for (i, slot) in conn.streams.iter().enumerate() {
                match (model[base + i], slot) {
                    (0, StreamSlot::Unseen) | (2, StreamSlot::Complete) => {}
                    (1, StreamSlot::Active(req)) => assert_eq!(req.size, (base + i + 1) as u64),
                    _ => panic!("slot mismatch at step {step}, stream {}", base + i),
                }
            }
            wrapped |= !conn.streams.as_slices().1.is_empty();
        }
        assert!(wrapped, "seed {seed} did not exercise circular indexing");
        assert!(conn.streams.capacity() > 4);
        assert!(base > 1000);
    }
}

/// Complete a real prefix while retaining unfinished higher requests, then
/// open enough requests to wrap the eight-slot allocation without growing it.
fn wrapped_connection() -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.streams = VecDeque::with_capacity(8);
    conn.max_streams_bidi = 256;
    conn.streams_credit.told = 256;
    for n in 0..8 {
        conn.on_stream(n * 4, 0, b"x", n < 5).unwrap();
    }
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!((conn.finished, conn.base_stream), (5, 5));
    for n in 8..13 {
        conn.on_stream(n * 4, 0, b"x", false).unwrap();
    }
    assert_eq!(conn.streams.capacity(), 8);
    assert!(!conn.streams.as_slices().1.is_empty());
    conn
}

#[test]
fn growing_a_wrapped_table_keeps_active_requests_and_unseen_gaps() {
    let mut conn = wrapped_connection();
    conn.on_stream(20 * 4, 0, b"new", false).unwrap();
    assert!(conn.streams.capacity() > 8);
    assert_eq!(conn.streams.len(), 16);
    for n in 5..13 {
        let req = conn.stream_mut(n * 4).unwrap();
        assert_eq!(req.size, 1);
        assert!(!req.fin);
    }
    for n in 13..20 {
        assert!(matches!(
            conn.stream_slot_mut(n * 4),
            Some(StreamSlot::Unseen)
        ));
    }
    assert_eq!(conn.stream_mut(20 * 4).unwrap().size, 3);
    assert_eq!(
        (conn.finished, conn.base_stream, conn.data_seen),
        (5, 5, 16)
    );
    assert!(conn.stream_mut(4 * 4).is_none());
    assert!(conn.stream_mut(256 * 4).is_none());
}

#[test]
fn wrapped_streams_preserve_fin_reset_stop_and_duplicate_accounting() {
    let mut conn = wrapped_connection();
    for (index, n) in [5, 7, 8, 12, 6, 9, 10, 11].into_iter().enumerate() {
        let id = n * 4;
        let finished = conn.finished;
        match n % 3 {
            0 => conn.on_stream(id, 1, b"", true).unwrap(),
            1 => conn.on_reset(id, 0x10c, 1).unwrap(),
            _ => conn.stop_sending(id, 0x10c),
        }
        let (pn, plain) = send_data(&mut conn);
        if n % 3 == 0 {
            assert!(frame::Frames::new(&plain).any(|frame| matches!(frame.unwrap(),
                frame::Frame::Stream { id: stream, offset: 0, data: RESPONSE, fin: true } if stream == id)));
        } else {
            assert_reset(&plain, id, 0);
        }
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        if n % 3 == 2 {
            assert_eq!(
                conn.finished, finished,
                "reset ACK cannot imply request FIN"
            );
            assert!(conn.stream_mut(id).unwrap().send_done);
            conn.on_stream(id, 1, b"", true).unwrap();
        }
        assert_eq!(conn.finished, 6 + index as u64);
        // Old ACKs, FIN, RESET_STREAM and STOP_SENDING cannot reopen a slot.
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        conn.on_stream(id, 1, b"", true).unwrap();
        conn.on_reset(id, 0x10c, 1).unwrap();
        conn.stop_sending(id, 0x10c);
        assert_eq!(conn.finished, 6 + index as u64);
        assert_eq!(conn.data_seen, 13);
    }
    assert_eq!((conn.base_stream, conn.finished), (13, 13));
    assert!(conn.streams.is_empty());
    assert!(conn.ready.is_empty());
    assert!(conn.resets.is_empty());
    assert!(conn.timeout().is_none());
}

#[test]
fn wrapped_partial_response_survives_head_movement_credit_and_late_ack() {
    let mut conn = wrapped_connection();
    let id = 8 * 4;
    conn.stream_mut(id).unwrap().send_limit = 4;
    conn.on_stream(id, 1, b"", true).unwrap();
    let (prefix, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(prefix, prefix)]);
    assert_eq!(conn.stream_mut(id).unwrap().sent, 4);
    assert!(!conn.stream_mut(id).unwrap().send_done);
    // Retire the first physical slot while the wrapped slot awaits credit.
    conn.on_stream(5 * 4, 1, b"", true).unwrap();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.base_stream, 6);
    conn.on_frame(
        &frame::Frame::MaxStreamData {
            id,
            limit: RESPONSE.len() as u64,
        },
        Space::Data,
    )
    .unwrap();
    let (tail, plain) = send_data(&mut conn);
    assert!(frame::Frames::new(&plain).any(|frame| matches!(frame.unwrap(),
        frame::Frame::Stream { id: stream, offset: 4, data, fin: true } if stream == id && data == &RESPONSE[4..])));
    let charged = conn.send_credit.sent;
    conn.on_timeout(conn.timeout().unwrap());
    let (retry, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(tail, tail)]);
    assert_eq!(conn.finished, 7);
    assert_eq!(conn.base_stream, 6, "unfinished lower requests remain open");
    assert!(!conn.send_credit.responses.contains_key(&id));
    assert!(!conn.ready.contains(&id));
    acknowledge(&mut conn, Space::Data, &[(retry, retry)]);
    assert_eq!(conn.finished, 7);
    assert_eq!(conn.send_credit.sent, charged);
    assert!(conn.timeout().is_none());
}

#[test]
fn wrapped_full_response_keeps_original_ack_after_repeated_pto() {
    let mut conn = wrapped_connection();
    let id = 12 * 4;
    conn.on_stream(id, 1, b"", true).unwrap();
    let (original, _) = send_data(&mut conn);
    let charged = conn.send_credit.sent;
    for _ in 0..3 {
        conn.on_timeout(conn.timeout().unwrap());
        send_data(&mut conn);
    }
    conn.on_timeout(conn.timeout().unwrap());
    acknowledge(&mut conn, Space::Data, &[(original, original)]);
    assert_eq!((conn.finished, conn.base_stream), (6, 5));
    assert_eq!(conn.send_credit.sent, charged);
    assert!(conn.send_credit.responses.is_empty());
    assert!(conn.ready.is_empty());
    assert!(conn.timeout().is_none());
}
