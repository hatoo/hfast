use super::*;

fn fields(req: &Request) -> (u64, [bool; 6], [u8; 2]) {
    (
        req.size,
        [
            req.fin,
            req.answered,
            req.stopped,
            req.send_done,
            req.partial,
            req.queued,
        ],
        [req.sent, req.send_limit],
    )
}

fn settled(stream: u64, data: u64) -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.peer.initial_max_stream_data_bidi_local = stream;
    conn.peer.initial_max_data = conn.send_credit.sent + data;
    conn.send_credit.initialize(&conn.peer);
    assert!(!conn.wants_send());
    conn
}

fn grant(conn: &mut Connection, id: u64, limit: u64) {
    conn.on_frame(&frame::Frame::MaxStreamData { id, limit }, Space::Data)
        .unwrap();
}

fn responses(plain: &[u8]) -> Vec<(u64, u64, Vec<u8>, bool)> {
    frame::Frames::new(plain)
        .filter_map(|f| match f.unwrap() {
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } if id & 3 == 0 => Some((id, offset, data.to_vec(), fin)),
            _ => None,
        })
        .collect()
}

#[test]
fn grants_preserve_all_fields_and_queue_gates() {
    let mut conn = connection();
    // Exhaust every flag, blocked membership and the credit boundaries. Some
    // stale states deliberately model cancellation/recovery callers as well.
    for mask in 0..64 {
        for blocked in [false, true] {
            for (sent, old, incoming) in [
                (0, 0, 0),
                (0, 0, 1),
                (1, 1, 2),
                (3, 7, 2),
                (3, 7, 7),
                (3, 7, 8),
                (9, 7, 8),
                (25, 25, u64::MAX),
                (3, 7, u64::MAX),
            ] {
                let req = conn.stream_mut(8).unwrap();
                *req = Request {
                    size: 37,
                    fin: mask & 1 != 0,
                    answered: mask & 2 != 0,
                    stopped: mask & 4 != 0,
                    send_done: mask & 8 != 0,
                    partial: mask & 16 != 0,
                    queued: mask & 32 != 0,
                    sent,
                    send_limit: old,
                };
                let mut expected = fields(req);
                conn.ready = vec![24];
                if mask & 32 != 0 {
                    conn.ready.push(8);
                }
                let mut ready = conn.ready.clone();
                conn.send_credit.blocked.clear();
                conn.send_credit.blocked.insert(24);
                if blocked {
                    conn.send_credit.blocked.insert(8);
                }
                let capped = incoming.min(RESPONSE.len() as u64) as u8;
                expected.2[1] = old.max(capped);
                let wake = capped > old && sent < capped;
                if wake && mask & (2 | 4 | 8 | 32) == 2 {
                    expected.1[5] = true;
                    ready.push(8);
                }
                // Duplicate grants must not duplicate entries or clear a
                // blocked entry that the first grant could not wake.
                for _ in 0..3 {
                    grant(&mut conn, 8, incoming);
                    assert_eq!(
                        fields(conn.stream_mut(8).unwrap()),
                        expected,
                        "mask={mask}, sent={sent}, old={old}, incoming={incoming}"
                    );
                    assert_eq!(conn.ready, ready);
                    assert_eq!(conn.send_credit.blocked.contains(&8), blocked && !wake);
                    assert!(conn.send_credit.blocked.contains(&24));
                    assert_eq!(
                        (conn.data_seen, conn.finished, conn.send_credit.sent),
                        (0, 0, 0)
                    );
                }
            }
        }
    }
}

#[test]
fn grants_before_fin_and_for_invalid_retired_or_complete_slots() {
    let mut conn = settled(0, 4096);
    grant(&mut conn, 8, u64::MAX);
    assert_eq!(conn.streams.len(), 3);
    assert!(matches!(conn.streams[0], StreamSlot::Unseen));
    assert!(matches!(conn.streams[1], StreamSlot::Unseen));
    let req = conn.stream_mut(8).unwrap();
    assert_eq!(req.send_limit as usize, RESPONSE.len());
    assert!(!req.answered && !req.queued && !req.fin);
    conn.on_stream(8, 0, b"request", false).unwrap();
    grant(&mut conn, 8, 0);
    assert!(conn.ready.is_empty());
    conn.on_stream(8, 7, b"", true).unwrap();
    assert_eq!(conn.ready, [8]);
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(responses(&plain), [(8, 0, RESPONSE.to_vec(), true)]);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert!(matches!(conn.streams[2], StreamSlot::Complete));
    let charged = conn.send_credit.sent;
    for id in [1, 2, 7, 8, 256, u64::MAX] {
        grant(&mut conn, id, u64::MAX);
    }
    // The control stream has its own limit and must not create a request.
    grant(&mut conn, CONTROL_STREAM, u64::MAX);
    assert_eq!(conn.streams.len(), 3);
    assert!(matches!(conn.streams[0], StreamSlot::Unseen));
    assert!(matches!(conn.streams[1], StreamSlot::Unseen));
    assert!(matches!(conn.streams[2], StreamSlot::Complete));
    for id in [0, 4] {
        conn.on_stream(id, 0, b"", true).unwrap();
        grant(&mut conn, id, 25);
    }
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!((conn.base_stream, conn.finished), (3, 3));
    assert_eq!(conn.send_credit.sent, charged + 2 * RESPONSE.len() as u64);
    for id in [0, 4, 8] {
        grant(&mut conn, id, u64::MAX);
    }
    assert!(conn.streams.is_empty() && conn.ready.is_empty());
    assert_eq!(conn.data_seen, 7);
    assert!(conn.timeout().is_none());
}

#[test]
fn wrapped_sparse_grants_preserve_newest_first_order_without_duplicates() {
    let mut conn = settled(0, 4096);
    conn.streams = VecDeque::with_capacity(8);
    for n in 0..8 {
        conn.on_stream(n * 4, 0, b"x", n < 5).unwrap();
        if n < 5 {
            grant(&mut conn, n * 4, 25);
        }
    }
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.base_stream, 5);
    for n in [8, 10, 11, 12] {
        conn.on_stream(n * 4, 0, b"x", false).unwrap();
    }
    assert_eq!(conn.streams.capacity(), 8);
    assert!(!conn.streams.as_slices().1.is_empty());
    let order = [5, 12, 7, 10];
    for n in order {
        conn.on_stream(n * 4, 1, b"", true).unwrap();
    }
    let mut body = Vec::new();
    conn.write_data(&mut body, 1200, 100);
    assert!(body.is_empty());
    assert!(conn.ready.is_empty());
    for n in order {
        grant(&mut conn, n * 4, 1);
        grant(&mut conn, n * 4, 2);
        grant(&mut conn, n * 4, 2);
    }
    assert_eq!(conn.ready, order.map(|n| n * 4));
    assert!(conn.send_credit.blocked.is_empty());
    let before = conn.send_credit.sent;
    let (pn, plain) = send_data(&mut conn);
    let expected: Vec<_> = order
        .into_iter()
        .rev()
        .map(|n| (n * 4, 0, RESPONSE[..2].to_vec(), false))
        .collect();
    assert_eq!(responses(&plain), expected);
    assert_eq!(conn.send_credit.sent, before + 8);
    assert!(
        conn.send_credit.blocked.is_empty(),
        "only connection-blocked streams join this set"
    );
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert!(matches!(conn.streams[4], StreamSlot::Unseen));
    assert_eq!(conn.finished, 5);
    assert!(conn.ready.is_empty());
}

#[test]
fn small_grants_interleave_connection_credit_pto_and_late_original_ack() {
    for step in [1, 2, 13, 25] {
        let mut conn = settled(0, 0);
        conn.on_stream(0, 0, b"request", true).unwrap();
        let initial = conn.send_credit.sent;
        let mut body = Vec::new();
        conn.write_data(&mut body, 1200, 100);
        assert!(body.is_empty());
        let mut offset = 0;
        while offset < RESPONSE.len() {
            let end = (offset + step).min(RESPONSE.len());
            grant(&mut conn, 0, end as u64);
            assert_eq!(conn.ready, [0]);
            // Stream credit alone cannot spend exhausted connection credit.
            conn.write_data(&mut body, 1200, 100);
            assert!(body.is_empty());
            assert!(conn.ready.is_empty());
            assert!(conn.send_credit.blocked.contains(&0));
            conn.on_frame(&frame::Frame::MaxData(initial + end as u64), Space::Data)
                .unwrap();
            assert_eq!(conn.ready, [0]);
            grant(&mut conn, 0, end as u64);
            assert_eq!(conn.ready, [0]);
            let (original, plain) = send_data(&mut conn);
            let expected = [(
                0,
                offset as u64,
                RESPONSE[offset..end].to_vec(),
                end == RESPONSE.len(),
            )];
            assert_eq!(responses(&plain), expected);
            assert_eq!(conn.send_credit.sent, initial + end as u64);
            conn.on_timeout(conn.timeout().unwrap());
            assert_eq!(conn.ready, [0]);
            // A repeated grant while a retry is queued cannot add a second entry.
            grant(&mut conn, 0, end as u64);
            assert_eq!(conn.ready, [0]);
            let (retry, plain) = send_data(&mut conn);
            assert_eq!(responses(&plain), expected);
            assert_eq!(conn.send_credit.sent, initial + end as u64);
            acknowledge(&mut conn, Space::Data, &[(original, original)]);
            acknowledge(&mut conn, Space::Data, &[(retry, retry)]);
            assert!(conn.ready.is_empty());
            assert_eq!(
                conn.send_credit.responses.len(),
                usize::from(end != RESPONSE.len())
            );
            if end != RESPONSE.len() {
                assert_eq!(conn.finished, 0);
            }
            offset = end;
        }
        assert_eq!((conn.finished, conn.base_stream, conn.data_seen), (1, 1, 7));
        assert_eq!(conn.send_credit.sent, initial + RESPONSE.len() as u64);
        assert!(conn.streams.is_empty() && conn.ready.is_empty());
        assert!(conn.timeout().is_none());
    }
}

#[test]
fn cancellation_and_receive_reset_preserve_response_lifecycle() {
    // STOP_SENDING cancels a response. RESET_STREAM cancels only a request
    // whose receive side had not already completed; a completed reply survives.
    for mode in 0..3 {
        let mut conn = settled(1, 4096);
        conn.on_stream(0, 0, b"request", mode != 1).unwrap();
        let original = if mode != 1 {
            Some(send_data(&mut conn).0)
        } else {
            None
        };
        if mode == 0 {
            conn.stop_sending(0, 0x10c);
        } else {
            conn.on_reset(0, 0x10c, 7).unwrap();
        }
        let before = conn.send_credit.sent;
        for limit in [2, 13, u64::MAX, 1] {
            grant(&mut conn, 0, limit);
        }
        assert!(!conn.send_credit.blocked.contains(&0));
        assert_eq!(conn.ready.len(), usize::from(mode == 2));
        let (pn, plain) = send_data(&mut conn);
        let resets: Vec<_> = frame::Frames::new(&plain)
            .map(Result::unwrap)
            .filter(|f| matches!(f, frame::Frame::ResetStream { .. }))
            .collect();
        if mode == 2 {
            assert_eq!(responses(&plain), [(0, 1, RESPONSE[1..].to_vec(), true)]);
            assert!(resets.is_empty());
        } else {
            assert!(responses(&plain).is_empty());
            assert_eq!(
                resets,
                [frame::Frame::ResetStream {
                    id: 0,
                    error_code: 0x10c,
                    final_size: u64::from(mode == 0)
                }]
            );
        }
        if let Some(original) = original {
            acknowledge(&mut conn, Space::Data, &[(original, original)]);
        }
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        grant(&mut conn, 0, u64::MAX);
        assert_eq!(
            conn.send_credit.sent,
            before
                + if mode == 2 {
                    RESPONSE.len() as u64 - 1
                } else {
                    0
                }
        );
        assert_eq!((conn.finished, conn.base_stream), (1, 1));
        assert!(conn.streams.is_empty() && conn.ready.is_empty());
        assert!(conn.timeout().is_none());
    }
}
