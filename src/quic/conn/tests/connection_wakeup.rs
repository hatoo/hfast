//! Connection-credit contracts independent of the blocked-waiter representation.

use super::*;

fn grant(conn: &mut Connection, limit: u64) {
    conn.on_frame(&frame::Frame::MaxData(limit), Space::Data)
        .unwrap();
}

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

fn settled() -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.peer.initial_max_stream_data_bidi_local = RESPONSE.len() as u64;
    conn.peer.initial_max_data = conn.send_credit.sent;
    conn.send_credit.initialize(&conn.peer);
    conn
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
fn connection_grants_preserve_fields_gates_and_stale_blocked_entries() {
    let mut conn = connection();
    for mask in 0..64 {
        for blocked in [false, true] {
            for incoming in [0, 6, 7, 8, u64::MAX] {
                conn.peer.initial_max_data = 7;
                conn.send_credit.initialize(&conn.peer);
                conn.send_credit.sent = 3;
                let req = conn.stream_mut(8).unwrap();
                *req = Request {
                    size: 37,
                    fin: mask & 1 != 0,
                    answered: mask & 2 != 0,
                    stopped: mask & 4 != 0,
                    send_done: mask & 8 != 0,
                    partial: mask & 16 != 0,
                    queued: mask & 32 != 0,
                    sent: 3,
                    send_limit: 13,
                };
                let mut expected = fields(req);
                conn.ready = vec![24];
                if mask & 32 != 0 {
                    conn.ready.push(8);
                }
                let mut ready = conn.ready.clone();
                conn.send_credit.blocked.clear();
                if blocked {
                    conn.send_credit.blocked.insert(8);
                }
                let wake = incoming > 7 && blocked;
                if wake && mask & (2 | 4 | 8 | 32) == 2 {
                    expected.1[5] = true;
                    ready.push(8);
                }
                grant(&mut conn, incoming);
                assert_eq!(fields(conn.stream_mut(8).unwrap()), expected);
                assert_eq!(conn.ready, ready);
                assert_eq!(conn.send_credit.blocked.contains(&8), blocked && !wake);
                assert_eq!(conn.send_credit.available(), incoming.max(7) - 3);
                // Reblocking after a grant must survive duplicates and older grants.
                conn.send_credit.blocked.insert(8);
                for duplicate in [incoming, 0, incoming] {
                    grant(&mut conn, duplicate);
                    assert!(conn.send_credit.blocked.contains(&8));
                    assert_eq!(fields(conn.stream_mut(8).unwrap()), expected);
                    assert_eq!(conn.ready, ready);
                    assert_eq!(
                        (conn.data_seen, conn.finished, conn.send_credit.sent),
                        (0, 0, 3)
                    );
                }
            }
        }
    }
}

#[test]
fn connection_grants_enqueue_sorted_populations_after_existing_ready_entries() {
    for count in [0, 1, 16, 511, 512, 513, 1024] {
        for stride in [1, 3] {
            let mut conn = connection();
            conn.max_streams_bidi = 4096;
            conn.streams_credit.told = 4096;
            conn.peer.initial_max_data = 0;
            conn.send_credit.initialize(&conn.peer);
            for n in (0..count).rev() {
                let id = n * stride * 4;
                let req = conn.stream_mut(id).unwrap();
                req.answered = true;
                req.fin = true;
                conn.send_credit.blocked.insert(id);
            }
            let existing = 4092 * 4;
            conn.stream_mut(existing).unwrap().queued = true;
            conn.ready.push(existing);
            let expected: Vec<_> = std::iter::once(existing)
                .chain((0..count).map(|n| n * stride * 4))
                .collect();
            grant(&mut conn, 1);
            assert_eq!(conn.ready, expected);
            assert!(conn.send_credit.blocked.is_empty());
            for n in 0..count {
                assert!(conn.stream_mut(n * stride * 4).unwrap().queued);
            }
            grant(&mut conn, 1);
            grant(&mut conn, 2);
            assert_eq!(conn.ready, expected);
            assert_eq!((conn.finished, conn.send_credit.sent), (0, 0));
        }
    }
}

#[test]
fn repeated_connection_grants_preserve_bytes_fin_order_and_retirement() {
    for slots in [1, 16, 255, 256, 257, 511, 512, 513] {
        for step in [1, 2, RESPONSE.len()] {
            let mut conn = connection();
            conn.max_streams_bidi = 1 << 20;
            conn.streams_credit.told = 1 << 20;
            conn.peer.initial_max_stream_data_bidi_local = RESPONSE.len() as u64;
            conn.peer.initial_max_data = 0;
            conn.send_credit.initialize(&conn.peer);
            let mut body = Vec::new();
            for wave in 0..2 {
                let mut seen = vec![0; slots];
                // Descending arrivals exercise sparse table growth; the blocked
                // wakeup still has to choose descending IDs on the wire.
                for n in (0..slots).rev() {
                    conn.on_stream(((wave * slots + n) * 4) as u64, 0, b"request", true)
                        .unwrap();
                }
                body.clear();
                conn.write_data(&mut body, 1200, 0);
                assert!(body.is_empty() && conn.ready.is_empty());
                assert_eq!(conn.send_credit.blocked.len(), slots);
                let mut received = 0;
                while received < slots * RESPONSE.len() {
                    let amount = step.min(slots * RESPONSE.len() - received);
                    let limit = conn.send_credit.sent + amount as u64;
                    // Derive wake order from received bytes, independently of
                    // the blocked set's contents or iteration order.
                    let expected_ready: Vec<_> = seen
                        .iter()
                        .enumerate()
                        .filter(|(_, bytes)| **bytes < RESPONSE.len())
                        .map(|(n, _)| ((wave * slots + n) * 4) as u64)
                        .collect();
                    grant(&mut conn, limit);
                    assert_eq!(conn.ready, expected_ready);
                    assert!(conn.send_credit.blocked.is_empty());
                    grant(&mut conn, limit);
                    body.clear();
                    let pn = conn.spaces[Space::Data as usize].next_pn;
                    conn.write_data(&mut body, 1200, pn);
                    conn.spaces[Space::Data as usize].next_pn += 1;
                    let mut charged = 0;
                    let mut previous = usize::MAX;
                    for (id, offset, data, fin) in responses(&body) {
                        let index = id as usize / 4 - wave * slots;
                        assert!(index < previous, "newest unfinished response first");
                        previous = index;
                        assert_eq!(offset as usize, seen[index]);
                        assert_eq!(data, RESPONSE[seen[index]..seen[index] + data.len()]);
                        seen[index] += data.len();
                        assert_eq!(fin, seen[index] == RESPONSE.len());
                        charged += data.len();
                    }
                    assert_eq!(charged, amount);
                    received += amount;
                    assert_eq!(conn.send_credit.sent, limit);
                    assert!(conn.ready.is_empty());
                    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
                    assert_eq!(
                        conn.finished as usize,
                        wave * slots + seen.iter().filter(|&&n| n == RESPONSE.len()).count()
                    );
                }
                assert_eq!(seen, vec![RESPONSE.len(); slots]);
                assert_eq!(
                    (conn.finished, conn.base_stream),
                    (((wave + 1) * slots) as u64, ((wave + 1) * slots) as u64)
                );
                assert!(conn.streams.is_empty() && conn.ready.is_empty());
                assert!(
                    conn.send_credit.blocked.is_empty() && conn.send_credit.responses.is_empty()
                );
                assert_eq!(conn.data_seen, ((wave + 1) * slots * 7) as u64);
            }
        }
    }
}

#[test]
fn wrapped_sparse_connection_wakeup_keeps_existing_ready_and_stream_credit() {
    let mut conn = settled();
    conn.streams = VecDeque::with_capacity(8);
    grant(&mut conn, conn_initial() + 5 * RESPONSE.len() as u64);
    for n in 0..8 {
        conn.on_stream(n * 4, 0, b"x", n < 5).unwrap();
    }
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.base_stream, 5);
    for n in [8, 10, 11, 12] {
        conn.on_stream(n * 4, 0, b"x", false).unwrap();
    }
    assert!(!conn.streams.as_slices().1.is_empty());
    for n in [12, 5, 10] {
        conn.on_stream(n * 4, 1, b"", true).unwrap();
    }
    let mut body = Vec::new();
    conn.write_data(&mut body, 1200, 100);
    assert!(body.is_empty() && conn.ready.is_empty());
    assert_eq!(
        conn.send_credit.blocked.iter().copied().collect::<Vec<_>>(),
        [20, 40, 48]
    );
    conn.on_stream(28, 1, b"", true).unwrap(); // already ready, outside the blocked set
    conn.on_frame(
        &frame::Frame::MaxStreamData {
            id: 20,
            limit: u64::MAX,
        },
        Space::Data,
    )
    .unwrap();
    let limit = conn.send_credit.sent + 4 * RESPONSE.len() as u64;
    grant(&mut conn, limit);
    assert_eq!(conn.ready, [28, 20, 40, 48]);
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(
        responses(&plain).iter().map(|r| r.0).collect::<Vec<_>>(),
        [48, 40, 20, 28]
    );
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.finished, 9);
    assert_eq!(conn.base_stream, 6);
    assert!(conn.ready.is_empty() && conn.send_credit.blocked.is_empty());
    assert!(matches!(conn.streams[3], StreamSlot::Unseen)); // stream 9 stays a hole
}

fn conn_initial() -> u64 {
    CONTROL_PRELUDE.len() as u64
}

#[test]
fn connection_wakeup_handles_cancellation_probe_and_late_original_ack() {
    for (previous_population, mode) in [0, 513]
        .into_iter()
        .flat_map(|p| (0..3).map(move |m| (p, m)))
    {
        let mut conn = settled();
        // Exercise fresh storage and storage reused after a large population.
        for id in 0..previous_population {
            conn.send_credit.blocked.insert(id * 4);
        }
        conn.send_credit.blocked.clear();
        conn.on_stream(0, 0, b"request", mode != 1).unwrap();
        grant(&mut conn, conn_initial() + 1);
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
        let charged = conn.send_credit.sent;
        grant(&mut conn, conn_initial() + RESPONSE.len() as u64);
        grant(&mut conn, conn_initial() + RESPONSE.len() as u64);
        let (last, plain) = send_data(&mut conn);
        if mode == 2 {
            assert_eq!(responses(&plain), [(0, 1, RESPONSE[1..].to_vec(), true)]);
            conn.on_timeout(conn.timeout().unwrap());
            let (retry, plain) = send_data(&mut conn);
            assert_eq!(
                responses(&plain),
                [
                    (0, 0, RESPONSE[..1].to_vec(), false),
                    (0, 1, RESPONSE[1..].to_vec(), true)
                ]
            );
            assert_eq!(
                conn.send_credit.sent,
                conn_initial() + RESPONSE.len() as u64
            );
            acknowledge(
                &mut conn,
                Space::Data,
                &[(original.unwrap(), original.unwrap())],
            );
            assert_eq!(conn.finished, 0);
            acknowledge(&mut conn, Space::Data, &[(last, last)]);
            acknowledge(&mut conn, Space::Data, &[(retry, retry)]);
        } else {
            assert!(responses(&plain).is_empty());
            assert_eq!(conn.send_credit.sent, charged);
            assert!(frame::Frames::new(&plain).map(Result::unwrap).any(|f| matches!(f, frame::Frame::ResetStream { id: 0, error_code: 0x10c, final_size } if final_size == charged - conn_initial())));
            acknowledge(&mut conn, Space::Data, &[(last, last)]);
            if let Some(pn) = original {
                acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
            }
        }
        assert_eq!((conn.finished, conn.base_stream, conn.data_seen), (1, 1, 7));
        assert!(
            conn.streams.is_empty() && conn.ready.is_empty() && conn.send_credit.blocked.is_empty()
        );
        assert!(conn.send_credit.responses.is_empty());
        assert!(conn.timeout().is_none());
    }
}
