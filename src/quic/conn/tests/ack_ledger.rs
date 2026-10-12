use super::*;

fn append(conn: &mut Connection, pn: u64, id: u64) {
    *conn.stream_mut(id).unwrap() = Request {
        fin: true,
        answered: true,
        sent: RESPONSE.len() as u8,
        ..Request::default()
    };
    conn.unacked.push_back((pn, id));
}

fn ack(conn: &mut Connection, ranges: &[(u64, u64)]) -> bool {
    let mut body = Vec::new();
    frame::put_ack(&mut body, ranges, 0);
    let frame::Frame::Ack {
        largest,
        first_range,
        rest,
        ..
    } = frame::Frames::new(&body).next().unwrap().unwrap()
    else {
        panic!("expected ACK")
    };
    conn.on_ack(largest, first_range, rest)
}

#[test]
fn ascending_acks_leave_newer_responses_in_place() {
    for group in [1_usize, 16] {
        let mut conn = connection();
        conn.streams_credit.told = 4096;
        for n in 0..4096 {
            append(&mut conn, 100 + n / group as u64, n * 4);
        }
        let capacity = conn.unacked.capacity();
        let last = &conn.unacked[4095] as *const (u64, u64);
        for packet in 0..4096 / group {
            let pn = 100 + packet as u64;
            assert!(conn.on_ack(pn, pn, &[]));
            assert_eq!(conn.unacked.len(), 4096 - (packet + 1) * group);
            if let Some(entry) = conn.unacked.back() {
                assert_eq!(entry as *const (u64, u64), last);
            }
            assert_eq!(conn.unacked.capacity(), capacity);
            assert_eq!(conn.finished as usize, (packet + 1) * group);
            assert!(!conn.on_ack(pn, pn, &[]), "duplicate ACK made progress");
            assert!(conn.ready.is_empty());
            assert!(conn.send_credit.responses.is_empty());
        }
        assert!(conn.streams.is_empty());
    }
}

#[test]
fn sparse_ack_keeps_boundary_groups_and_wrapped_suffix() {
    let mut conn = connection();
    conn.unacked = VecDeque::with_capacity(16);
    for n in 0..12 {
        append(&mut conn, 100 + n, n * 4);
    }
    assert!(conn.on_ack(105, 5, &[]));
    for n in 12..20 {
        append(&mut conn, 109 + n / 4, n * 4);
    }
    assert_eq!(conn.unacked.capacity(), 16);
    assert!(!conn.unacked.as_slices().1.is_empty());
    let last = conn.unacked.back().unwrap() as *const (u64, u64);
    assert!(ack(&mut conn, &[(109, 109), (107, 107)]));
    assert_eq!(conn.finished, 8);
    assert_eq!(conn.unacked.front(), Some(&(106, 24))); // exactly largest - 3
    assert!(conn.ready.is_empty());
    assert_eq!(conn.unacked.back().unwrap() as *const (u64, u64), last);
    assert!(conn.on_ack(112, 0, &[]));
    assert_eq!(conn.finished, 12); // every response in packet 112
    assert_eq!(conn.ready, [24, 32]); // 106 and 108, in original order
    assert_eq!(
        conn.unacked.iter().copied().collect::<Vec<_>>(),
        [
            (110, 40),
            (111, 44),
            (113, 64),
            (113, 68),
            (113, 72),
            (113, 76)
        ]
    );
    assert_eq!(conn.unacked.back().unwrap() as *const (u64, u64), last);
    // A reversed ACK can still acknowledge a sparse survivor.
    assert!(conn.on_ack(110, 0, &[]));
    assert_eq!(conn.finished, 13);
    assert_eq!(conn.ready, [24, 32]);
}

#[test]
fn ack_classification_matches_full_scan_model() {
    // The model uses sets of delivered PNs and a flat vector, independently of
    // the prefix stopping/compaction and circular storage under test.
    for seed in [1_u64, 0xa731, 0x9e3779b97f4a7c15] {
        let mut conn = connection();
        conn.streams_credit.told = 20000;
        let mut model = Vec::new();
        let mut ready = Vec::new();
        let mut finished = 0;
        let mut pn = 100;
        let mut next_id = 0;
        let mut rng = seed;
        for step in 0..2000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            pn += 1 + rng % 3;
            let count = 1 + (rng >> 16) % 5;
            for id in (next_id..next_id + count).rev().map(|n| n * 4) {
                append(&mut conn, pn, id);
                model.push((pn, id));
            }
            next_id += count;
            if step % 11 == 0 && !model.is_empty() {
                let id = model[model.len() / 2].1;
                conn.stop_sending(id, 0x10c);
                model.retain(|&(_, stream)| stream != id);
                ready.retain(|&stream| stream != id);
            }
            let largest = pn.saturating_sub((rng >> 32) % 20);
            let ranges = if step % 3 == 0 {
                vec![(largest - 2, largest), (largest - 7, largest - 5)]
            } else {
                vec![(largest, largest)]
            };
            let mut delivered = false;
            model.retain(|&(number, id)| {
                if ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&number)) {
                    finished += 1;
                    delivered = true;
                    false
                } else if number < largest.saturating_sub(3) {
                    ready.push(id);
                    false
                } else {
                    true
                }
            });
            assert_eq!(
                ack(&mut conn, &ranges),
                delivered,
                "seed {seed}, step {step}"
            );
            assert_eq!(conn.unacked.iter().copied().collect::<Vec<_>>(), model);
            assert_eq!(conn.finished, finished);
            assert_eq!(conn.ready, ready);
            assert_eq!(conn.send_credit.responses.len(), ready.len());
        }
        for id in ready {
            let req = conn.stream_mut(id).unwrap();
            assert!(req.partial && req.queued && !req.send_done);
        }
    }
}

#[test]
fn loss_boundary_handles_zero_and_maximum_packet_numbers() {
    for base in [0, (1_u64 << 62) - 8, u64::MAX - 7] {
        let mut conn = connection();
        for n in 0..8 {
            append(&mut conn, base + n, n * 4);
        }
        assert!(conn.on_ack(base + 3, 0, &[]));
        assert!(conn.ready.is_empty(), "strict loss boundary changed");
        assert!(conn.on_ack(base + 4, 0, &[]));
        assert_eq!(conn.ready, [0]);
        assert_eq!(
            conn.unacked.iter().map(|&(pn, _)| pn).collect::<Vec<_>>(),
            [base + 1, base + 2, base + 5, base + 6, base + 7]
        );
        assert!(conn.on_ack(base + 1, 0, &[]));
        assert_eq!(conn.finished, 3);
    }
}

#[test]
fn wrapped_ledger_preserves_stop_reset_and_late_original_acks_after_pto() {
    let mut conn = data_connection();
    let (control, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(control, control)]);
    conn.unacked = VecDeque::with_capacity(16);
    let mut packets = Vec::new();
    for n in 0..12 {
        conn.on_stream(n * 4, 0, b"request", true).unwrap();
        packets.push(send_data(&mut conn).0);
    }
    acknowledge(&mut conn, Space::Data, &[(packets[0], packets[5])]);
    for n in 12..20 {
        conn.on_stream(n * 4, 0, b"request", true).unwrap();
        packets.push(send_data(&mut conn).0);
    }
    assert!(!conn.unacked.as_slices().1.is_empty());
    conn.stop_sending(10 * 4, 0x10c);
    acknowledge(&mut conn, Space::Data, &[(packets[10], packets[10])]);
    assert_eq!(conn.finished, 6, "old response ACK cannot finish a reset");
    let (reset, plain) = send_data(&mut conn);
    assert_reset(&plain, 40, RESPONSE.len() as u64);
    let charged = conn.send_credit.sent;
    conn.on_timeout(conn.timeout().unwrap());
    assert!(conn.unacked.is_empty());
    assert!(!conn.send_credit.responses.is_empty());
    acknowledge(&mut conn, Space::Data, &[(packets[6], packets[19])]);
    assert_eq!(conn.finished, 19);
    assert!(conn.send_credit.responses.is_empty());
    assert!(conn.ready.is_empty());
    acknowledge(&mut conn, Space::Data, &[(reset, reset)]);
    assert_eq!(conn.finished, 20);
    assert!(conn.streams.is_empty());
    assert_eq!(conn.send_credit.sent, charged);
    acknowledge(&mut conn, Space::Data, &[(packets[0], reset)]);
    assert_eq!(conn.finished, 20);
    assert!(conn.timeout().is_none());
}
