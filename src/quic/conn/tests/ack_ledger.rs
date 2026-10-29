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

#[test]
fn many_ranges_match_full_scan_with_packet_groups_and_gaps() {
    for count in [1_u64, 8, 64, 256] {
        for group in [1_u64, 4] {
            for seed in [1_u64, 0xa731, 0x9e3779b97f4a7c15] {
                let mut conn = connection();
                conn.streams_credit.told = 20000;
                let mut rng = seed;
                let mut ranges = Vec::new();
                let mut lo = 10;
                for _ in 0..count {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    let hi = lo + rng % 7;
                    ranges.push((lo, hi));
                    lo = hi + 2 + (rng >> 16) % 5;
                }
                ranges.reverse();
                let largest = ranges[0].1;
                let mut model = Vec::new();
                let mut ready = Vec::new();
                let mut finished = 0;
                // Cover both sides of every inclusive boundary, including
                // packets before the first range and after the last range.
                for pn in 0..=largest + 4 {
                    for _ in 0..group {
                        let id = (model.len() as u64 + ready.len() as u64 + finished) * 4;
                        append(&mut conn, pn, id);
                        if ranges.iter().any(|&(a, b)| (a..=b).contains(&pn)) {
                            finished += 1;
                        } else if pn < largest.saturating_sub(Connection::LOSS_THRESHOLD) {
                            ready.push(id);
                        } else {
                            model.push((pn, id));
                        }
                    }
                }
                assert!(ack(&mut conn, &ranges));
                assert_eq!(conn.finished, finished, "seed {seed}, count {count}");
                assert_eq!(conn.unacked.iter().copied().collect::<Vec<_>>(), model);
                assert_eq!(conn.ready, ready);
                assert_eq!(conn.send_credit.responses.len(), ready.len());
                for &id in &ready {
                    let req = conn.stream_mut(id).unwrap();
                    assert!(req.partial && req.queued && !req.send_done);
                }
                assert!(!ack(&mut conn, &ranges), "duplicate ACK made progress");
                assert_eq!(conn.finished, finished);
                assert_eq!(conn.ready, ready);
                assert_eq!(conn.unacked.iter().copied().collect::<Vec<_>>(), model);
            }
        }
    }
}

#[test]
fn sparse_range_cursor_restarts_for_older_acks_at_numeric_limits() {
    for base in [0, (1_u64 << 62) - 16, u64::MAX - 15] {
        let mut conn = connection();
        for n in 0..16 {
            append(&mut conn, base + n, n * 4);
        }
        // Decode three singleton ranges: base + 10, base + 6, base + 2.
        // Pass the header directly to also test internal u64 arithmetic beyond
        // the wire format's 62-bit packet-number limit.
        assert!(conn.on_ack(base + 10, 0, &[2, 0, 2, 0]));
        assert_eq!(conn.finished, 3);
        assert_eq!(conn.ready, [0, 4, 12, 16, 20]);
        assert_eq!(conn.unacked.front(), Some(&(base + 7, 28)));
        assert!(!conn.on_ack(base + 10, 0, &[2, 0, 2, 0]));
        // The cursor belongs to one ACK, not to the connection. An older ACK
        // still covers survivors on each side of its own gaps.
        assert!(conn.on_ack(base + 9, 0, &[0, 0]));
        assert_eq!(conn.finished, 5);
        assert_eq!(conn.unacked.front(), Some(&(base + 8, 32)));
        assert_eq!(conn.unacked.back(), Some(&(base + 15, 60)));
        assert_eq!(conn.ready, [0, 4, 12, 16, 20]);
    }
}

#[test]
fn cursor_skips_empty_ranges_across_a_wrapped_ledger() {
    let mut conn = connection();
    conn.unacked = VecDeque::with_capacity(16);
    for n in 0..12 {
        append(&mut conn, n, n * 4);
    }
    assert!(conn.on_ack(7, 7, &[]));
    for n in 12..24 {
        append(&mut conn, 100 + n * 10, n * 4);
    }
    assert!(!conn.unacked.as_slices().1.is_empty());
    let suffix = conn.unacked.back().unwrap() as *const (u64, u64);
    let mut ranges: Vec<_> = (8..=320).step_by(2).map(|pn| (pn, pn)).collect();
    ranges.reverse();
    assert!(ack(&mut conn, &ranges));
    assert_eq!(conn.finished, 21);
    assert_eq!(conn.ready, [36, 44]);
    assert_eq!(conn.unacked, [(330, 92)]);
    assert_eq!(conn.unacked.back().unwrap() as *const (u64, u64), suffix);
}

#[test]
fn many_sparse_acks_preserve_late_original_and_retry_credit() {
    for retry in [false, true] {
        let mut conn = data_connection();
        conn.max_streams_bidi = 128;
        conn.streams_credit.told = 128;
        let (control, _) = send_data(&mut conn);
        acknowledge(&mut conn, Space::Data, &[(control, control)]);
        let mut packets = Vec::new();
        for n in 0..128 {
            conn.on_stream(n * 4, 0, b"request", true).unwrap();
            packets.push(send_data(&mut conn).0);
        }
        let charged = conn.send_credit.sent;
        let selected: Vec<_> = packets
            .iter()
            .step_by(2)
            .rev()
            .map(|&pn| (pn, pn))
            .collect();
        acknowledge(&mut conn, Space::Data, &selected);
        assert_eq!(conn.finished, 64);
        assert_eq!(conn.unacked.len(), 3); // largest - 3, largest - 1, newest
        conn.on_timeout(conn.timeout().unwrap());
        assert!(conn.unacked.is_empty());
        let mut retries = Vec::new();
        while !conn.ready.is_empty() {
            retries.push(send_data(&mut conn).0);
        }
        // Retry packets can be adjacent, so use a single inclusive range.
        if retry {
            acknowledge(
                &mut conn,
                Space::Data,
                &[(retries[0], *retries.last().unwrap())],
            );
        } else {
            let ranges: Vec<_> = packets
                .iter()
                .skip(1)
                .step_by(2)
                .rev()
                .map(|&pn| (pn, pn))
                .collect();
            acknowledge(&mut conn, Space::Data, &ranges);
        }
        assert_eq!(conn.finished, 128);
        assert_eq!(conn.streams_limit(), conn.max_streams_bidi + 128);
        assert_eq!(conn.send_credit.sent, charged);
        assert!(conn.ready.is_empty());
        assert!(conn.send_credit.responses.is_empty());
        assert!(conn.streams.is_empty());
        acknowledge(
            &mut conn,
            Space::Data,
            &[(*packets.first().unwrap(), *retries.last().unwrap())],
        );
        assert_eq!(conn.finished, 128, "late copies returned credit twice");
    }
}

// Place the same logical ledger at a specified physical head, without
// acknowledging artificial packets or changing any stream/recovery state.
fn rotated_ledger(packets: &[u64], head: usize) -> Connection {
    let mut conn = connection();
    conn.streams_credit.told = packets.len() as u64;
    conn.unacked = VecDeque::with_capacity(packets.len());
    let capacity = conn.unacked.capacity();
    assert!(head < capacity);
    conn.unacked.extend((0..head).map(|_| (0, u64::MAX)));
    let first_len = packets.len().min(capacity - head);
    for (i, &pn) in packets[..first_len].iter().enumerate() {
        append(&mut conn, pn, i as u64 * 4);
    }
    for _ in 0..head {
        assert_eq!(conn.unacked.pop_front(), Some((0, u64::MAX)));
    }
    for (i, &pn) in packets.iter().enumerate().skip(first_len) {
        append(&mut conn, pn, i as u64 * 4);
    }
    assert_eq!(conn.unacked.capacity(), capacity);
    assert_eq!(conn.unacked.as_slices().0.len(), first_len);
    conn.send_credit.sent = packets.len() as u64 * RESPONSE.len() as u64;
    conn
}

fn check_flat_ack(conn: &mut Connection, largest: u64, first: u64, rest: &[u8]) {
    let before: Vec<_> = conn.unacked.iter().copied().collect();
    let ranges: Vec<_> = frame::AckRanges::new(largest, first, rest).collect();
    let mut expected = Vec::new();
    let mut lost = conn.ready.clone();
    let mut finished = conn.finished;
    let mut acknowledged = false;
    // Full vector scan and independent per-entry range membership: no ring
    // indexing, monotone range cursor, prefix stopping or in-place compaction.
    for &(pn, id) in &before {
        if ranges.iter().any(|&(lo, hi)| lo <= pn && pn <= hi) {
            finished += 1;
            acknowledged = true;
        } else if largest.checked_sub(pn).is_some_and(|gap| gap > 3) {
            lost.push(id);
        } else {
            expected.push((pn, id));
        }
    }
    let capacity = conn.unacked.capacity();
    let charged = conn.send_credit.sent;
    let suffix: Vec<_> = conn
        .unacked
        .iter()
        .filter(|&&(pn, _)| pn > largest)
        .map(|entry| (*entry, entry as *const (u64, u64)))
        .collect();
    let prefix_survivors = expected.iter().filter(|&&(pn, _)| pn <= largest).count();
    assert_eq!(conn.on_ack(largest, first, rest), acknowledged);
    assert_eq!(conn.unacked.iter().copied().collect::<Vec<_>>(), expected);
    assert_eq!(conn.finished, finished);
    assert_eq!(conn.ready, lost);
    assert_eq!(conn.send_credit.sent, charged);
    assert_eq!(conn.send_credit.responses.len(), lost.len());
    assert_eq!(conn.unacked.capacity(), capacity);
    for &id in &lost {
        assert!(conn.send_credit.responses.contains_key(&id));
        let req = conn.stream_mut(id).unwrap();
        assert!(req.partial && req.queued && !req.send_done);
    }
    for &(_, id) in &expected {
        let req = conn.stream_mut(id).unwrap();
        assert!(!req.partial && !req.queued && !req.send_done);
    }
    // VecDeque drains the shorter side. A large newer suffix must remain at
    // exactly the same addresses, even with many surviving streams per PN.
    if suffix.len() > prefix_survivors {
        for (entry, (value, address)) in conn
            .unacked
            .iter()
            .filter(|&&(pn, _)| pn > largest)
            .zip(suffix)
        {
            assert_eq!(*entry, value);
            assert_eq!(entry as *const (u64, u64), address);
        }
    }
}

#[test]
fn wrapped_shared_packet_survivors_match_flat_model() {
    for group in [1, 4, 16] {
        let packets: Vec<_> = (0..128).map(|i| 100 + i / group).collect();
        let largest = packets[127] - 4;
        for head in [0, 1, 32, 63, 96, 127] {
            for mask in 0..8 {
                let mut conn = rotated_ledger(&packets, head);
                // Select among older, separated ranges without using the
                // production range encoder. The highest range is always one PN.
                let mut rest = Vec::new();
                let mut previous = largest;
                for (bit, offset) in [2, 4, 6].into_iter().enumerate() {
                    if mask & (1 << bit) != 0 {
                        let pn = largest - offset;
                        rest.extend_from_slice(&[(previous - pn - 2) as u8, 0]);
                        previous = pn;
                    }
                }
                check_flat_ack(&mut conn, largest, 0, &rest);
                check_flat_ack(&mut conn, largest, 0, &rest); // duplicate
                check_flat_ack(&mut conn, largest - 1, 0, &[]); // older
                check_flat_ack(&mut conn, packets[127], 0, &[]); // newer
            }
        }
    }
}

#[test]
fn wrapped_ack_prefix_boundaries_preserve_large_newer_suffix() {
    let packets: Vec<_> = (0..4096).map(|i| 100 + i / 16).collect();
    for head in [0, 1, 3984, 4000, 4016, 4095] {
        for largest in [99, 100, 105, 106, 107, 355] {
            for first in [0, largest] {
                let mut conn = rotated_ledger(&packets, head);
                check_flat_ack(&mut conn, largest, first, &[]);
            }
        }
    }
}

#[test]
fn wrapped_shared_packet_loss_boundary_at_numeric_limits() {
    for base in [0, (1_u64 << 62) - 8, u64::MAX - 7] {
        let packets: Vec<_> = (0..128).map(|i| base + i / 16).collect();
        for head in [0, 1, 63, 96, 127] {
            let mut conn = rotated_ledger(&packets, head);
            check_flat_ack(&mut conn, base + 3, 0, &[]);
            assert!(conn.ready.is_empty()); // exactly three PNs is not lost
            check_flat_ack(&mut conn, base + 4, 0, &[]);
            assert_eq!(conn.ready, (0..16).map(|i| i * 4).collect::<Vec<_>>());
            check_flat_ack(&mut conn, base + 1, 0, &[]);
        }
    }
}
