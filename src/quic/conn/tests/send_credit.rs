use super::*;

fn constrained(stream: u64, data: u64) -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.peer.initial_max_stream_data_bidi_local = stream;
    conn.peer.initial_max_data = data + CONTROL_PRELUDE.len() as u64;
    conn.send_credit.initialize(&conn.peer);
    conn
}

fn grant(conn: &mut Connection, id: u64, limit: u64) {
    conn.on_frame(&frame::Frame::MaxStreamData { id, limit }, Space::Data)
        .unwrap();
}

fn streams(plain: &[u8]) -> Vec<(u64, u64, Vec<u8>, bool)> {
    frame::Frames::new(plain)
        .filter_map(|f| match f.unwrap() {
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => Some((id, offset, data.to_vec(), fin)),
            _ => None,
        })
        .collect()
}

fn idle(conn: &mut Connection) {
    assert!(!conn.wants_send());
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
    assert!(conn.timeout().is_none());
}

#[test]
fn late_fragment_ack_cancels_only_pending_range_with_unacked_siblings() {
    for id in [0, 64] {
        let mut conn = constrained(1, 4096);
        conn.on_stream(id, 0, b"request", true).unwrap();
        conn.on_stream(id + 4, 0, b"unfinished", false).unwrap();
        let mut originals = Vec::new();
        let mut start = 0;
        for end in [1, 3, 7, 9] {
            grant(&mut conn, id, end);
            let (pn, plain) = send_data(&mut conn);
            let parts = streams(&plain);
            assert_eq!(
                parts,
                [(
                    id,
                    start,
                    RESPONSE[start as usize..end as usize].to_vec(),
                    false
                )]
            );
            originals.push(pn);
            start = end;
        }
        // Only the earliest range reaches the packet-loss threshold.
        acknowledge(&mut conn, Space::Data, &[(originals[3], originals[3])]);
        assert_eq!(conn.ready, [id]);
        acknowledge(&mut conn, Space::Data, &[(originals[0], originals[0])]);
        assert!(
            conn.ready.is_empty(),
            "an ACKed pending range cannot keep a retry queued"
        );
        assert!(!conn.stream_mut(id).unwrap().queued);
        assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
        assert_eq!(conn.finished, 0);
        // Duplicate ACKs do not create work; two unacknowledged ranges remain.
        acknowledge(&mut conn, Space::Data, &[(originals[0], originals[0])]);
        assert!(conn.ready.is_empty());
        acknowledge(&mut conn, Space::Data, &[(originals[1], originals[2])]);
        grant(&mut conn, id, RESPONSE.len() as u64);
        let (pn, plain) = send_data(&mut conn);
        assert_eq!(streams(&plain), [(id, 9, RESPONSE[9..].to_vec(), true)]);
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        assert_eq!(conn.finished, 1);
        let sibling = conn.streams.get(((id + 4) / 4 - conn.base_stream) as usize);
        assert!(matches!(sibling, Some(StreamSlot::Active(req)) if !req.fin && req.size == 10));
    }
}

#[test]
fn fragment_ack_keeps_later_pending_range_after_partial_retry() {
    let mut conn = constrained(1, 4096);
    conn.on_stream(0, 0, b"request", true).unwrap();
    let mut originals = Vec::new();
    for end in [1, 4, 9] {
        grant(&mut conn, 0, end);
        originals.push(send_data(&mut conn).0);
    }
    let charged = conn.send_credit.sent;
    conn.on_send_credit_timeout();
    let mut body = Vec::new();
    let retry = conn.spaces[Space::Data as usize].next_pn;
    // Two STREAM headers (type, ID, offset, length) and four payload bytes.
    assert!(conn.write_partial_response(0, &mut body, 12, retry));
    conn.spaces[Space::Data as usize].next_pn += 1;
    assert_eq!(
        streams(&body),
        [
            (0, 0, RESPONSE[..1].to_vec(), false),
            (0, 1, RESPONSE[1..4].to_vec(), false),
        ]
    );
    assert_eq!(conn.send_credit.sent, charged);
    acknowledge(&mut conn, Space::Data, &[(originals[0], originals[0])]);
    assert_eq!(
        conn.ready,
        [0],
        "the later pending range still needs a retry"
    );
    acknowledge(&mut conn, Space::Data, &[(originals[2], originals[2])]);
    assert!(
        conn.ready.is_empty(),
        "only a nonpending retransmitted range survives"
    );
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
    acknowledge(&mut conn, Space::Data, &[(originals[1], originals[1])]);
    grant(&mut conn, 0, RESPONSE.len() as u64);
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(streams(&plain), [(0, 9, RESPONSE[9..].to_vec(), true)]);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.finished, 1);
    assert_eq!(
        conn.send_credit.sent,
        CONTROL_PRELUDE.len() as u64 + RESPONSE.len() as u64
    );
    idle(&mut conn);
}

#[test]
fn zero_stale_and_sparse_grants_do_not_spin_or_wake_other_streams() {
    let mut conn = constrained(0, 1024);
    for id in (0..32).map(|i| i * 4) {
        conn.on_stream(id, 0, b"request", true).unwrap();
    }
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
    idle(&mut conn);
    for id in [0, 4, 124] {
        grant(&mut conn, id, 0);
    }
    idle(&mut conn);
    for id in [124, 0, 48, 4] {
        let mut response = Vec::new();
        for limit in [1, 7, 19, RESPONSE.len() as u64] {
            grant(&mut conn, id, limit);
            grant(&mut conn, id, limit);
            grant(&mut conn, id, 0);
            assert_eq!(conn.ready, [id]);
            let (pn, plain) = send_data(&mut conn);
            let parts = streams(&plain);
            assert_eq!(parts.len(), 1);
            let (stream, offset, data, fin) = &parts[0];
            assert_eq!(*stream, id);
            assert_eq!(*offset, response.len() as u64);
            response.extend_from_slice(data);
            assert_eq!(*fin, response.len() == RESPONSE.len());
            acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
            idle(&mut conn);
        }
        assert_eq!(response, RESPONSE);
    }
    assert_eq!(conn.finished, 4);
    assert_eq!(conn.send_credit.sent, 3 + 4 * RESPONSE.len() as u64);
    grant(&mut conn, 124, MAX_STREAM_OFFSET);
    grant(&mut conn, 2, MAX_STREAM_OFFSET);
    grant(&mut conn, 256, MAX_STREAM_OFFSET);
    idle(&mut conn);
    assert_eq!(std::mem::size_of::<Request>(), 16);
    assert_eq!(std::mem::size_of::<(u64, u64)>(), 16);
}

#[test]
fn connection_credit_counts_control_and_every_fresh_byte_once() {
    let mut conn = constrained(1024, 0);
    for id in [0, 4, 8] {
        conn.on_stream(id, 0, b"request", true).unwrap();
    }
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
    idle(&mut conn);
    assert_eq!(conn.send_credit.blocked.len(), 3);
    let mut responses = [Vec::new(), Vec::new(), Vec::new()];
    let mut fins = [0; 3];
    for limit in 4..=3 + 3 * RESPONSE.len() as u64 {
        conn.on_max_data(limit);
        conn.on_max_data(limit - 1);
        let (pn, plain) = send_data(&mut conn);
        for (id, offset, data, fin) in streams(&plain) {
            let out = &mut responses[(id / 4) as usize];
            assert_eq!(offset, out.len() as u64);
            out.extend(data);
            fins[(id / 4) as usize] += usize::from(fin);
        }
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        assert_eq!(conn.send_credit.sent, limit);
        idle(&mut conn);
    }
    assert_eq!(fins, [1; 3]);
    assert!(responses.iter().all(|r| r == RESPONSE));
    assert_eq!(conn.finished, 3);
    assert!(conn.send_credit.responses.is_empty());
    assert!(conn.send_credit.blocked.is_empty());
}

#[test]
fn fragment_loss_sparse_acks_and_late_original_ack_preserve_ranges() {
    let mut conn = constrained(4, 4);
    conn.on_stream(0, 0, b"request", true).unwrap();
    let (original, first) = send_data(&mut conn);
    assert_eq!(streams(&first), [(0, 0, RESPONSE[..4].to_vec(), false)]);
    conn.on_timeout(conn.timeout().unwrap());
    let (copy, retry) = send_data(&mut conn);
    assert_eq!(streams(&retry), streams(&first));
    assert_eq!(conn.send_credit.sent, 7);
    grant(&mut conn, 0, RESPONSE.len() as u64);
    conn.on_max_data(3 + RESPONSE.len() as u64);
    let (tail, plain) = send_data(&mut conn);
    assert_eq!(streams(&plain), [(0, 4, RESPONSE[4..].to_vec(), true)]);
    acknowledge(&mut conn, Space::Data, &[(tail, tail)]);
    assert_eq!(
        conn.finished, 0,
        "FIN ACK alone does not cover the missing prefix"
    );
    conn.on_timeout(conn.timeout().unwrap());
    assert_eq!(conn.ready, [0]);
    acknowledge(&mut conn, Space::Data, &[(original, original)]);
    assert_eq!(conn.finished, 1);
    idle(&mut conn);
    assert!(original < copy && copy < tail);
    acknowledge(&mut conn, Space::Data, &[(original, tail)]);
    assert_eq!(conn.finished, 1);
    assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
}

#[test]
fn sparse_packet_threshold_loss_and_repeated_pto_do_not_charge_new_credit() {
    let mut conn = constrained(8, 8);
    conn.on_stream(0, 0, b"request", true).unwrap();
    let (original, first) = send_data(&mut conn);
    let mut later = original;
    for _ in 0..3 {
        conn.path_response = Some([7; 8]);
        later = send_data(&mut conn).0;
    }
    acknowledge(&mut conn, Space::Data, &[(later, later)]);
    assert_eq!(conn.ready, [0]);
    let (probe, plain) = send_data(&mut conn);
    assert_eq!(streams(&plain), streams(&first));
    // An ACK for an older packet must not requeue the newer probe.
    acknowledge(&mut conn, Space::Data, &[(original, original)]);
    idle(&mut conn);
    assert_eq!(conn.finished, 0);
    acknowledge(&mut conn, Space::Data, &[(probe, probe)]);
    grant(&mut conn, 0, RESPONSE.len() as u64);
    conn.on_max_data(3 + RESPONSE.len() as u64);
    let (_, tail) = send_data(&mut conn);
    for _ in 0..12 {
        conn.on_timeout(conn.timeout().unwrap());
        let (_, retry) = send_data(&mut conn);
        assert_eq!(streams(&retry), streams(&tail));
        assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
    }
    let last = conn.spaces[Space::Data as usize].next_pn - 1;
    acknowledge(&mut conn, Space::Data, &[(last, last)]);
    assert_eq!(conn.finished, 1);
    idle(&mut conn);
}

#[test]
fn stopped_partial_response_resets_at_actual_offset_without_refunding_credit() {
    for sent in [0, 1, 7, 23] {
        let mut conn = constrained(sent, 1024);
        conn.on_stream(0, 0, b"request", true).unwrap();
        let mut original = None;
        if sent > 0 {
            original = Some(send_data(&mut conn).0);
        } else {
            assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
        }
        receive_stop(&mut conn, 0).unwrap();
        grant(&mut conn, 0, RESPONSE.len() as u64);
        let (pn, plain) = send_data(&mut conn);
        assert_reset(&plain, 0, sent);
        assert!(streams(&plain).is_empty());
        if let Some(old) = original {
            acknowledge(&mut conn, Space::Data, &[(old, old)]);
        }
        assert_eq!(conn.finished, 0);
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        assert_eq!(conn.finished, 1);
        assert_eq!(conn.send_credit.sent, 3 + sent);
        assert!(conn.send_credit.responses.is_empty());
        idle(&mut conn);
    }
}

#[test]
fn control_stream_waits_for_opening_stream_and_connection_credit() {
    let mut conn = data_connection();
    conn.peer.initial_max_data = 0;
    conn.peer.initial_max_stream_data_uni = 0;
    conn.peer.initial_max_streams_uni = 0;
    conn.send_credit.initialize(&conn.peer);
    let (pn, plain) = send_data(&mut conn); // HANDSHAKE_DONE remains sendable.
    assert!(streams(&plain).is_empty());
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    idle(&mut conn);
    conn.on_frame(
        &frame::Frame::MaxStreams {
            bidi: false,
            limit: 1,
        },
        Space::Data,
    )
    .unwrap();
    idle(&mut conn);
    grant(&mut conn, CONTROL_STREAM, 1);
    idle(&mut conn);
    for end in 1..=3 {
        grant(&mut conn, CONTROL_STREAM, end);
        conn.on_max_data(end);
        let (pn, plain) = send_data(&mut conn);
        assert_eq!(
            streams(&plain),
            [(3, end - 1, vec![CONTROL_PRELUDE[end as usize - 1]], false)]
        );
        conn.on_timeout(conn.timeout().unwrap());
        let (_, retry) = send_data(&mut conn);
        assert_eq!(streams(&retry), streams(&plain));
        assert_eq!(conn.send_credit.sent, end);
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        idle(&mut conn);
    }
    grant(&mut conn, CONTROL_STREAM, MAX_STREAM_OFFSET);
    conn.on_max_data(MAX_STREAM_OFFSET);
    idle(&mut conn);
}

#[test]
fn packet_room_does_not_consume_or_lose_credit_and_ordinary_retries_are_free() {
    let mut conn = constrained(7, 7);
    conn.on_stream(0, 0, b"request", true).unwrap();
    let need = frame::stream_overhead(0, 0, 7) + 7;
    let mut plain = Vec::new();
    conn.write_data(&mut plain, need - 1, 10);
    assert!(plain.is_empty());
    assert_eq!(conn.send_credit.sent, 3);
    assert_eq!(conn.ready, [0]);
    conn.write_data(&mut plain, need, 11);
    assert_eq!(streams(&plain), [(0, 0, RESPONSE[..7].to_vec(), false)]);
    assert_eq!(conn.send_credit.sent, 10);
    let mut conn = constrained(1024, RESPONSE.len() as u64);
    conn.on_stream(0, 0, b"request", true).unwrap();
    let (_, first) = send_data(&mut conn);
    assert!(conn.send_credit.responses.is_empty());
    conn.on_timeout(conn.timeout().unwrap());
    let (pn, retry) = send_data(&mut conn);
    assert_eq!(streams(&first), streams(&retry));
    assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    idle(&mut conn);
}

#[test]
fn mixed_full_and_fragmented_responses_retire_across_table_shifts() {
    let mut conn = constrained(1, 4096);
    for round in 0..32 {
        let base = round * 16;
        for id in [base, base + 4, base + 8, base + 12] {
            if id & 4 != 0 {
                // Credit can arrive before the request bytes.
                grant(&mut conn, id, RESPONSE.len() as u64);
            }
            conn.on_stream(id, 0, b"request", true).unwrap();
        }
        let (first, plain) = send_data(&mut conn);
        assert_eq!(streams(&plain).len(), 4);
        acknowledge(&mut conn, Space::Data, &[(first, first)]);
        assert_eq!(conn.finished, round * 4 + 2);
        for id in [base + 8, base] {
            grant(&mut conn, id, RESPONSE.len() as u64);
        }
        let (last, _) = send_data(&mut conn);
        acknowledge(&mut conn, Space::Data, &[(last, last)]);
        assert_eq!(conn.finished, round * 4 + 4);
        assert_eq!(conn.base_stream, round * 4 + 4);
        assert!(conn.streams.is_empty());
        // MAX_STREAMS may need a reliable update as the allowance is used.
        while conn.wants_send() {
            let (pn, _) = send_data(&mut conn);
            acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        }
        idle(&mut conn);
    }
    assert_eq!(conn.send_credit.sent, 3 + 128 * RESPONSE.len() as u64);
}

#[test]
fn whole_response_copy_window_preserves_late_ack_and_queued_probe() {
    // The oracle retains the last eight actual transmissions, independently
    // of the recovery representation. An unsent probe adds no identity.
    for copies in [1_usize, 2, 8, 9, 17] {
        for acknowledged_index in [0, copies.saturating_sub(8), copies - 1] {
            for queued in [false, true] {
                let mut conn = constrained(1024, RESPONSE.len() as u64);
                conn.on_stream(0, 0, b"request", true).unwrap();
                let (original, first) = send_data(&mut conn);
                let mut transmissions = vec![original];
                conn.on_timeout(conn.timeout().unwrap());
                for _ in 1..copies {
                    let (pn, plain) = send_data(&mut conn);
                    assert_eq!(streams(&plain), streams(&first));
                    transmissions.push(pn);
                    if transmissions.len() < copies || queued {
                        conn.on_timeout(conn.timeout().unwrap());
                    }
                }
                let retained: std::collections::BTreeSet<_> =
                    transmissions.iter().rev().take(8).copied().collect();
                let acked = transmissions[acknowledged_index];
                acknowledge(&mut conn, Space::Data, &[(acked, acked)]);
                assert_eq!(conn.finished, u64::from(retained.contains(&acked)));
                assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
                if retained.contains(&acked) {
                    assert!(conn.ready.is_empty());
                    assert!(conn.send_credit.responses.is_empty());
                    idle(&mut conn);
                }
                let newest = *transmissions.last().unwrap();
                acknowledge(&mut conn, Space::Data, &[(newest, newest)]);
                acknowledge(&mut conn, Space::Data, &[(original, newest)]);
                assert_eq!(conn.finished, 1, "duplicate copies returned stream credit");
                assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
                idle(&mut conn);
            }
        }
    }
}

#[test]
fn whole_response_room_failure_cannot_forget_original_or_charge_credit() {
    for id in [0, 60, 64, 252] {
        let mut conn = constrained(1024, RESPONSE.len() as u64);
        conn.on_stream(id, 0, b"request", true).unwrap();
        let (original, _) = send_data(&mut conn);
        conn.on_timeout(conn.timeout().unwrap());
        let need = frame::stream_overhead(id, 0, RESPONSE.len()) + RESPONSE.len();
        for pn in 100..120 {
            let mut plain = Vec::new();
            assert!(conn.write_partial_response(id, &mut plain, need - 1, pn));
            assert!(plain.is_empty());
            assert_eq!(conn.ready, [id]);
            assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
        }
        // If a failed send appended a packet number, twenty failures would
        // evict this real copy and the response would incorrectly remain live.
        acknowledge(&mut conn, Space::Data, &[(original, original)]);
        assert_eq!(conn.finished, 1);
        assert!(conn.send_credit.responses.is_empty());
        idle(&mut conn);
    }
}

#[test]
fn whole_response_recovery_preserves_unfinished_sibling_and_respects_stop() {
    for stopped in [false, true] {
        for retry in [false, true] {
            let mut conn = constrained(1024, 2 * RESPONSE.len() as u64);
            conn.on_stream(0, 0, b"request", false).unwrap();
            conn.on_stream(4, 0, b"request", true).unwrap();
            let (original, first) = send_data(&mut conn);
            assert_eq!(streams(&first), [(4, 0, RESPONSE.to_vec(), true)]);
            conn.on_timeout(conn.timeout().unwrap());
            if retry {
                let (_, plain) = send_data(&mut conn);
                assert_eq!(streams(&plain), streams(&first));
                conn.on_timeout(conn.timeout().unwrap());
            }
            if stopped {
                receive_stop(&mut conn, 4).unwrap();
                assert!(conn.send_credit.responses.is_empty());
            }
            acknowledge(&mut conn, Space::Data, &[(original, original)]);
            assert!(!conn.stream_mut(0).unwrap().answered);
            if stopped {
                assert_eq!(conn.finished, 0, "RESET_STREAM still needs its own ACK");
                let (reset, plain) = send_data(&mut conn);
                assert_reset(&plain, 4, RESPONSE.len() as u64);
                assert!(streams(&plain).is_empty());
                acknowledge(&mut conn, Space::Data, &[(reset, reset)]);
            }
            assert_eq!(conn.finished, 1);
            assert_eq!(
                conn.base_stream, 0,
                "unfinished sibling must remain addressable"
            );
            assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
            assert!(conn.send_credit.responses.is_empty());
            idle(&mut conn);
            conn.on_stream(0, 7, b"", true).unwrap();
            let (pn, plain) = send_data(&mut conn);
            assert_eq!(streams(&plain), [(0, 0, RESPONSE.to_vec(), true)]);
            acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
            assert_eq!(conn.finished, 2);
            assert_eq!(conn.send_credit.sent, 3 + 2 * RESPONSE.len() as u64);
            idle(&mut conn);
        }
    }
}

#[test]
fn every_response_credit_split_retains_prefix_until_original_ack() {
    for split in 1..RESPONSE.len() as u64 {
        let mut conn = constrained(split, split);
        conn.on_stream(0, 0, b"request", true).unwrap();
        let (original, first) = send_data(&mut conn);
        assert_eq!(
            streams(&first),
            [(0, 0, RESPONSE[..split as usize].to_vec(), false)]
        );
        conn.on_timeout(conn.timeout().unwrap());
        let (_, retry) = send_data(&mut conn);
        assert_eq!(streams(&retry), streams(&first));
        grant(&mut conn, 0, RESPONSE.len() as u64);
        conn.on_max_data(3 + RESPONSE.len() as u64);
        let (tail, plain) = send_data(&mut conn);
        assert_eq!(
            streams(&plain),
            [(0, split, RESPONSE[split as usize..].to_vec(), true)]
        );
        acknowledge(&mut conn, Space::Data, &[(tail, tail)]);
        assert_eq!(conn.finished, 0);
        conn.on_timeout(conn.timeout().unwrap());
        acknowledge(&mut conn, Space::Data, &[(original, original)]);
        assert_eq!(conn.finished, 1);
        assert_eq!(conn.send_credit.sent, 3 + RESPONSE.len() as u64);
        idle(&mut conn);
    }
}
