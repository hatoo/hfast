use super::*;
use std::collections::BTreeSet;

fn ranges(packets: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for &pn in packets.iter().rev() {
        if let Some(last) = ranges.last_mut()
            && last.0 == pn + 1
        {
            last.0 = pn;
        } else {
            ranges.push((pn, pn));
        }
    }
    ranges
}

fn apply_with<H: PacketHistory>(
    flight: &mut Flight<H>,
    packets: &BTreeSet<u64>,
    decoded: bool,
) -> bool {
    let mut bytes = Vec::new();
    frame::put_ack(&mut bytes, &ranges(packets), 0);
    let frame::Frame::Ack {
        largest,
        first_range,
        rest,
        ..
    } = frame::Frames::new(&bytes).next().unwrap().unwrap()
    else {
        panic!("expected ACK");
    };
    if decoded {
        let ranges: Vec<_> = frame::AckRanges::new(largest, first_range, rest).collect();
        flight.on_ack_ranges(largest, &ranges)
    } else {
        flight.on_ack(largest, first_range, rest)
    }
}

fn apply<H: PacketHistory>(flight: &mut Flight<H>, packets: &BTreeSet<u64>) -> bool {
    apply_with(flight, packets, false)
}

fn check(history: &[u64], packets: &BTreeSet<u64>, pending: bool) {
    // Both storage policies must agree with the independent set model,
    // including empty, inline and spilled fragment histories.
    check_storage::<Vec<u64>>(history, packets, pending, Vec::capacity);
    check_storage::<sent_packets::SentPackets>(
        history,
        packets,
        pending,
        sent_packets::SentPackets::capacity,
    );
}

fn check_storage<H: PacketHistory>(
    history: &[u64],
    packets: &BTreeSet<u64>,
    pending: bool,
    capacity: impl Fn(&H) -> usize,
) {
    for decoded in [false, true] {
        let mut flight = Flight::<H>::new();
        for &pn in history {
            flight.sent(pn);
        }
        flight.pending = pending;
        let before_capacity = capacity(&flight.sent_in);
        let hit = history.iter().any(|pn| packets.contains(pn));
        let loss = history
            .last()
            .is_some_and(|pn| *packets.last().unwrap() >= pn + Connection::LOSS_THRESHOLD);
        assert_eq!(
            apply_with(&mut flight, packets, decoded),
            hit,
            "{history:?} {packets:?}"
        );
        assert_eq!(flight.pending, !hit && (pending || loss));
        assert_eq!(&*flight.sent_in, if hit { &[][..] } else { history });
        assert_eq!(capacity(&flight.sent_in), before_capacity);
        assert!(
            !apply_with(&mut flight, packets, decoded),
            "duplicate ACK made progress"
        );
        assert_eq!(flight.pending, !hit && (pending || loss));
    }
}

#[test]
fn control_ack_exhaustive_set_oracle() {
    // The model uses set membership, not a range/history merge. Exhaust all
    // histories and ACK subsets in a small domain, with repeated identities.
    for ack_mask in 1_u16..256 {
        let packets = (0..8).filter(|pn| ack_mask & (1 << pn) != 0).collect();
        for history_mask in 0_u16..256 {
            let history: Vec<_> = (0..8)
                .filter(|pn| history_mask & (1 << pn) != 0)
                .flat_map(|pn| [pn, pn])
                .collect();
            check(&history, &packets, false);
            check(&history, &packets, true);
        }
    }
}

#[test]
fn control_ack_sparse_large_history() {
    let history: Vec<_> = (0..1024).map(|i| 4 * i).collect();
    let misses: BTreeSet<_> = (0..512).map(|i| 8 * i + 1).collect();
    check(&history, &misses, false);
    check(&history, &misses, true);
    for pn in [history[0], history[511], history[1023]] {
        let mut packets = misses.clone();
        packets.insert(pn);
        check(&history, &packets, false);
        check(&history, &packets, true);
    }
}

#[test]
fn decoded_ack_sparse_range_boundaries_match_set() {
    let max = (1_u64 << 62) - 1;
    // Include both sides of the short-list cutoff and binary search splits.
    for len in [
        1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33, 63, 64, 65, 511, 512, 513,
    ] {
        for base in [0, max - 4 * len - 3] {
            let packets: BTreeSet<_> = (0..len)
                .flat_map(|i| [base + 4 * i + 1, base + 4 * i + 2])
                .collect();
            // Inclusive endpoints, both sides of every gap, and identities
            // older/newer than all ranges. The oracle is packet membership.
            for pn in base..=base + 4 * len + 3 {
                check(&[pn], &packets, false);
                check(&[pn], &packets, true);
            }
            check(&[], &packets, false);
            check(&[], &packets, true);
            // A late original must deliver a flight even after several newer
            // copies, while a matching newer copy must survive older misses.
            for pn in [base + 1, base + 4 * (len / 2) + 1, base + 4 * len - 2] {
                check(&[pn, max, max], &packets, true);
                check(&[base, base, pn], &packets, false);
            }
        }
    }
}

#[test]
fn decoded_ack_empty_ranges_preserve_history_and_loss_rules() {
    for pending in [false, true] {
        for largest in [0, 32, 33] {
            let mut flight = Flight::<sent_packets::SentPackets>::new();
            flight.sent(10);
            flight.sent(30);
            flight.pending = pending;
            assert!(!flight.on_ack_ranges(largest, &[]));
            assert_eq!(&*flight.sent_in, &[10, 30]);
            assert_eq!(flight.pending, pending || largest >= 33);
        }
    }
}

#[test]
fn control_ack_varint_and_packet_number_boundaries() {
    let max = (1_u64 << 62) - 1;
    let history = [0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, max];
    for &pn in &history {
        check(&history, &BTreeSet::from([pn]), false);
        check(&history, &BTreeSet::from([pn]), true);
        for lo in [pn.saturating_sub(1), pn] {
            let packets = (lo..=pn.saturating_add(1).min(max)).collect();
            check(&history, &packets, false);
        }
    }
    check(&history, &BTreeSet::from([1, 62, 65, max - 1]), false);
    check(&[], &BTreeSet::from([0, max]), true);
}

#[test]
fn control_ack_generated_set_oracle() {
    for mut rng in [1_u64, 0xa731, 0x9e3779b97f4a7c15] {
        for _ in 0..1024 {
            let mut history = Vec::new();
            let mut packets = BTreeSet::new();
            let mut pn = 0;
            for _ in 0..128 {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                pn += rng % 8;
                if rng & 16 != 0 {
                    history.push(pn);
                }
                if rng & 32 != 0 {
                    packets.insert(pn);
                }
            }
            packets.insert(pn + 1);
            check(&history, &packets, rng & 64 != 0);
        }
    }
}

#[test]
fn control_ack_old_copy_cancels_queued_or_sent_retry() {
    for retransmit in [false, true] {
        let mut flight = ControlFlight::new();
        flight.sent(10);
        flight.on_timeout();
        if retransmit {
            flight.sent(20);
        }
        assert!(apply(&mut flight, &BTreeSet::from([10, 15, 25])));
        assert!(!flight.pending);
        assert!(flight.sent_in.is_empty());
        flight.on_timeout();
        assert!(!flight.pending);
        assert!(!apply(&mut flight, &BTreeSet::from([10, 20])));
    }
}

#[test]
fn control_ack_loss_only_uses_newest_copy() {
    let mut flight = ControlFlight::new();
    flight.sent(10);
    flight.on_timeout();
    flight.sent(30);
    assert!(!apply(&mut flight, &BTreeSet::from([13, 29, 32])));
    assert!(!flight.pending);
    assert!(!apply(&mut flight, &BTreeSet::from([33])));
    assert!(flight.pending);
    flight.sent(40);
    assert!(!apply(&mut flight, &BTreeSet::from([33])));
    assert!(!flight.pending);
    assert!(apply(&mut flight, &BTreeSet::from([9, 10, 11])));
    assert!(!flight.pending);
}

#[test]
fn control_ack_search_boundaries_and_duplicates() {
    // Exercise every possible inclusive high endpoint across lengths on both
    // sides of exponential probe boundaries. The independent model remains
    // set membership, including runs of duplicate packet identities.
    for len in [
        1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025,
    ] {
        let history: Vec<_> = (0..len).map(|i| 4 * (i / 2) + 1).collect();
        for pn in 0..=history[len as usize - 1] + 1 {
            check(&history, &BTreeSet::from([pn]), false);
            check(&history, &BTreeSet::from([pn]), true);
        }
    }
}

#[test]
fn control_ack_long_skips_and_range_gaps() {
    let max = (1_u64 << 62) - 1;
    for base in [0, max - 4 * 1024] {
        let history: Vec<_> = (0..1024).map(|i| base + 4 * i).collect();
        // ACK only gaps, with entire runs above, below and between ranges.
        let misses = BTreeSet::from([base + 1, base + 1025, base + 2049, base + 4093]);
        check(&history, &misses, false);
        check(&history, &misses, true);
        for index in [0, 1, 2, 511, 512, 513, 1022, 1023] {
            let mut packets = misses.clone();
            packets.insert(history[index]);
            check(&history, &packets, false);
            check(&history, &packets, true);
        }
        check(&history, &BTreeSet::from([base + 1]), false);
        check(&history, &BTreeSet::from([base + 4093]), false);
    }
    // No eligible identity at either packet-number limit.
    check(&vec![max; 1024], &BTreeSet::from([0]), true);
    check(&vec![0; 1024], &BTreeSet::from([max]), false);
}

#[test]
fn control_ack_dispatch_preserves_empty_and_live_flights() {
    for mask in 0..16 {
        for empty_pending in [false, true] {
            let mut conn = data_connection();
            conn.rtt_probe = None;
            conn.pto_count = 5;
            for (i, flight) in [
                &mut conn.control,
                &mut conn.handshake_done,
                &mut conn.streams_credit.flight,
                &mut conn.data_credit.flight,
            ]
            .into_iter()
            .enumerate()
            {
                *flight = ControlFlight::new();
                flight.pending = empty_pending;
                if mask & (1 << i) != 0 {
                    flight.sent(10 + i as u64);
                }
            }
            // Missing copies are marked for retry without making progress;
            // unsent and settled flights preserve their different pending bits.
            conn.on_frame(
                &frame::Frame::Ack {
                    largest: 100,
                    delay: 0,
                    first_range: 0,
                    rest: &[],
                },
                Space::Data,
            )
            .unwrap();
            assert_eq!(conn.pto_count, 5);
            for (i, flight) in [
                &conn.control,
                &conn.handshake_done,
                &conn.streams_credit.flight,
                &conn.data_credit.flight,
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(flight.pending, mask & (1 << i) != 0 || empty_pending);
            }
            // Cover all saved copies. Only flights with identities can change
            // pending state or reset the PTO count, in every dispatch position.
            conn.on_frame(
                &frame::Frame::Ack {
                    largest: 100,
                    delay: 0,
                    first_range: 100,
                    rest: &[],
                },
                Space::Data,
            )
            .unwrap();
            assert_eq!(conn.pto_count, if mask == 0 { 5 } else { 0 });
            for (i, flight) in [
                &conn.control,
                &conn.handshake_done,
                &conn.streams_credit.flight,
                &conn.data_credit.flight,
            ]
            .into_iter()
            .enumerate()
            {
                assert!(flight.sent_in.is_empty());
                assert_eq!(flight.pending, mask & (1 << i) == 0 && empty_pending);
            }
        }
    }
}
