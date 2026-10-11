use super::*;
use std::collections::{BTreeMap, BTreeSet};

// An intentionally exhaustive model: no flight indices, sparse membership or
// array compaction. Emitted frames drive delivery state, and ACK ranges are
// supplied directly rather than decoded with the production ACK iterator.
struct Limit {
    desired: u64,
    told: u64,
    packets: VecDeque<u64>,
    queued: bool,
}

impl Limit {
    fn needs_update(&self) -> bool {
        self.desired > self.told
            && (self.desired == MAX_STREAM_OFFSET || self.desired - self.told >= 32)
    }
}

fn check(credits: &StreamCredits, model: &BTreeMap<u64, Limit>) {
    assert_eq!(credits.streams.len(), model.len());
    let mut queued = BTreeSet::new();
    let mut flights = BTreeSet::new();
    for (&id, expected) in model {
        let actual = &credits.streams[&id];
        assert_eq!(actual.desired, expected.desired);
        assert_eq!(actual.told, expected.told);
        assert_eq!(actual.queued, expected.queued);
        assert_eq!(credits.limit(id), expected.told);
        if expected.queued {
            queued.insert(id);
        }
        if !expected.packets.is_empty() {
            flights.insert(id);
            let flight = &credits.flights[actual.flight_index];
            assert_eq!(flight.id, id);
            assert_eq!(flight.copies, expected.packets.len());
            assert!(flight.copies <= COPIES);
            assert!(
                flight.sent_in[..flight.copies]
                    .iter()
                    .eq(expected.packets.iter())
            );
        } else {
            assert_eq!(actual.flight_index, NO_FLIGHT);
        }
    }
    assert_eq!(credits.pending.len(), queued.len());
    assert_eq!(
        credits.pending.iter().copied().collect::<BTreeSet<_>>(),
        queued
    );
    assert_eq!(credits.flights.len(), flights.len());
    assert_eq!(
        credits
            .flights
            .iter()
            .map(|f| f.id)
            .collect::<BTreeSet<_>>(),
        flights
    );
    assert_eq!(credits.owed(), !queued.is_empty());
    assert_eq!(credits.in_flight(), !flights.is_empty());
    assert_eq!(credits.is_empty(), model.is_empty());
}

#[test]
fn sparse_credit_matches_exhaustive_delivery_model() {
    for initial_seed in [1, 0xfedc_ba98_7654_3210, 0x9e37_79b9_7f4a_7c15] {
        let mut seed: u64 = initial_seed;
        let mut credits = StreamCredits::new(64);
        let mut model: BTreeMap<u64, Limit> = BTreeMap::new();
        let mut pn = 0;
        for event in 0..12_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let id = ((seed >> 16) % 257) * 4;
            match seed % 8 {
                0..=2 => {
                    let size = if seed & 1023 == 0 {
                        u64::MAX
                    } else {
                        seed >> 32
                    };
                    credits.update(id, size);
                    let desired = size.saturating_add(64).min(MAX_STREAM_OFFSET);
                    let m = model.entry(id).or_insert(Limit {
                        desired,
                        told: 64,
                        packets: VecDeque::new(),
                        queued: false,
                    });
                    m.desired = m.desired.max(desired);
                    m.queued |= m.needs_update();
                }
                3 => {
                    let prefix = (seed >> 24) as usize % 11;
                    let room = prefix + (seed >> 40) as usize % 128;
                    let mut body = vec![0; prefix];
                    credits.write(&mut body, room, pn);
                    assert_eq!(body[..prefix], vec![0; prefix]);
                    assert!(body.len() <= room);
                    for frame in frame::Frames::new(&body[prefix..]) {
                        let frame::Frame::MaxStreamData { id, limit } = frame.unwrap() else {
                            panic!("unexpected frame");
                        };
                        let m = model.get_mut(&id).unwrap();
                        assert!(m.queued);
                        assert_eq!(limit, m.desired);
                        if m.told != limit {
                            m.packets.clear();
                            m.told = limit;
                        }
                        if m.packets.len() == 8 {
                            m.packets.pop_front();
                        }
                        m.packets.push_back(pn);
                        m.queued = false;
                    }
                    // A fitting pending frame must never be silently omitted.
                    if let Some(id) = credits.pending.front() {
                        let need = 1 + varint_len(*id) + varint_len(model[id].desired);
                        assert!(body.len() + need > room);
                    }
                    pn += 1;
                }
                4 | 5 => {
                    let largest = pn.saturating_sub((seed >> 32) % 160);
                    let mut ranges = vec![(largest, largest)];
                    let mut rest = Vec::new();
                    if largest >= 5 && seed & 256 != 0 {
                        ranges.push((largest - 5, largest - 4));
                        put_varint(&mut rest, 2);
                        put_varint(&mut rest, 1);
                    }
                    let mut progress = false;
                    for m in model.values_mut().filter(|m| !m.packets.is_empty()) {
                        if m.packets
                            .iter()
                            .any(|pn| ranges.iter().any(|(lo, hi)| pn >= lo && pn <= hi))
                        {
                            progress = true;
                            m.packets.clear();
                            if m.queued && !m.needs_update() {
                                m.queued = false;
                            }
                        } else if largest.saturating_sub(*m.packets.back().unwrap()) >= 3 {
                            m.queued = true;
                        }
                    }
                    assert_eq!(credits.on_ack(largest, 0, &rest), progress);
                }
                6 => {
                    credits.on_timeout();
                    for m in model.values_mut().filter(|m| !m.packets.is_empty()) {
                        m.queued = true;
                    }
                }
                _ => {
                    credits.remove(id);
                    model.remove(&id);
                }
            }
            check(&credits, &model);
            if event % 4096 == 0 {
                assert_eq!(credits.limit(u64::MAX), 64);
            }
        }
        for id in model.keys().copied().collect::<Vec<_>>() {
            credits.remove(id);
        }
        check(&credits, &BTreeMap::new());
    }
}

#[test]
fn ack_compaction_and_swap_removal_keep_indices_valid() {
    let mut credits = StreamCredits::new(64);
    let mut body = Vec::new();
    for id in 0..9 {
        credits.update(id * 4, 32);
        credits.write(&mut body, usize::MAX, id + 10);
        body.clear();
    }
    for id in [0, 4, 8] {
        assert!(credits.on_ack(id + 10, 0, &[]));
    }
    for id in [5, 1, 7, 2, 6, 3] {
        credits.remove(id * 4);
        for (index, flight) in credits.flights.iter().enumerate() {
            assert_eq!(credits.streams[&flight.id].flight_index, index);
        }
    }
    assert!(!credits.in_flight());
    credits.on_timeout();
    assert!(!credits.owed());
    assert_eq!(credits.streams.len(), 3, "ACKed limits remain advertised");
}

#[test]
fn retransmission_and_supersession_keep_single_membership() {
    let mut credits = StreamCredits::new(64);
    let mut body = Vec::new();
    for pn in 0..100 {
        credits.update(12, (pn + 1) * 32);
        credits.write(&mut body, usize::MAX, pn);
        body.clear();
        credits.on_timeout();
        assert_eq!(credits.flights.len(), 1);
        assert_eq!(credits.flights[0].id, 12);
        assert_eq!(credits.streams[&12].flight_index, 0);
        assert_eq!(credits.flights[0].copies, 1);
    }
    assert!(!credits.on_ack(98, 0, &[]));
    credits.update(12, 3232);
    assert!(credits.on_ack(99, 0, &[]));
    assert!(credits.owed(), "ACK cannot cancel an unsent increase");
    assert!(!credits.in_flight());
    credits.write(&mut body, usize::MAX, 100);
    assert_eq!(credits.flights.len(), 1);
    assert_eq!(credits.flights[0].id, 12);
    credits.remove(12);
    assert!(!credits.in_flight());
    assert!(!credits.owed());
}

#[test]
fn pending_fifo_and_packet_room_are_unchanged() {
    let mut credits = StreamCredits::new(64);
    for id in [12, 4, 8] {
        credits.update(id, 32);
    }
    let mut body = Vec::new();
    credits.write(&mut body, 3, 0);
    assert!(body.is_empty());
    assert!(!credits.in_flight());
    for id in [12, 4, 8] {
        credits.write(&mut body, 4, 1);
        assert_eq!(
            frame::Frames::new(&body).next().unwrap().unwrap(),
            frame::Frame::MaxStreamData { id, limit: 96 }
        );
        body.clear();
    }
    assert_eq!(
        credits.flights.iter().map(|f| f.id).collect::<Vec<_>>(),
        [12, 4, 8]
    );
    assert!(!credits.owed());
}
