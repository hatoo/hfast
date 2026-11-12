//! Lazy receive limits for streams that need more than their initial window.

use std::collections::{HashMap, VecDeque};

use super::{Connection, frame, put_varint, varint_len};

pub(super) const MAX_STREAM_OFFSET: u64 = (1 << 62) - 1;

// Retain recent copies for late ACKs, but never grow memory with repeated loss.
// Forgetting an older copy can only cause a redundant credit transmission.
const COPIES: usize = 8;

struct Update {
    desired: u64,
    told: u64,
    sent_in: [u64; COPIES],
    copies: usize,
    queued: bool,
}

impl Update {
    fn needs_update(&self, window: u64) -> bool {
        self.desired > self.told
            && (self.desired == MAX_STREAM_OFFSET
                || self.desired - self.told >= (window / 2).max(1))
    }
}

pub(super) struct StreamCredits {
    window: u64,
    streams: HashMap<u64, Update>,
    pending: VecDeque<u64>,
    flights: usize,
}

impl StreamCredits {
    pub(super) fn new(window: u64) -> Self {
        Self {
            window,
            streams: HashMap::new(),
            pending: VecDeque::new(),
            flights: 0,
        }
    }

    pub(super) fn limit(&self, id: u64) -> u64 {
        self.streams.get(&id).map_or(self.window, |u| u.told)
    }

    pub(super) fn update(&mut self, id: u64, size: u64) {
        let desired = size.saturating_add(self.window).min(MAX_STREAM_OFFSET);
        let update = self.streams.entry(id).or_insert(Update {
            desired,
            told: self.window,
            sent_in: [0; COPIES],
            copies: 0,
            queued: false,
        });
        update.desired = update.desired.max(desired);
        if !update.queued && update.needs_update(self.window) {
            update.queued = true;
            self.pending.push_back(id);
        }
    }

    pub(super) fn owed(&self) -> bool {
        !self.pending.is_empty()
    }

    pub(super) fn in_flight(&self) -> bool {
        self.flights != 0
    }

    pub(super) fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// FIN/RESET makes further credit unnecessary (RFC 9000 Section 13.3).
    /// Final-size validation remains in the connection's receive state.
    pub(super) fn remove(&mut self, id: u64) {
        if let Some(update) = self.streams.remove(&id) {
            self.flights -= usize::from(update.copies != 0);
            if update.queued {
                self.pending.retain(|&pending| pending != id);
            }
        }
    }

    pub(super) fn write(&mut self, body: &mut Vec<u8>, room: usize, pn: u64) {
        while let Some(&id) = self.pending.front() {
            let update = self.streams.get_mut(&id).unwrap();
            let need = 1 + varint_len(id) + varint_len(update.desired);
            if body.len() + need > room {
                break;
            }
            put_varint(body, frame::MAX_STREAM_DATA);
            put_varint(body, id);
            put_varint(body, update.desired);
            // Only a frame that fits advertises or supersedes a limit.
            if update.told != update.desired {
                self.flights -= usize::from(update.copies != 0);
                update.copies = 0;
                update.told = update.desired;
            }
            if update.copies == COPIES {
                update.sent_in.copy_within(1.., 0);
                update.copies -= 1;
            }
            self.flights += usize::from(update.copies == 0);
            update.sent_in[update.copies] = pn;
            update.copies += 1;
            update.queued = false;
            self.pending.pop_front();
        }
    }

    pub(super) fn on_ack(&mut self, largest: u64, first_range: u64, rest: &[u8]) -> bool {
        if self.flights == 0 {
            return false;
        }
        let mut progress = false;
        let mut cancelled = false;
        for (&id, update) in &mut self.streams {
            if update.copies == 0 {
                continue;
            }
            let acknowledged = update.sent_in[..update.copies].iter().any(|&pn| {
                frame::AckRanges::new(largest, first_range, rest)
                    .any(|(lo, hi)| pn >= lo && pn <= hi)
            });
            if acknowledged {
                update.copies = 0;
                self.flights -= 1;
                progress = true;
                // An ACK can cancel a retry, but not a still-unsent increase.
                if update.queued && !update.needs_update(self.window) {
                    update.queued = false;
                    cancelled = true;
                }
            } else if !update.queued
                && largest.saturating_sub(update.sent_in[update.copies - 1])
                    >= Connection::LOSS_THRESHOLD
            {
                update.queued = true;
                self.pending.push_back(id);
            }
        }
        if cancelled {
            self.pending.retain(|id| self.streams[id].queued);
        }
        progress
    }

    pub(super) fn on_timeout(&mut self) {
        for (&id, update) in &mut self.streams {
            if update.copies != 0 && !update.queued {
                update.queued = true;
                self.pending.push_back(id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded_limits(body: &[u8]) -> Vec<(u64, u64)> {
        frame::Frames::new(body)
            .map(|frame| match frame.unwrap() {
                frame::Frame::MaxStreamData { id, limit } => (id, limit),
                other => panic!("unexpected credit frame: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn cancelled_entries_and_reused_ids_keep_fifo_and_exact_room() {
        let mut credits = StreamCredits::new(64);
        let ids = (0..128).map(|n| n * 4).collect::<Vec<_>>();
        for &id in &ids {
            credits.update(id, 32);
        }
        // Cancel head, tail and interior entries. Reusing an ID here is also a
        // stronger queue contract than QUIC's terminal stream lifecycle needs.
        for &id in ids.iter().step_by(2).chain(ids.last()) {
            credits.remove(id);
            credits.remove(id);
        }
        let mut expected = ids
            .iter()
            .copied()
            .filter(|id| id % 8 == 4 && *id != 508)
            .map(|id| (id, 96))
            .collect::<Vec<_>>();
        for &id in ids.iter().step_by(2).rev() {
            credits.update(id, 64);
            credits.update(id, 48); // A duplicate cannot lower or reorder it.
            expected.push((id, 128));
        }
        credits.update(MAX_STREAM_OFFSET, 32);
        expected.push((MAX_STREAM_OFFSET, 96));
        let mut body = vec![0; 7];
        credits.write(&mut body, 10, 1);
        assert_eq!(body, [0; 7], "no room for the first update");
        assert_eq!(credits.limit(expected[0].0), 64);
        assert!(!credits.in_flight());
        let mut actual = Vec::new();
        let mut pn = 2;
        while credits.owed() {
            body.clear();
            credits.write(&mut body, 23, pn);
            assert!(!body.is_empty());
            assert!(body.len() <= 23);
            actual.extend(decoded_limits(&body));
            assert!(credits.on_ack(pn, 0, &[]));
            assert!(!credits.in_flight());
            pn += 1;
        }
        assert_eq!(actual, expected);
        for (id, limit) in expected {
            assert_eq!(credits.limit(id), limit);
            credits.remove(id);
        }
        assert!(credits.is_empty());
        assert!(!credits.owed());
    }

    #[test]
    fn sparse_ack_cancellation_keeps_new_increase_and_reused_queue_slots() {
        let mut credits = StreamCredits::new(64);
        let mut body = Vec::new();
        for (id, pn) in [(0, 10), (4, 11), (8, 12)] {
            credits.update(id, 32);
            body.clear();
            credits.write(&mut body, 4, pn);
            assert_eq!(decoded_limits(&body), [(id, 96)]);
        }
        credits.on_timeout();
        credits.on_timeout(); // Exactly one pending retry per stream.
        credits.update(4, 64);
        // ACK 12 and 10, with a hole at 11. Cancel two retries in one pass.
        assert!(credits.on_ack(12, 0, &[0, 0]));
        assert_eq!(credits.flights, 1);
        assert!(credits.owed());
        credits.update(0, 64);
        credits.remove(8);
        assert!(credits.on_ack(11, 0, &[]));
        assert!(!credits.in_flight());
        body.clear();
        credits.write(&mut body, 8, 20);
        assert_eq!(decoded_limits(&body), [(4, 128), (0, 128)]);
        assert!(!credits.owed());
        assert_eq!(credits.flights, 2);
        credits.on_timeout();
        assert!(
            !credits.on_ack(12, 2, &[]),
            "old ACK cannot deliver a new limit"
        );
        assert!(credits.owed());
        assert!(credits.on_ack(20, 0, &[]));
        assert!(!credits.owed());
        assert!(!credits.in_flight());
        credits.on_timeout();
        assert!(!credits.owed());
        for id in [0, 4] {
            credits.remove(id);
        }
        assert!(credits.is_empty());
    }

    #[test]
    fn cancelled_cohorts_leave_no_output_or_flight_after_reuse() {
        let mut credits = StreamCredits::new(64);
        let mut body = Vec::new();
        for round in 0..6 {
            for n in 0..2048 {
                credits.update(n * 4, 32);
            }
            if round % 2 == 0 {
                for n in 0..2048 {
                    credits.remove(n * 4);
                }
            } else {
                for n in (0..2048).rev() {
                    credits.remove(n * 4);
                }
            }
            assert!(credits.is_empty());
            assert!(!credits.owed());
            assert!(!credits.in_flight());
            credits.write(&mut body, 1200, round);
            assert!(body.is_empty());
        }
        credits.update(0, 32);
        credits.write(&mut body, 4, 10);
        assert_eq!(decoded_limits(&body), [(0, 96)]);
        assert!(credits.on_ack(10, 0, &[]));
        assert!(!credits.in_flight());
    }

    #[test]
    fn repeated_loss_has_bounded_history_and_retains_recent_late_acks() {
        let mut credits = StreamCredits::new(64);
        credits.update(0, 32);
        let mut body = Vec::new();
        for pn in 0..100 {
            body.clear();
            credits.write(&mut body, 1200, pn);
            assert_eq!(credits.flights, 1);
            assert_eq!(credits.streams[&0].copies, ((pn + 1) as usize).min(COPIES));
            credits.on_timeout();
        }
        assert!(
            !credits.on_ack(0, 0, &[]),
            "forgotten ACK cannot invent delivery"
        );
        assert!(credits.owed());
        assert!(
            credits.on_ack(95, 0, &[]),
            "recent old copy still cancels retry"
        );
        assert!(!credits.owed());
        assert!(!credits.in_flight());
        assert_eq!(credits.limit(0), 96);
        println!(
            "StreamCredits={} Update={} copies={COPIES}",
            size_of::<StreamCredits>(),
            size_of::<Update>()
        );
    }

    #[test]
    fn one_stream_ack_or_fin_does_not_cancel_another() {
        let mut credits = StreamCredits::new(64);
        credits.update(0, 32);
        credits.update(4, 32);
        let mut body = Vec::new();
        credits.write(&mut body, 4, 10);
        body.clear();
        credits.write(&mut body, 4, 11);
        assert_eq!(credits.flights, 2);
        credits.on_timeout();
        assert!(credits.on_ack(10, 0, &[]));
        assert!(credits.owed());
        assert_eq!(credits.flights, 1);
        credits.remove(0);
        assert!(credits.owed());
        credits.remove(4);
        assert!(!credits.owed());
        assert!(!credits.in_flight());
        assert!(credits.is_empty());
    }

    #[test]
    fn stream_id_and_limit_encoding_respect_exact_room() {
        for id in [0, 64, 16384, 1 << 30, MAX_STREAM_OFFSET - 3] {
            let mut credits = StreamCredits::new(1 << 30);
            credits.update(id, 1 << 29);
            let need = 1 + varint_len(id) + 8;
            let mut body = vec![0; 11];
            credits.write(&mut body, 11 + need - 1, 10);
            assert_eq!(body.len(), 11);
            assert_eq!(credits.limit(id), 1 << 30);
            credits.write(&mut body, 11 + need, 11);
            assert_eq!(body.len(), 11 + need);
            assert_eq!(
                frame::Frames::new(&body[11..]).next().unwrap().unwrap(),
                frame::Frame::MaxStreamData {
                    id,
                    limit: (1 << 30) + (1 << 29)
                }
            );
        }
    }
}
