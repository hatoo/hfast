//! Peer receive credit. Ordinary replies keep the single-frame path; only
//! credit-fragmented replies allocate range recovery state.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

// The fixed messages fit in byte-sized offsets. Changing their size must not
// silently truncate either flow-control accounting or RESET_STREAM final sizes.
const _: () = assert!(RESPONSE.len() < u8::MAX as usize);
const _: () = assert!(CONTROL_PRELUDE.len() < u8::MAX as usize);
const MAX_COPIES: usize = 8;

#[derive(Default)]
pub(super) struct SendCredit {
    limit: u64,
    pub sent: u64,
    pub control_allowed: bool,
    control_limit: u8,
    control_sent: u8,
    control_fragments: Option<Box<Fragments>>,
    pub responses: BTreeMap<u64, Fragments>,
    pub blocked: BTreeSet<u64>,
}

impl SendCredit {
    pub fn initialize(&mut self, peer: &transport::Peer) {
        self.limit = peer.initial_max_data;
        self.control_limit = peer
            .initial_max_stream_data_uni
            .min(CONTROL_PRELUDE.len() as u64) as u8;
        self.control_allowed = peer.initial_max_streams_uni > 0;
    }

    pub fn available(&self) -> u64 {
        self.limit.saturating_sub(self.sent)
    }

    pub fn in_flight(&self) -> bool {
        self.control_fragments
            .as_ref()
            .is_some_and(|f| !f.flights.is_empty())
            || self.responses.values().any(|f| !f.flights.is_empty())
    }
}

struct RangeFlight {
    start: u8,
    end: u8,
    delivery: ControlFlight,
}

impl RangeFlight {
    fn write(&mut self, id: u64, data: &[u8], fin: bool, body: &mut Vec<u8>, pn: u64) {
        frame::put_stream(
            body,
            id,
            u64::from(self.start),
            fin && self.end as usize == data.len(),
            &data[self.start as usize..self.end as usize],
        );
        // Bounded history still lets a late original ACK cancel a probe. If
        // an ancient copy is forgotten, a newer copy remains recoverable.
        if self.delivery.sent_in.len() == MAX_COPIES {
            self.delivery.sent_in.remove(0);
        }
        self.delivery.sent(pn);
    }

    fn fits(&self, id: u64, used: usize, room: usize) -> bool {
        let len = (self.end - self.start) as usize;
        used + frame::stream_overhead(id, u64::from(self.start), len) + len <= room
    }
}

#[derive(Default)]
pub(super) struct Fragments {
    flights: Vec<RangeFlight>,
}

impl Fragments {
    fn pending(&self) -> bool {
        self.flights.iter().any(|f| f.delivery.pending)
    }

    fn on_ack(&mut self, largest: u64, first_range: u64, rest: &[u8]) -> bool {
        let before = self.flights.len();
        self.flights
            .retain_mut(|f| !f.delivery.on_ack(largest, first_range, rest));
        self.flights.len() < before
    }

    fn on_timeout(&mut self) {
        for flight in &mut self.flights {
            flight.delivery.on_timeout();
        }
    }

    /// Emit exact lost ranges before fresh bytes. Returns whether packet room
    /// (rather than credit) prevents more output. `sent` is never rewound.
    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        id: u64,
        data: &[u8],
        fin: bool,
        sent: &mut u8,
        limit: u8,
        available: u64,
        body: &mut Vec<u8>,
        room: usize,
        pn: u64,
    ) -> bool {
        for flight in &mut self.flights {
            if flight.delivery.pending {
                if !flight.fits(id, body.len(), room) {
                    return true;
                }
                flight.write(id, data, fin, body, pn);
            }
        }
        let fresh = u64::from(limit.saturating_sub(*sent)).min(available) as u8;
        if fresh != 0 {
            let mut flight = RangeFlight {
                start: *sent,
                end: *sent + fresh,
                delivery: ControlFlight::new(),
            };
            if !flight.fits(id, body.len(), room) {
                return true;
            }
            flight.write(id, data, fin, body, pn);
            *sent = flight.end;
            self.flights.push(flight);
        }
        false
    }
}

impl Connection {
    pub(super) fn queue_response(&mut self, id: u64) {
        if let Some(req) = self.stream_mut(id)
            && req.answered
            && !req.stopped
            && !req.send_done
            && !req.queued
        {
            req.queued = true;
            self.ready.push(id);
        }
    }

    pub(super) fn on_max_data(&mut self, limit: u64) {
        if limit <= self.send_credit.limit {
            return;
        }
        self.send_credit.limit = limit;
        while let Some(id) = self.send_credit.blocked.pop_first() {
            self.queue_response(id);
        }
    }

    pub(super) fn on_max_stream_data(&mut self, id: u64, limit: u64) {
        if id == CONTROL_STREAM {
            self.send_credit.control_limit = self
                .send_credit
                .control_limit
                .max(limit.min(CONTROL_PRELUDE.len() as u64) as u8);
        } else if let Some(req) = self.stream_mut(id) {
            let limit = limit.min(RESPONSE.len() as u64) as u8;
            if limit > req.send_limit {
                req.send_limit = limit;
                if req.sent < limit {
                    self.send_credit.blocked.remove(&id);
                    self.queue_response(id);
                }
            }
        }
    }

    pub(super) fn control_sendable(&self) -> bool {
        let credit = &self.send_credit;
        if !credit.control_allowed {
            return false;
        }
        let fresh = credit.control_sent < credit.control_limit && credit.available() > 0;
        if let Some(fragments) = &credit.control_fragments {
            fragments.pending() || fresh
        } else {
            self.control.pending && (credit.control_sent > 0 || fresh)
        }
    }

    pub(super) fn write_control(&mut self, body: &mut Vec<u8>, room: usize, pn: u64) {
        if !self.control_sendable() {
            return;
        }
        let credit = &mut self.send_credit;
        let available = credit.available();
        if credit.control_fragments.is_none()
            && (credit.control_sent > 0
                || (credit.control_limit as usize == CONTROL_PRELUDE.len()
                    && available >= CONTROL_PRELUDE.len() as u64))
        {
            let need = frame::stream_overhead(CONTROL_STREAM, 0, CONTROL_PRELUDE.len())
                + CONTROL_PRELUDE.len();
            if body.len() + need <= room {
                frame::put_stream(body, CONTROL_STREAM, 0, false, CONTROL_PRELUDE);
                credit.sent += (CONTROL_PRELUDE.len() - credit.control_sent as usize) as u64;
                credit.control_sent = CONTROL_PRELUDE.len() as u8;
                self.control.sent(pn);
            }
            return;
        }
        self.control.pending = false;
        let fragments = credit
            .control_fragments
            .get_or_insert_with(Default::default);
        let before = credit.control_sent;
        fragments.write(
            CONTROL_STREAM,
            CONTROL_PRELUDE,
            false,
            &mut credit.control_sent,
            credit.control_limit,
            available,
            body,
            room,
            pn,
        );
        credit.sent += u64::from(credit.control_sent - before);
    }

    /// At most one ready entry per response. Stream-blocked responses await
    /// their own grant; only connection-blocked IDs are visited on MAX_DATA.
    pub(super) fn write_partial_response(
        &mut self,
        id: u64,
        body: &mut Vec<u8>,
        room: usize,
        pn: u64,
    ) -> bool {
        let i = ((id >> 2) - self.base_stream) as usize;
        let StreamSlot::Active(req) = &mut self.streams[i] else {
            unreachable!()
        };
        req.partial = true;
        let available = self.send_credit.available();
        let fragments = self.send_credit.responses.entry(id).or_default();
        let before = req.sent;
        let full = fragments.write(
            id,
            RESPONSE,
            true,
            &mut req.sent,
            req.send_limit,
            available,
            body,
            room,
            pn,
        );
        self.send_credit.sent += u64::from(req.sent - before);
        if !full {
            req.queued = false;
            self.ready.pop();
            if req.sent < req.send_limit {
                self.send_credit.blocked.insert(id);
            }
        }
        full
    }

    pub(super) fn on_send_credit_ack(
        &mut self,
        largest: u64,
        first_range: u64,
        rest: &[u8],
    ) -> bool {
        let mut progress = false;
        if let Some(control) = &mut self.send_credit.control_fragments {
            progress |= control.on_ack(largest, first_range, rest);
            if control.flights.is_empty()
                && self.send_credit.control_sent as usize == CONTROL_PRELUDE.len()
            {
                self.send_credit.control_fragments = None;
            }
        }
        if self.send_credit.responses.is_empty() {
            return progress;
        }
        let available = self.send_credit.available();
        let mut retired = false;
        self.send_credit.responses.retain(|&id, fragments| {
            progress |= fragments.on_ack(largest, first_range, rest);
            let i = ((id >> 2) - self.base_stream) as usize;
            let StreamSlot::Active(req) = &mut self.streams[i] else {
                unreachable!()
            };
            if req.sent as usize == RESPONSE.len() && fragments.flights.is_empty() {
                req.send_done = true;
                req.queued = false;
                if req.fin {
                    self.streams[i] = StreamSlot::Complete;
                    self.finished += 1;
                    retired = true;
                }
                self.send_credit.blocked.remove(&id);
                return false;
            }
            let sendable = fragments.pending() || (req.sent < req.send_limit && available > 0);
            if sendable && !req.queued {
                req.queued = true;
                self.ready.push(id);
            } else if !sendable {
                req.queued = false;
            }
            true
        });
        // A late ACK may cancel a queued retransmission. Do not leave it
        // making wants_send report work after every credited byte is ACKed.
        self.ready.retain(|&id| {
            matches!(self.streams.get(((id >> 2) - self.base_stream) as usize),
            Some(StreamSlot::Active(req)) if req.queued)
        });
        if retired {
            self.retire();
        }
        progress
    }

    pub(super) fn on_send_credit_timeout(&mut self) {
        if let Some(control) = &mut self.send_credit.control_fragments {
            control.on_timeout();
        }
        for (&id, fragments) in &mut self.send_credit.responses {
            fragments.on_timeout();
            if fragments.pending() {
                let StreamSlot::Active(req) =
                    &mut self.streams[((id >> 2) - self.base_stream) as usize]
                else {
                    unreachable!()
                };
                if !req.queued {
                    req.queued = true;
                    self.ready.push(id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytewise_flight_history_is_bounded_and_sparse_acks_cancel_each_range() {
        let mut fragments = Fragments::default();
        let mut sent = 0;
        let mut body = Vec::new();
        let mut pn = 0;
        for end in 1..=RESPONSE.len() as u8 {
            assert!(!fragments.write(0, RESPONSE, true, &mut sent, end, 1, &mut body, 4096, pn));
            assert_eq!(sent, end);
            pn += 1;
        }
        assert_eq!(fragments.flights.len(), RESPONSE.len());
        for _ in 0..20 {
            fragments.on_timeout();
            body.clear();
            assert!(!fragments.write(
                0,
                RESPONSE,
                true,
                &mut sent,
                RESPONSE.len() as u8,
                0,
                &mut body,
                4096,
                pn
            ));
            pn += 1;
            assert!(
                fragments
                    .flights
                    .iter()
                    .all(|f| f.delivery.sent_in.len() <= MAX_COPIES)
            );
        }
        assert!(
            !fragments.on_ack(0, 0, &[]),
            "forgotten copies cannot acknowledge newer data"
        );
        fragments.on_timeout();
        assert!(fragments.pending());
        assert!(fragments.on_ack(pn - 2, 0, &[]));
        assert!(fragments.flights.is_empty());
    }
}
