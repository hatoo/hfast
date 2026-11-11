//! Bounded receive-side MAX_DATA ledger. Control stream 3 reserves three bytes.
//! Wire offsets consume credit even across gaps or locally discarded packets;
//! only delivered unique bytes permit the next grant. Packet-copy authentication
//! belongs to the driver, which must call ack only for a retained sent flight.
type Result<T> = std::result::Result<T, &'static str>;
use crate::waves::{Grants, MAX_WINDOW, trace_limit};
const ALL: u32 = (1 << 25) - 1;

#[derive(Default)]
struct Slot {
    highest: u64,
    wire: u32,
    delivered: u32,
    request_acked: bool,
}

pub(crate) struct ConnectionCredit {
    pub(crate) step: u64,
    pub(crate) limit: u64,
    pub(crate) acked: u64,
    pub(crate) charged: u64,
    pub(crate) wire_unique: u64,
    pub(crate) received: u64,
    pub(crate) completed_waves: u64,
    pub(crate) events: Vec<(u8, u64, u64, u64)>,
    window: usize,
    total: usize,
    retired: u64,
    end: u64,
    slots: Vec<Slot>,
    event_limit: usize,
}
impl ConnectionCredit {
    pub(crate) fn new(step: u64, window: usize, total: usize, trace: bool) -> Result<Self> {
        if ![1, 2, 25].contains(&step)
            || !(1..=MAX_WINDOW).contains(&window)
            || !(window..=1 << 22).contains(&total)
        {
            return Err("invalid connection-credit workload");
        }
        Ok(Self {
            step,
            limit: 3,
            acked: 3,
            charged: 3,
            wire_unique: 3,
            received: 3,
            completed_waves: 0,
            events: Vec::new(),
            window,
            total,
            retired: 0,
            end: 3,
            slots: Vec::with_capacity(window),
            event_limit: if trace {
                trace_limit(
                    total,
                    window,
                    if step == 25 {
                        Grants::Full
                    } else {
                        Grants::Bytes(step)
                    },
                    true,
                )?
            } else {
                0
            },
        })
    }
    fn event(&mut self, kind: u8, a: u64, b: u64, c: u64) -> Result<()> {
        if self.event_limit != 0 {
            if self.events.len() >= self.event_limit {
                return Err("connection transcript exhausted");
            }
            self.events.push((kind, a, b, c));
        }
        Ok(())
    }
    pub(crate) fn settled(&self) -> bool {
        self.limit == self.end && self.received == self.limit && self.acked == self.limit
    }
    pub(crate) fn begin(&mut self, first: u64, count: usize) -> Result<()> {
        if !self.slots.is_empty()
            || !self.settled()
            || first != self.retired * 4
            || count == 0
            || count > self.window
            || self.retired + count as u64 > self.total as u64
        {
            return Err("invalid connection wave");
        }
        self.event(0, first, count as u64, 0)?;
        self.end = 3 + (self.retired + count as u64) * 25;
        self.slots.resize_with(count, Slot::default);
        Ok(())
    }
    fn index(&self, stream: u64) -> Result<Option<usize>> {
        if !stream.is_multiple_of(4) || stream / 4 >= self.retired + self.slots.len() as u64 {
            return Err("unsolicited connection-credit stream");
        }
        Ok((stream / 4 >= self.retired).then(|| (stream / 4 - self.retired) as usize))
    }
    pub(crate) fn request_ack(&mut self, stream: u64) -> Result<()> {
        if let Some(i) = self.index(stream)? {
            self.event(6, stream, 0, 0)?;
            self.slots[i].request_acked = true;
        }
        Ok(())
    }
    pub(crate) fn next(&self) -> Option<u64> {
        (self.limit < self.end
            && self.received == self.limit
            && self.acked == self.limit
            && self.slots.iter().all(|s| s.request_acked))
        .then(|| (self.limit + self.step).min(self.end))
    }
    pub(crate) fn grant(&mut self, value: u64) -> Result<()> {
        if self.next() != Some(value) {
            return Err("connection grant before bytes/request/grant ACK or wrong generation");
        }
        self.event(1, value, 0, 0)?;
        self.limit = value;
        Ok(())
    }
    pub(crate) fn ack(&mut self, value: u64) -> Result<()> {
        if value < 3 || (value > self.acked && value != self.limit) {
            return Err("ACK of unsent connection grant");
        }
        self.event(2, value, 0, 0)?;
        self.acked = self.acked.max(value);
        Ok(())
    }
    fn mask(offset: u64, len: usize) -> Result<(u64, u32)> {
        let end = offset.checked_add(len as u64).ok_or("offset overflow")?;
        if end > 25 {
            return Err("invalid connection-credit byte range");
        }
        Ok((end, ((1u32 << len) - 1) << offset))
    }
    pub(crate) fn wire(&mut self, stream: u64, offset: u64, len: usize) -> Result<()> {
        let (end, mask) = Self::mask(offset, len)?;
        let index = self.index(stream)?;
        if let Some(i) = index {
            let delta = end.saturating_sub(self.slots[i].highest);
            if self.charged + delta > self.limit {
                return Err("wire connection credit exceeded");
            }
            self.event(3, stream, offset, len as u64)?;
            let s = &mut self.slots[i];
            self.charged += delta;
            self.wire_unique += u64::from((mask & !s.wire).count_ones());
            s.highest = s.highest.max(end);
            s.wire |= mask;
        } else {
            self.event(3, stream, offset, len as u64)?;
        }
        Ok(())
    }
    pub(crate) fn receive(&mut self, stream: u64, offset: u64, len: usize) -> Result<()> {
        let (_, mask) = Self::mask(offset, len)?;
        if let Some(i) = self.index(stream)? {
            if self.slots[i].wire & mask != mask {
                return Err("delivery without authenticated wire bytes");
            }
            self.event(4, stream, offset, len as u64)?;
            let s = &mut self.slots[i];
            self.received += u64::from((mask & !s.delivered).count_ones());
            s.delivered |= mask;
        } else {
            self.event(4, stream, offset, len as u64)?;
        }
        Ok(())
    }
    pub(crate) fn retire(&mut self) -> Result<()> {
        if self.slots.is_empty()
            || !self.settled()
            || self
                .slots
                .iter()
                .any(|s| s.delivered != ALL || !s.request_acked)
        {
            return Err("unsettled connection wave");
        }
        self.event(5, self.retired * 4, self.slots.len() as u64, 0)?;
        self.retired += self.slots.len() as u64;
        self.slots.clear();
        self.completed_waves += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_waves_exact_unique_bytes_and_every_ack_gate() {
        for step in [1, 2, 25] {
            for window in [1, 16, 511, 512, 513, 1024, 4096] {
                let total = 2 * window + 1;
                let mut c = ConnectionCredit::new(step, window, total, false).unwrap();
                let capacity = c.slots.capacity();
                while c.retired < total as u64 {
                    let count = window.min(total - c.retired as usize);
                    let first = c.retired * 4;
                    c.begin(first, count).unwrap();
                    assert_eq!(c.next(), None);
                    for i in 0..count {
                        c.request_ack(first + i as u64 * 4).unwrap();
                    }
                    while let Some(n) = c.next() {
                        let start = c.limit - 3;
                        c.grant(n).unwrap();
                        assert!(c.grant(n).is_err());
                        assert_eq!(c.next(), None);
                        for byte in start..n - 3 {
                            let (stream, offset) = (byte / 25 * 4, byte % 25);
                            c.wire(stream, offset, 1).unwrap();
                            c.wire(stream, offset, 1).unwrap();
                            c.receive(stream, offset, 1).unwrap();
                            c.receive(stream, offset, 1).unwrap();
                        }
                        assert_eq!(c.next(), None); // response does not ACK a grant
                        assert!(c.ack(n + 1).is_err());
                        c.ack(n).unwrap();
                        c.ack(n).unwrap();
                        c.ack(3).unwrap();
                    }
                    c.retire().unwrap();
                    // Old response data cannot consume credit in the new wave.
                    c.wire(first, 0, 25).unwrap();
                    c.receive(first, 0, 25).unwrap();
                }
                assert_eq!(c.received, 3 + total as u64 * 25);
                assert_eq!(
                    (c.limit, c.acked, c.charged, c.wire_unique),
                    (c.received, c.received, c.received, c.received)
                );
                assert_eq!(c.slots.capacity(), capacity);
                assert!(c.events.is_empty());
                assert_eq!(c.completed_waves, 3);
            }
        }
    }
    #[test]
    fn gaps_drops_and_overlaps_do_not_create_credit() {
        let mut c = ConnectionCredit::new(25, 2, 2, false).unwrap();
        c.begin(0, 2).unwrap();
        c.request_ack(0).unwrap();
        c.request_ack(4).unwrap();
        assert!(c.wire(0, 0, 1).is_err()); // zero response credit
        c.grant(28).unwrap();
        c.ack(28).unwrap();
        c.wire(0, 20, 5).unwrap(); // 25 credit, only 5 unique bytes
        c.receive(0, 20, 5).unwrap();
        assert_eq!((c.charged, c.received), (28, 8));
        assert!(c.wire(4, 0, 1).is_err());
        assert_eq!(c.next(), None);
        c.wire(0, 0, 21).unwrap(); // packet discarded locally
        assert_eq!(c.next(), None);
        c.wire(0, 0, 21).unwrap();
        c.receive(0, 0, 21).unwrap();
        assert_eq!(c.next(), Some(53));
        assert!(c.retire().is_err());
        assert!(c.begin(8, 1).is_err());
        assert!(c.wire(8, 0, 1).is_err());
        assert!(c.wire(0, u64::MAX, 1).is_err());
        assert!(c.wire(0, 25, 1).is_err());
        assert!(c.receive(4, 0, 1).is_err());
    }
    #[test]
    fn stale_ack_cannot_settle_a_new_grant() {
        let mut c = ConnectionCredit::new(1, 1, 1, true).unwrap();
        c.begin(0, 1).unwrap();
        c.request_ack(0).unwrap();
        c.grant(4).unwrap();
        c.wire(0, 0, 1).unwrap();
        c.receive(0, 0, 1).unwrap();
        c.ack(4).unwrap();
        c.grant(5).unwrap();
        c.ack(4).unwrap();
        c.wire(0, 1, 1).unwrap();
        c.receive(0, 1, 1).unwrap();
        assert_eq!(c.next(), None);
        c.ack(5).unwrap();
        assert_eq!(c.next(), Some(6));
        assert_eq!(c.events.iter().filter(|e| e.0 == 1).count(), 2);
    }
    #[test]
    fn invalid_workloads_fail_explicitly() {
        for step in [0, 3, u64::MAX] {
            assert!(ConnectionCredit::new(step, 1, 1, false).is_err());
        }
        assert!(ConnectionCredit::new(1, 0, 1, false).is_err());
        assert!(ConnectionCredit::new(1, MAX_WINDOW + 1, MAX_WINDOW + 1, false).is_err());
        assert!(ConnectionCredit::new(1, 2, 1, false).is_err());
    }

    #[test]
    fn transcript_exhaustion_preserves_existing_evidence_and_credit() {
        let mut c = ConnectionCredit::new(1, 513, 513, true).unwrap();
        c.begin(0, 513).unwrap();
        for sid in (0..513 * 4).step_by(4) {
            c.request_ack(sid).unwrap();
        }
        // Exhaust with duplicate authenticated wire events, not lost samples.
        c.grant(4).unwrap();
        c.wire(0, 0, 1).unwrap();
        while c.events.len() < c.event_limit {
            c.wire(0, 0, 1).unwrap();
        }
        let before = (c.limit, c.charged, c.received, c.events.len());
        assert_eq!(c.receive(0, 0, 1), Err("connection transcript exhausted"));
        assert_eq!((c.limit, c.charged, c.received, c.events.len()), before);
        assert_eq!(c.events[0], (0, 0, 513, 0));
        assert!(ConnectionCredit::new(1, 4096, 8193, true).is_err());
        assert!(ConnectionCredit::new(1, 4096, 8193, false).is_ok());
    }
}
