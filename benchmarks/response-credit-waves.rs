//! Bounded response-credit waves shared by the native driver and model tests.
//! Run with `rustc --edition=2024 --test response-credit-waves.rs`.
//!
//! The transport must verify ACKs against retained packet-copy identities before
//! calling the ACK methods. A response never implies a request or grant ACK.
//! Stream IDs are never reused. Retired streams have a known complete literal
//! response, so delayed duplicates can be checked without retaining their slots.

const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";
const ALL_BYTES: u32 = (1 << RESPONSE.len()) - 1;
const MAX_VARINT: u64 = (1 << 62) - 1;
const MAX_STREAMS: u64 = 1 << 60;
const MAX_SAMPLES: usize = 1 << 22;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Grants {
    Bytes(u64),
    // Two fragments, unlike the thirteen fragments produced by Bytes(2).
    TwoFragments,
    Full,
}
impl Grants {
    pub(crate) fn initial(self) -> Result<u64> {
        match self {
            Self::Bytes(n @ (1 | 2)) => Ok(n),
            Self::Bytes(_) => Err("unsupported byte increment"),
            Self::TwoFragments => Ok(1),
            Self::Full => Ok(25),
        }
    }
    pub(crate) fn next(self, limit: u64) -> Option<u64> {
        if limit == 25 {
            None
        } else {
            Some(match self {
                Self::Bytes(n) => (limit + n).min(25),
                Self::TwoFragments | Self::Full => 25,
            })
        }
    }
    pub(crate) fn contains(self, limit: u64) -> bool {
        match self {
            Self::Bytes(n) => (1..=25).contains(&limit) && (limit == 25 || limit.is_multiple_of(n)),
            Self::TwoFragments => limit == 1 || limit == 25,
            Self::Full => limit == 25,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) started: Option<u64>,
    pub(crate) completed: Option<u64>,
    pub(crate) seen: u32,
    pub(crate) fin: bool,
    pub(crate) limit: u64,
    pub(crate) grant_acked: u64,
    pub(crate) request_acked: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    pub(crate) stream: u64,
    pub(crate) started_ns: u64,
    pub(crate) completed_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    Pending,
    Complete,
    Duplicate,
    RetiredDuplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ready {
    Started { first: u64, count: usize },
    StreamCredit,
    DataCredit,
}

pub(crate) struct Waves {
    pub(crate) grants: Grants,
    pub(crate) window: usize,
    pub(crate) sample_budget: usize,
    pub(crate) request_bytes: u64,
    pub(crate) reserved_data: u64,
    pub(crate) max_data: u64,
    pub(crate) max_streams: u64,
    // Counts of client bidi streams, not encoded stream IDs.
    pub(crate) retired: u64,
    pub(crate) next: u64,
    pub(crate) slots: Vec<Slot>,
    pub(crate) samples: Vec<Sample>,
    pub(crate) late_duplicates: u64,
}
impl Waves {
    pub(crate) fn new(
        grants: Grants,
        window: usize,
        sample_budget: usize,
        request_bytes: u64,
        control_bytes: u64,
        max_data: u64,
        max_streams: u64,
    ) -> Result<Self> {
        grants.initial()?;
        if !(1..=512).contains(&window)
            || !(window..=MAX_SAMPLES).contains(&sample_budget)
            || request_bytes == 0
            || request_bytes > MAX_VARINT
            || control_bytes > max_data
            || max_data > MAX_VARINT
            || max_streams > MAX_STREAMS
        {
            return Err("invalid workload or transport limits");
        }
        Ok(Self {
            grants,
            window,
            sample_budget,
            request_bytes,
            reserved_data: control_bytes,
            max_data,
            max_streams,
            retired: 0,
            next: 0,
            slots: Vec::with_capacity(window),
            samples: Vec::with_capacity(sample_budget),
            late_duplicates: 0,
        })
    }
    pub(crate) fn max_data(&mut self, value: u64) -> Result<()> {
        if value > MAX_VARINT {
            return Err("invalid MAX_DATA");
        }
        self.max_data = self.max_data.max(value);
        Ok(())
    }
    pub(crate) fn max_streams(&mut self, value: u64) -> Result<()> {
        if value > MAX_STREAMS {
            return Err("invalid MAX_STREAMS");
        }
        self.max_streams = self.max_streams.max(value);
        Ok(())
    }
    pub(crate) fn begin(&mut self, count: usize) -> Result<Ready> {
        if !self.slots.is_empty() || count == 0 || count > self.window {
            return Err("active wave or invalid wave size");
        }
        if count > self.sample_budget - self.samples.len() {
            return Err("sample budget exhausted; no samples discarded");
        }
        let end = self
            .next
            .checked_add(count as u64)
            .ok_or("stream overflow")?;
        if end > MAX_STREAMS {
            return Err("stream ID space exhausted");
        }
        if end > self.max_streams {
            return Ok(Ready::StreamCredit);
        }
        let bytes = self
            .request_bytes
            .checked_mul(count as u64)
            .ok_or("data overflow")?;
        let end_data = self
            .reserved_data
            .checked_add(bytes)
            .ok_or("data overflow")?;
        if end_data > MAX_VARINT {
            return Err("connection data space exhausted");
        }
        if end_data > self.max_data {
            return Ok(Ready::DataCredit);
        }
        let limit = self.grants.initial()?;
        self.slots.extend((0..count).map(|_| Slot {
            started: None,
            completed: None,
            seen: 0,
            fin: false,
            limit,
            grant_acked: limit,
            request_acked: false,
        }));
        let first = self.next * 4;
        self.next = end;
        self.reserved_data = end_data;
        Ok(Ready::Started { first, count })
    }
    pub(crate) fn received_bytes(&self) -> u64 {
        self.retired * 25
            + self
                .slots
                .iter()
                .map(|s| u64::from(s.seen.count_ones()))
                .sum::<u64>()
    }
    pub(crate) fn index(&self, stream: u64) -> Result<Option<usize>> {
        if stream > MAX_VARINT || !stream.is_multiple_of(4) || stream / 4 >= self.next {
            return Err("unsolicited or invalid response stream");
        }
        if stream / 4 < self.retired {
            Ok(None)
        } else {
            Ok(Some((stream / 4 - self.retired) as usize))
        }
    }
    pub(crate) fn start(&mut self, stream: u64, now: u64) -> Result<()> {
        let i = self.index(stream)?.ok_or("cannot restart retired stream")?;
        if self.slots[i].started.is_some() {
            return Err("request started twice");
        }
        self.slots[i].started = Some(now);
        Ok(())
    }
    pub(crate) fn grant(&mut self, stream: u64, limit: u64) -> Result<()> {
        let i = self.index(stream)?.ok_or("cannot grant retired stream")?;
        let s = &mut self.slots[i];
        if s.started.is_none()
            || u64::from(s.seen.trailing_ones()) != s.limit
            || s.grant_acked != s.limit
            || self.grants.next(s.limit) != Some(limit)
        {
            return Err("grant before prefix/ACK or wrong grant generation");
        }
        s.limit = limit;
        Ok(())
    }
    pub(crate) fn ack_request(&mut self, stream: u64) -> Result<()> {
        if let Some(i) = self.index(stream)? {
            let s = &mut self.slots[i];
            if s.started.is_none() {
                return Err("ACK before request");
            }
            s.request_acked = true;
        }
        Ok(())
    }
    pub(crate) fn ack_grant(&mut self, stream: u64, limit: u64) -> Result<()> {
        let index = self.index(stream)?;
        if !self.grants.contains(limit) {
            return Err("unknown grant generation");
        }
        if let Some(i) = index {
            let s = &mut self.slots[i];
            if s.started.is_none() || limit > s.limit {
                return Err("ACK of unsent grant");
            }
            s.grant_acked = s.grant_acked.max(limit);
        }
        Ok(())
    }
    pub(crate) fn receive(
        &mut self,
        stream: u64,
        offset: u64,
        bytes: &[u8],
        fin: bool,
        now: u64,
    ) -> Result<Delivery> {
        let index = self.index(stream)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or("offset overflow")?;
        if end > 25 || bytes != &RESPONSE[offset as usize..end as usize] || (fin && end != 25) {
            return Err("wrong response bytes or FIN");
        }
        let Some(i) = index else {
            self.late_duplicates += 1;
            return Ok(Delivery::RetiredDuplicate);
        };
        let s = &mut self.slots[i];
        let start = s.started.ok_or("response before request")?;
        if now < start || end > s.limit {
            return Err("response before timestamp or beyond credit");
        }
        let mask = ((1u32 << bytes.len()) - 1) << offset;
        let duplicate = s.seen & mask == mask && (!fin || s.fin);
        s.seen |= mask;
        s.fin |= fin;
        if s.seen == ALL_BYTES && s.fin && s.completed.is_none() {
            s.completed = Some(now);
            Ok(Delivery::Complete)
        } else if duplicate {
            Ok(Delivery::Duplicate)
        } else {
            Ok(Delivery::Pending)
        }
    }
    pub(crate) fn retire(&mut self) -> Result<()> {
        if self.slots.is_empty()
            || self.slots.iter().any(|s| {
                s.seen != ALL_BYTES
                    || !s.fin
                    || s.completed.is_none()
                    || !s.request_acked
                    || s.grant_acked != 25
            })
        {
            return Err("incomplete response, sample, request ACK or grant ACK");
        }
        for (i, s) in self.slots.drain(..).enumerate() {
            self.samples.push(Sample {
                stream: (self.retired + i as u64) * 4,
                started_ns: s.started.unwrap(),
                completed_ns: s.completed.unwrap(),
            });
        }
        self.retired = self.next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn waves(grants: Grants, window: usize, total: usize) -> Waves {
        Waves::new(grants, window, total, 18, 5, MAX_VARINT, MAX_STREAMS).unwrap()
    }
    pub(crate) fn complete(w: &mut Waves, stream: u64, started: u64) {
        w.start(stream, started).unwrap();
        w.ack_request(stream).unwrap();
        let i = w.index(stream).unwrap().unwrap();
        let mut offset = 0;
        loop {
            let end = w.slots[i].limit;
            let got = w
                .receive(
                    stream,
                    offset,
                    &RESPONSE[offset as usize..end as usize],
                    end == 25,
                    started + end,
                )
                .unwrap();
            assert_eq!(
                got,
                if end == 25 {
                    Delivery::Complete
                } else {
                    Delivery::Pending
                }
            );
            if end == 25 {
                break;
            }
            let next = w.grants.next(end).unwrap();
            w.grant(stream, next).unwrap();
            w.ack_grant(stream, next).unwrap();
            offset = end;
        }
    }
    #[test]
    pub(crate) fn bounded_slots_exact_samples_and_late_duplicates_across_1024_waves() {
        for grants in [
            Grants::Bytes(1),
            Grants::Bytes(2),
            Grants::TwoFragments,
            Grants::Full,
        ] {
            let mut w = waves(grants, 8, 8192);
            let slots = w.slots.as_ptr();
            let samples = w.samples.as_ptr();
            for wave in 0..1024 {
                let first = wave * 32;
                assert_eq!(w.begin(8).unwrap(), Ready::Started { first, count: 8 });
                // Complete out of order; storage reuse must not change identity.
                for i in (0..8).rev() {
                    complete(&mut w, first + i * 4, first + i);
                }
                if wave > 0 {
                    let before = w.samples.clone();
                    for id in [0, first - 4] {
                        assert_eq!(
                            w.receive(id, 0, RESPONSE, true, first + 99).unwrap(),
                            Delivery::RetiredDuplicate
                        );
                        w.ack_request(id).unwrap();
                        w.ack_grant(id, 25).unwrap();
                    }
                    assert_eq!(w.samples, before);
                }
                w.retire().unwrap();
                assert_eq!(w.slots.as_ptr(), slots);
                assert_eq!(w.samples.as_ptr(), samples);
                assert_eq!(w.samples.len(), (wave as usize + 1) * 8);
                assert_eq!(w.received_bytes(), (wave + 1) * 8 * 25);
            }
            assert_eq!(w.late_duplicates, 2046);
            for (i, sample) in w.samples.iter().enumerate() {
                assert_eq!(sample.stream, i as u64 * 4);
                assert_eq!(sample.completed_ns - sample.started_ns, 25);
            }
            assert!(w.begin(1).is_err());
            assert_eq!(w.samples.len(), 8192);
        }
    }
    #[test]
    pub(crate) fn blocked_credit_does_not_consume_ids_bytes_or_sample_capacity() {
        let mut w = Waves::new(Grants::Full, 2, 4, 18, 5, 40, 1).unwrap();
        assert_eq!(w.begin(2).unwrap(), Ready::StreamCredit);
        assert_eq!((w.next, w.reserved_data), (0, 5));
        w.max_streams(2).unwrap();
        assert_eq!(w.begin(2).unwrap(), Ready::DataCredit);
        assert_eq!((w.next, w.reserved_data), (0, 5));
        w.max_data(41).unwrap();
        assert_eq!(w.begin(2).unwrap(), Ready::Started { first: 0, count: 2 });
        assert_eq!(w.reserved_data, 41);
        assert!(w.begin(1).is_err());
        complete(&mut w, 4, 10);
        complete(&mut w, 0, 20);
        w.retire().unwrap();
        w.max_streams(1).unwrap(); // Reordered older updates cannot revoke credit.
        w.max_data(0).unwrap();
        assert_eq!((w.max_streams, w.max_data), (2, 41));
        assert_eq!(w.begin(2).unwrap(), Ready::StreamCredit);
        w.max_streams(4).unwrap();
        assert_eq!(w.begin(2).unwrap(), Ready::DataCredit);
        w.max_data(77).unwrap();
        assert_eq!(w.begin(2).unwrap(), Ready::Started { first: 8, count: 2 });
    }
    #[test]
    pub(crate) fn no_retirement_without_fin_bytes_request_ack_and_final_grant_ack() {
        let mut w = waves(Grants::TwoFragments, 1, 2);
        w.begin(1).unwrap();
        w.start(0, 10).unwrap();
        assert!(w.grant(0, 25).is_err());
        w.receive(0, 0, &RESPONSE[..1], false, 11).unwrap();
        w.grant(0, 25).unwrap();
        assert!(w.grant(0, 25).is_err());
        assert!(w.ack_grant(0, 2).is_err());
        // FIN arrives across a gap, and must not complete the response.
        assert_eq!(
            w.receive(0, 24, &RESPONSE[24..], true, 12).unwrap(),
            Delivery::Pending
        );
        assert!(w.retire().is_err());
        assert_eq!(
            w.receive(0, 1, &RESPONSE[1..24], false, 13).unwrap(),
            Delivery::Complete
        );
        assert!(w.retire().is_err());
        w.ack_request(0).unwrap();
        assert!(w.retire().is_err());
        w.ack_grant(0, 25).unwrap();
        w.ack_grant(0, 1).unwrap();
        assert_eq!(
            w.receive(0, 0, RESPONSE, true, 90).unwrap(),
            Delivery::Duplicate
        );
        w.retire().unwrap();
        assert_eq!(
            w.samples,
            [Sample {
                stream: 0,
                started_ns: 10,
                completed_ns: 13
            }]
        );
        assert!(w.retire().is_err());
        w.begin(1).unwrap();
        w.start(4, 100).unwrap();
        // Old successes must not acknowledge the new slot, even after reuse.
        w.ack_request(0).unwrap();
        w.ack_grant(0, 25).unwrap();
        assert!(!w.slots[0].request_acked);
        assert_eq!(w.slots[0].grant_acked, 1);
        assert!(w.retire().is_err());
        assert_eq!(w.samples.len(), 1);
    }
    #[test]
    pub(crate) fn full_response_cannot_substitute_for_the_request_packet_ack() {
        let mut w = waves(Grants::Full, 1, 2);
        w.begin(1).unwrap();
        w.start(0, 10).unwrap();
        assert_eq!(
            w.receive(0, 0, RESPONSE, true, 20).unwrap(),
            Delivery::Complete
        );
        // Isolate the request ACK gate: no dynamic grant is outstanding here.
        assert!(w.retire().is_err());
        assert_eq!(w.samples.len(), 0);
        assert!(w.begin(1).is_err());
        w.ack_request(0).unwrap();
        w.retire().unwrap();
        assert_eq!(
            w.samples,
            [Sample {
                stream: 0,
                started_ns: 10,
                completed_ns: 20
            }]
        );
    }
    #[test]
    pub(crate) fn reject_foreign_ids_invalid_retired_bytes_and_unsent_grants() {
        let mut w = waves(Grants::Bytes(1), 1, 2);
        w.begin(1).unwrap();
        assert!(w.receive(0, 0, &RESPONSE[..1], false, 0).is_err());
        assert!(w.ack_request(0).is_err());
        complete(&mut w, 0, 10);
        w.retire().unwrap();
        w.begin(1).unwrap();
        w.start(4, 100).unwrap();
        assert!(w.start(4, 105).is_err());
        assert_eq!(w.slots[0].started, Some(100));
        assert!(w.ack_grant(4, 25).is_err());
        for id in [1, 2, 3, 8, MAX_VARINT, u64::MAX] {
            assert!(w.receive(id, 0, &RESPONSE[..1], false, 110).is_err());
            assert!(w.ack_request(id).is_err());
            assert!(w.ack_grant(id, 1).is_err());
        }
        for id in [0, 4] {
            assert!(w.receive(id, 0, b"x", false, 110).is_err());
            assert!(w.receive(id, 0, &RESPONSE[..1], true, 110).is_err());
            assert!(w.receive(id, u64::MAX, b"x", false, 110).is_err());
            assert!(w.receive(id, 26, b"", false, 110).is_err());
        }
        assert!(w.receive(4, 0, &RESPONSE[..2], false, 110).is_err());
        assert_eq!(w.slots[0].seen, 0);
        assert_eq!(w.samples.len(), 1);
        assert_eq!(w.late_duplicates, 0);
    }
    #[test]
    pub(crate) fn explicit_identity_data_and_sample_limits_never_wrap_or_discard() {
        let mut w = waves(Grants::Full, 1, 1);
        assert!(w.max_data(MAX_VARINT + 1).is_err());
        assert!(w.max_streams(MAX_STREAMS + 1).is_err());
        w.next = MAX_STREAMS;
        assert!(w.begin(1).is_err());
        w.next = 0;
        w.reserved_data = MAX_VARINT - 17;
        assert!(w.begin(1).is_err());
        assert_eq!(w.next, 0);
        w.reserved_data = 5;
        w.begin(1).unwrap();
        complete(&mut w, 0, 0);
        w.retire().unwrap();
        let sample = w.samples.clone();
        assert!(w.begin(1).is_err());
        assert_eq!(w.samples, sample);
        assert!(Waves::new(Grants::Bytes(0), 1, 1, 18, 5, 100, 1).is_err());
        assert!(Waves::new(Grants::Full, 513, 1024, 18, 5, 100, 1).is_err());
        assert!(Waves::new(Grants::Full, 1, MAX_SAMPLES + 1, 18, 5, 100, 1).is_err());
    }
    #[test]
    pub(crate) fn every_missing_byte_and_fin_preserves_first_completion_timestamp() {
        for missing in 0..25 {
            let mut w = waves(Grants::Full, 1, 1);
            w.begin(1).unwrap();
            w.start(0, 50).unwrap();
            w.ack_request(0).unwrap();
            for i in (0..25).rev().filter(|&i| i != missing) {
                assert_eq!(
                    w.receive(0, i, &RESPONSE[i as usize..i as usize + 1], false, 100)
                        .unwrap(),
                    Delivery::Pending
                );
            }
            assert_eq!(w.received_bytes(), 24);
            assert!(w.retire().is_err());
            assert_eq!(
                w.receive(
                    0,
                    missing,
                    &RESPONSE[missing as usize..missing as usize + 1],
                    false,
                    101
                )
                .unwrap(),
                Delivery::Pending
            );
            assert_eq!(w.received_bytes(), 25);
            assert!(w.retire().is_err());
            assert_eq!(
                w.receive(0, 25, b"", true, 102).unwrap(),
                Delivery::Complete
            );
            assert_eq!(
                w.receive(0, 0, RESPONSE, true, 103).unwrap(),
                Delivery::Duplicate
            );
            w.retire().unwrap();
            assert_eq!(w.samples[0].completed_ns, 102);
            assert_eq!(w.samples[0].started_ns, 50);
        }
    }
}
