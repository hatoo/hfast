//! Exact interval, ACK and upload accounting for the disposable native peer.
use crate::quic::varint::{get_varint, put_varint};
use anyhow::{Context, Result, ensure};

pub const MAX_VARINT: u64 = (1 << 62) - 1;
pub const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";
const MAX_RANGES: usize = 16384;

#[derive(Default, Clone, Debug)]
pub struct Ranges(pub Vec<(u64, u64)>);
impl Ranges {
    pub fn contains(&self, value: u64) -> bool {
        let i = self.0.partition_point(|&(lo, _)| lo <= value);
        i != 0 && value <= self.0[i - 1].1
    }
    pub fn insert(&mut self, mut lo: u64, mut hi: u64) -> Result<()> {
        ensure!(lo <= hi && hi <= MAX_VARINT, "invalid interval");
        let first = self.0.partition_point(|&(_, end)| end + 1 < lo);
        let mut end = first;
        while end < self.0.len() && self.0[end].0 <= hi + 1 {
            lo = lo.min(self.0[end].0);
            hi = hi.max(self.0[end].1);
            end += 1;
        }
        ensure!(
            self.0.len() + 1 - (end - first) <= MAX_RANGES,
            "range budget exhausted; no history discarded"
        );
        self.0.splice(first..end, [(lo, hi)]);
        Ok(())
    }
    pub fn count(&self) -> u64 {
        self.0.iter().map(|(lo, hi)| hi - lo + 1).sum()
    }
    pub fn covers(&self, end: u64) -> bool {
        end == 0
            || self
                .0
                .first()
                .is_some_and(|&(lo, hi)| lo == 0 && hi == end - 1)
    }
}

// RFC 9000 19.3.1: next largest = previous smallest - gap - 2.
// Validate arithmetic explicitly: the production iterator intentionally keeps
// a valid prefix on malformed input, which is insufficient for an oracle.
pub fn decode_ack(largest: u64, first: u64, rest: &[u8], count: u64) -> Result<Ranges> {
    ensure!(largest <= MAX_VARINT, "invalid largest ACK");
    let mut lo = largest
        .checked_sub(first)
        .context("ACK first range underflow")?;
    let mut ranges = vec![(lo, largest)];
    let mut pos = 0;
    for _ in 0..count {
        let (gap, n) = get_varint(&rest[pos..]).context("truncated ACK gap")?;
        pos += n;
        let (len, n) = get_varint(&rest[pos..]).context("truncated ACK range")?;
        pos += n;
        let hi = lo
            .checked_sub(gap)
            .and_then(|v| v.checked_sub(2))
            .context("ACK gap underflow")?;
        lo = hi.checked_sub(len).context("ACK range underflow")?;
        ranges.push((lo, hi));
        ensure!(ranges.len() <= MAX_RANGES, "ACK range budget exhausted");
    }
    ensure!(pos == rest.len(), "extra ACK range bytes");
    ranges.reverse();
    Ok(Ranges(ranges))
}

fn encode(ranges: &[(u64, u64)]) -> Vec<u8> {
    let mut bytes = vec![2];
    let &(lo, hi) = ranges.last().unwrap();
    put_varint(&mut bytes, hi);
    put_varint(&mut bytes, 0); // deliberate immediate ACK schedule, not RTT measurement
    put_varint(&mut bytes, ranges.len() as u64 - 1);
    put_varint(&mut bytes, hi - lo);
    let mut previous = lo;
    for &(lo, hi) in ranges.iter().rev().skip(1) {
        put_varint(&mut bytes, previous - hi - 2);
        put_varint(&mut bytes, hi - lo);
        previous = lo;
    }
    bytes
}

fn varint_size(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 4,
        _ => 8,
    }
}

pub fn ack_chunks(ranges: &Ranges, budget: usize) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    let mut end = ranges.0.len();
    while end > 0 {
        let mut start = end - 1;
        let (lo, hi) = ranges.0[start];
        let header = 2 + varint_size(hi) + varint_size(hi - lo);
        let mut tail_size = 0;
        ensure!(header < budget, "ACK budget cannot fit one range");
        while start > 0 {
            let (next_lo, next_hi) = ranges.0[start - 1];
            let next_size = tail_size
                + varint_size(ranges.0[start].0 - next_hi - 2)
                + varint_size(next_hi - next_lo);
            if header + varint_size((end - start) as u64) + next_size > budget {
                break;
            }
            start -= 1;
            tail_size = next_size;
        }
        result.push(encode(&ranges.0[start..end]));
        end = start;
    }
    Ok(result)
}

pub struct Upload {
    pub sent: u64,
    pub end: u64,
    pub acked: Ranges,
    pub limit: u64,
    pub fin_sent: bool,
    pub fin_acked: bool,
    pub response: Ranges,
    pub response_fin: bool,
    pub completed_ns: Option<u64>,
}
impl Upload {
    pub fn new(end: u64, limit: u64) -> Self {
        Self {
            sent: 0,
            end,
            acked: Ranges::default(),
            limit,
            fin_sent: false,
            fin_acked: false,
            response: Ranges::default(),
            response_fin: false,
            completed_ns: None,
        }
    }
    pub fn ready_fin(&self) -> bool {
        self.sent == self.end && self.acked.covers(self.end)
    }
    pub fn finish(&mut self) -> Result<()> {
        ensure!(self.ready_fin(), "FIN before all upload bytes acknowledged");
        ensure!(!self.fin_sent, "duplicate logical FIN");
        self.fin_sent = true;
        Ok(())
    }
    pub fn response(&mut self, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        ensure!(
            self.fin_sent && self.ready_fin(),
            "response before acknowledged upload/FIN"
        );
        let end = offset
            .checked_add(data.len() as u64)
            .context("response overflow")?;
        ensure!(
            end <= RESPONSE.len() as u64,
            "extra or duplicate logical response"
        );
        ensure!(
            RESPONSE[offset as usize..end as usize] == *data,
            "wrong response status/body bytes"
        );
        if !data.is_empty() {
            self.response.insert(offset, end - 1)?;
        }
        if fin {
            ensure!(end == RESPONSE.len() as u64, "wrong response final size");
            self.response_fin = true;
        }
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.ready_fin()
            && self.fin_sent
            && self.fin_acked
            && self.response_fin
            && self.response.covers(RESPONSE.len() as u64)
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use crate::quic::frame::{Frame, Iter};
    use std::collections::BTreeSet;
    #[test]
    fn chunk_union_preserves_every_gap_at_varint_boundaries() {
        let mut ranges = Ranges::default();
        for base in [0, 63, 16383, (1 << 30) - 1, MAX_VARINT - 10000] {
            for i in 0..1000 {
                ranges.insert(base + i * 3, base + i * 3).unwrap();
            }
        }
        for budget in [33, 64, 255, 1100] {
            let mut union = Ranges::default();
            let mut total = 0;
            for packet in ack_chunks(&ranges, budget).unwrap() {
                assert!(packet.len() <= budget);
                let Frame::Ack {
                    largest,
                    first_range,
                    ranges: tail,
                    range_count,
                    ..
                } = Iter::new(&packet).next().unwrap().unwrap()
                else {
                    panic!()
                };
                let decoded = decode_ack(largest, first_range, tail, range_count).unwrap();
                total += decoded.count();
                for (lo, hi) in decoded.0 {
                    union.insert(lo, hi).unwrap();
                }
            }
            assert_eq!(union.0, ranges.0);
            assert_eq!(total, ranges.count());
        }
        assert!(ack_chunks(&ranges, 1).is_err());
    }
    #[test]
    fn interval_model_reorders_duplicates_and_merges() {
        let mut actual = Ranges::default();
        let mut model = BTreeSet::new();
        let mut seed = 123456u64;
        for _ in 0..20000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let lo = (seed >> 32) % 4096;
            let hi = lo + seed % 8;
            actual.insert(lo, hi).unwrap();
            model.extend(lo..=hi);
            assert_eq!(actual.count(), model.len() as u64);
            for p in [0, lo, hi, hi + 1, 4103] {
                assert_eq!(actual.contains(p), model.contains(&p));
            }
        }
    }
    #[test]
    fn ack_rejects_malformed_arithmetic_and_truncation() {
        assert!(decode_ack(0, 1, &[], 0).is_err());
        for tail in [&[0x40][..], &[0, 0x80][..], &[0, 1][..], &[63, 0][..]] {
            assert!(decode_ack(2, 1, tail, 1).is_err());
        }
        assert!(decode_ack(5, 0, &[0, 0], 0).is_err());
        assert_eq!(decode_ack(3, 0, &[0, 1], 1).unwrap().0, [(0, 1), (3, 3)]);
    }
    #[test]
    fn upload_requires_every_byte_both_fins_and_exact_response() {
        let mut u = Upload::new(100, 100);
        u.sent = 100;
        u.acked.insert(0, 48).unwrap();
        u.acked.insert(50, 99).unwrap();
        assert!(u.finish().is_err());
        assert!(u.response(0, RESPONSE, true).is_err());
        u.acked.insert(49, 49).unwrap();
        u.finish().unwrap();
        assert!(u.finish().is_err());
        u.response(10, &RESPONSE[10..], true).unwrap();
        assert!(!u.complete());
        u.response(0, &RESPONSE[..10], false).unwrap();
        assert!(!u.complete());
        u.fin_acked = true;
        assert!(u.complete());
        // Transport duplicates are valid, but a second HTTP response is not.
        u.response(0, RESPONSE, true).unwrap();
        assert!(u.response(RESPONSE.len() as u64, RESPONSE, true).is_err());
        assert!(u.response(0, b"bad", true).is_err());
    }
}
