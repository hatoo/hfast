//! Independent fixed-response oracle. No production response parser is reused.
use anyhow::{Context, Result, ensure};

pub const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";
const COMPLETE: u32 = (1 << RESPONSE.len()) - 1;
pub const HISTORY: usize = 128;

#[derive(Debug)]
pub struct Response {
    pub limit: u64,
    pub seen: u32,
    pub fin: bool,
    pub started: Option<u64>,
    pub completed: Option<u64>,
    pub frames: u64,
    pub duplicates: u64,
}
impl Response {
    pub fn new(limit: u64) -> Result<Self> {
        ensure!(
            (1..=RESPONSE.len() as u64).contains(&limit),
            "invalid initial credit"
        );
        Ok(Self {
            limit,
            seen: 0,
            fin: false,
            started: None,
            completed: None,
            frames: 0,
            duplicates: 0,
        })
    }
    pub fn start(&mut self, now: u64) -> Result<()> {
        ensure!(self.started.is_none(), "request started twice");
        self.started = Some(now);
        Ok(())
    }
    pub fn grant(&mut self, limit: u64) -> Result<()> {
        ensure!(
            limit > self.limit && limit <= RESPONSE.len() as u64,
            "non-increasing or oversized grant"
        );
        self.limit = limit;
        Ok(())
    }
    pub fn prefix(&self) -> u64 {
        self.seen.trailing_ones() as u64
    }
    pub fn receive(&mut self, offset: u64, data: &[u8], fin: bool, now: u64) -> Result<bool> {
        let start = self.started.context("response before request")?;
        ensure!(now >= start, "response clock reversed");
        let end = offset
            .checked_add(data.len() as u64)
            .context("offset overflow")?;
        ensure!(
            end <= RESPONSE.len() as u64 && end <= self.limit,
            "response exceeds length or granted credit"
        );
        ensure!(
            data == &RESPONSE[offset as usize..end as usize],
            "response bytes differ"
        );
        ensure!(!fin || end == RESPONSE.len() as u64, "premature FIN");
        let mask = ((1u32 << data.len()) - 1) << offset;
        self.frames += 1;
        if self.seen & mask == mask && (!fin || self.fin) {
            self.duplicates += 1;
        }
        self.seen |= mask;
        self.fin |= fin;
        // A reordered final fragment may arrive before a gap; never complete it.
        if self.seen == COMPLETE && self.fin && self.completed.is_none() {
            self.completed = Some(now);
            return Ok(true);
        }
        Ok(false)
    }
    pub fn latency(&self) -> Result<u64> {
        ensure!(self.seen == COMPLETE && self.fin, "incomplete response");
        self.completed
            .context("missing latency sample")?
            .checked_sub(self.started.context("missing request timestamp")?)
            .context("latency clock reversed")
    }
}

#[derive(Debug)]
pub struct Copies {
    pub packets: Vec<u64>,
    pub last_ns: u64,
}
impl Copies {
    pub fn new(pn: u64, now: u64) -> Self {
        Self {
            packets: vec![pn],
            last_ns: now,
        }
    }
    pub fn retry(&mut self, pn: u64, now: u64) -> Result<()> {
        ensure!(
            self.packets.len() < HISTORY,
            "retransmission history exhausted; no copies discarded"
        );
        ensure!(
            pn > *self.packets.last().unwrap() && now >= self.last_ns,
            "retry order reversed"
        );
        self.packets.push(pn);
        self.last_ns = now;
        Ok(())
    }
    pub fn due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_ns) >= 50_000_000
    }
    pub fn acked(&self, contains: impl Fn(u64) -> bool) -> bool {
        self.packets.iter().any(|&pn| contains(pn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fragment_size_and_order_retains_exactly_one_sample() {
        for width in 1..=25 {
            for reversed in [false, true] {
                let mut r = Response::new(25).unwrap();
                r.start(100).unwrap();
                let mut parts: Vec<_> = RESPONSE
                    .chunks(width)
                    .enumerate()
                    .map(|(i, b)| (i * width, b))
                    .collect();
                if reversed {
                    parts.reverse();
                }
                let mut completions = 0;
                for (offset, bytes) in parts.iter().copied() {
                    completions += usize::from(
                        r.receive(offset as u64, bytes, offset + bytes.len() == 25, 200)
                            .unwrap(),
                    );
                }
                assert_eq!(completions, 1);
                assert_eq!(r.prefix(), 25);
                assert_eq!(r.latency().unwrap(), 100);
                for (offset, bytes) in parts {
                    assert!(
                        !r.receive(offset as u64, bytes, offset + bytes.len() == 25, 300)
                            .unwrap()
                    );
                }
                assert_eq!(r.latency().unwrap(), 100);
            }
        }
    }
    #[test]
    fn actual_byte_grants_and_matching_overlaps() {
        let mut r = Response::new(1).unwrap();
        r.start(0).unwrap();
        for i in 0..25 {
            if i > 0 {
                r.grant(i + 1).unwrap();
            }
            assert_eq!(
                r.receive(i, &RESPONSE[i as usize..i as usize + 1], i == 24, i + 10)
                    .unwrap(),
                i == 24
            );
            assert!(r.grant(i + 1).is_err());
        }
        assert!(!r.receive(3, &RESPONSE[3..19], false, 100).unwrap());
        assert_eq!(r.latency().unwrap(), 34);
        assert_eq!(r.duplicates, 1);
    }
    #[test]
    fn missing_byte_fin_or_sample_never_succeeds() {
        for gap in 0..25 {
            let mut r = Response::new(25).unwrap();
            r.start(0).unwrap();
            for (i, byte) in RESPONSE.iter().enumerate() {
                if i != gap {
                    assert!(!r.receive(i as u64, &[*byte], i == 24, 10).unwrap());
                }
            }
            assert!(r.latency().is_err());
            assert!(
                r.receive(gap as u64, &RESPONSE[gap..gap + 1], gap == 24, 20)
                    .unwrap()
            );
            assert_eq!(r.latency().unwrap(), 20);
        }
        let mut r = Response::new(25).unwrap();
        r.start(0).unwrap();
        assert!(!r.receive(0, RESPONSE, false, 1).unwrap());
        assert!(r.latency().is_err());
        assert!(r.receive(25, &[], true, 2).unwrap());
        r.completed = None;
        assert!(r.latency().is_err());
    }
    #[test]
    fn corrupt_bytes_credit_fin_ids_and_timestamps_fail() {
        let mut r = Response::new(1).unwrap();
        assert!(r.receive(0, &RESPONSE[..1], false, 0).is_err());
        r.start(10).unwrap();
        assert!(r.start(20).is_err());
        assert!(r.receive(0, &RESPONSE[..1], false, 9).is_err());
        for (offset, data, fin) in [
            (0, &RESPONSE[..2], false),
            (0, &RESPONSE[..1], true),
            (0, b"x".as_slice(), false),
            (u64::MAX, b"x".as_slice(), false),
            (26, b"".as_slice(), false),
        ] {
            assert!(r.receive(offset, data, fin, 20).is_err());
            assert_eq!(r.seen, 0);
            assert!(!r.fin);
        }
        for grant in [0, 1, 26, u64::MAX] {
            assert!(r.grant(grant).is_err());
        }
        assert_eq!(r.limit, 1);
    }
    #[test]
    fn retry_retains_original_and_every_copy_until_bounded_failure() {
        let mut c = Copies::new(4, 0);
        assert!(!c.due(49_999_999));
        assert!(c.due(50_000_000));
        for i in 1..HISTORY {
            c.retry(4 + i as u64, i as u64 * 50_000_000).unwrap();
        }
        for pn in 4..4 + HISTORY as u64 {
            assert!(c.acked(|p| p == pn));
        }
        assert!(!c.acked(|p| p == 3));
        let retained = c.packets.clone();
        assert!(c.retry(200, 10_000_000_000).is_err());
        assert_eq!(retained, c.packets);
    }
}
