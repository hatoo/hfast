//! Scheduling and byte/packet oracles for the disposable native peer only.
use anyhow::{Result, ensure};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Reverse,
    Overlap,
}
impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "normal" => Ok(Self::Normal),
            "reverse" => Ok(Self::Reverse),
            "overlap-duplicates" => Ok(Self::Overlap),
            _ => anyhow::bail!("unknown CRYPTO schedule {s}"),
        }
    }
}

pub fn ranges(mode: Mode, size: usize) -> Vec<(usize, usize)> {
    assert!(size >= 24);
    let chunk = 96.min(size / 3);
    let mut ranges: Vec<_> = (0..size)
        .step_by(chunk)
        .map(|start| (start, size.min(start + chunk)))
        .collect();
    if mode != Mode::Normal {
        ranges.reverse();
    }
    if mode == Mode::Overlap {
        let first = ranges[0];
        ranges.splice(0..0, [first; 8]);
        ranges.insert(ranges.len() - 1, (chunk / 2, size.min(chunk * 2)));
    }
    ranges
}

#[derive(Clone, Debug)]
pub struct Emission {
    pub packet: u64,
    pub start: usize,
    pub stop: usize,
    pub acknowledged: bool,
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub bytes: usize,
    pub empty_prefix: usize,
    pub schedule: Vec<(usize, usize)>,
    pub sent: Vec<Emission>,
    original: Vec<u8>,
}
impl Plan {
    pub fn new(mode: Mode, original: &[u8]) -> Self {
        Self::with_empty_prefix(mode, original, 0).unwrap()
    }

    pub fn with_empty_prefix(mode: Mode, original: &[u8], empty_prefix: usize) -> Result<Self> {
        ensure!(
            matches!(empty_prefix, 0 | 1 | 32 | 512),
            "invalid empty prefix"
        );
        let mut schedule = vec![(original.len(), original.len()); empty_prefix];
        schedule.extend(ranges(mode, original.len()));
        Ok(Self {
            bytes: original.len(),
            empty_prefix,
            schedule,
            sent: Vec::new(),
            original: original.to_vec(),
        })
    }

    pub fn next(&self) -> Option<(usize, usize)> {
        self.schedule.get(self.sent.len()).copied()
    }

    // Bound the live flight and require an ACK fence before any real TLS data.
    // This is an untimed exposure fixture, not a different congestion algorithm.
    pub fn can_emit(&self) -> bool {
        let pending = self
            .sent
            .iter()
            .filter(|s| s.start == s.stop && !s.acknowledged)
            .count();
        if self.sent.len() < self.empty_prefix {
            pending < 16
        } else {
            pending == 0
        }
    }

    pub fn acknowledge(&mut self, first: u64, last: u64) {
        for sent in self.sent.iter_mut().take(self.empty_prefix) {
            if (first..=last).contains(&sent.packet) {
                sent.acknowledged = true;
            }
        }
    }

    pub fn record(&mut self, pn: u64, start: usize, data: &[u8]) -> Result<()> {
        let stop = start + data.len();
        ensure!(self.can_emit(), "unacknowledged empty CRYPTO fence");
        ensure!(self.next() == Some((start, stop)), "changed CRYPTO range");
        ensure!(data == &self.original[start..stop], "changed TLS bytes");
        ensure!(
            self.sent.last().is_none_or(|last| pn > last.packet),
            "reused CRYPTO packet number"
        );
        self.sent.push(Emission {
            packet: pn,
            start,
            stop,
            acknowledged: false,
        });
        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            self.sent.len() == self.schedule.len(),
            "unsent CRYPTO fragments"
        );
        let mut covered = vec![false; self.bytes];
        for emitted in &self.sent {
            covered[emitted.start..emitted.stop].fill(true);
        }
        ensure!(covered.into_iter().all(|b| b), "missing TLS bytes");
        ensure!(
            self.sent
                .iter()
                .take(self.empty_prefix)
                .all(|s| s.acknowledged),
            "missing empty CRYPTO ACK"
        );
        Ok(())
    }

    pub fn json(&self) -> Value {
        json!({"bytes": self.bytes, "schedule": self.schedule, "empty_prefix": self.empty_prefix,
            "empty_acked": self.sent.iter().take(self.empty_prefix)
                .filter(|s| s.acknowledged).map(|s| s.packet).collect::<Vec<_>>(),
            "original_hex": self.original.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "sent": self.sent.iter().map(|s| json!({"packet": s.packet,
                "start": s.start, "stop": s.stop})).collect::<Vec<_>>()})
    }
}

pub struct Audit {
    pub mode: Mode,
    pub empty_prefix: usize,
    pub plans: [Option<Plan>; 2],
}
impl Audit {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            empty_prefix: 0,
            plans: [None, None],
        }
    }
    pub fn verify(&self) -> Result<()> {
        for plan in &self.plans {
            plan.as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing TLS epoch"))?
                .verify()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    #[test]
    fn empty_prefixes_are_bounded_fenced_and_never_cover_tls_bytes() {
        for count in [0, 1, 32, 512] {
            for mode in [Mode::Normal, Mode::Reverse, Mode::Overlap] {
                let bytes: Vec<_> = (0..257).map(|i| (i % 251) as u8).collect();
                let mut plan = Plan::with_empty_prefix(mode, &bytes, count).unwrap();
                for i in 0..count {
                    assert_eq!(plan.next(), Some((257, 257)));
                    if !plan.can_emit() {
                        assert_eq!(i % 16, 0);
                        plan.acknowledge(0, i as u64 - 1);
                    }
                    plan.record(i as u64, 257, &[]).unwrap();
                }
                assert!(plan.verify().is_err(), "empty frames are not TLS bytes");
                if count > 0 {
                    assert!(!plan.can_emit(), "real data must wait for the fence");
                    let (a, b) = plan.next().unwrap();
                    assert!(plan.record(count as u64, a, &bytes[a..b]).is_err());
                    // A sparse ACK which omits the final empty packet cannot unlock TLS.
                    if count > 1 {
                        plan.acknowledge(0, count as u64 - 2);
                        assert!(!plan.can_emit());
                    }
                    plan.acknowledge(count as u64 - 1, count as u64 - 1);
                    plan.acknowledge(0, count as u64 - 1);
                }
                let mut pn = count as u64;
                while let Some((a, b)) = plan.next() {
                    plan.record(pn, a, &bytes[a..b]).unwrap();
                    pn += 1;
                }
                plan.verify().unwrap();
                assert_eq!(plan.schedule[count..], ranges(mode, bytes.len()));
                assert_eq!(plan.json()["empty_acked"].as_array().unwrap().len(), count);
            }
        }
        assert!(Plan::with_empty_prefix(Mode::Normal, &[0; 36], 513).is_err());
        assert!(Plan::with_empty_prefix(Mode::Normal, &[0; 36], 2).is_err());
    }

    #[test]
    fn empty_frames_require_the_future_offset_and_fresh_packet_numbers() {
        let mut plan = Plan::with_empty_prefix(Mode::Normal, &[0; 36], 32).unwrap();
        assert!(plan.record(3, 35, &[]).is_err());
        assert!(plan.record(3, 36, &[1]).is_err());
        plan.record(3, 36, &[]).unwrap();
        assert!(plan.record(3, 36, &[]).is_err());
        plan.record(4, 36, &[]).unwrap();
        plan.acknowledge(4, 4);
        assert_eq!(plan.json()["empty_acked"], json!([4]));
    }

    #[test]
    fn schedules_cover_both_short_and_large_tls_messages() {
        for size in [24, 36, 96, 97, 257, 4096] {
            for mode in [Mode::Normal, Mode::Reverse, Mode::Overlap] {
                let bytes: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                let mut plan = Plan::new(mode, &bytes);
                let mut pn = 3;
                while let Some((a, b)) = plan.next() {
                    plan.record(pn, a, &bytes[a..b]).unwrap();
                    pn += 2;
                }
                plan.verify().unwrap();
                if mode != Mode::Normal {
                    assert!(plan.sent[0].start > 0);
                    assert_eq!(plan.sent.last().unwrap().start, 0);
                }
            }
        }
    }

    #[test]
    fn rejects_corrupt_bytes_replayed_packet_numbers_and_missing_fragments() {
        let bytes: Vec<_> = (0..256).map(|i| i as u8).collect();
        let mut plan = Plan::new(Mode::Overlap, &bytes);
        let (a, b) = plan.next().unwrap();
        assert!(plan.verify().is_err());
        assert!(plan.record(5, a, &vec![0; b - a]).is_err());
        plan.record(5, a, &bytes[a..b]).unwrap();
        assert!(plan.record(5, a, &bytes[a..b]).is_err());
        assert!(plan.record(6, a + 1, &bytes[a + 1..b]).is_err());
        assert!(Audit::new(Mode::Normal).verify().is_err());
    }
}
