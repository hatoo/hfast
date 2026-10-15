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
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub bytes: usize,
    pub schedule: Vec<(usize, usize)>,
    pub sent: Vec<Emission>,
    original: Vec<u8>,
}
impl Plan {
    pub fn new(mode: Mode, original: &[u8]) -> Self {
        Self {
            bytes: original.len(),
            schedule: ranges(mode, original.len()),
            sent: Vec::new(),
            original: original.to_vec(),
        }
    }

    pub fn next(&self) -> Option<(usize, usize)> {
        self.schedule.get(self.sent.len()).copied()
    }

    pub fn record(&mut self, pn: u64, start: usize, data: &[u8]) -> Result<()> {
        let stop = start + data.len();
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
        Ok(())
    }

    pub fn json(&self) -> Value {
        json!({"bytes": self.bytes, "schedule": self.schedule,
            "original_hex": self.original.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "sent": self.sent.iter().map(|s| json!({"packet": s.packet,
                "start": s.start, "stop": s.stop})).collect::<Vec<_>>()})
    }
}

pub struct Audit {
    pub mode: Mode,
    pub plans: [Option<Plan>; 2],
}
impl Audit {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
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
