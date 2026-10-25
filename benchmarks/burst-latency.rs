//! Opt-in, bounded exact request timestamps. Allocation and export are untimed.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{io::Write, path::Path, time::Instant};

pub const MAX_SAMPLES: usize = 1 << 22;
pub const MAX_PHASE: usize = 64;
const MAGIC: &[u8; 8] = b"HFBSTL01";

#[derive(Clone, Copy, Debug)]
struct Sample {
    stream: u64,
    sent_ns: u64,
    complete_ns: u64,
}
impl Sample {
    fn duration(self) -> u64 {
        self.complete_ns - self.sent_ns
    }
}

pub struct Ledger {
    phase: usize,
    first: u64,
    expected: usize,
    epoch: Instant,
    burst: Option<(u64, usize, u64)>,
    samples: Vec<Sample>,
    end_ns: Option<u64>,
}
impl Ledger {
    pub fn new(phase: usize, first: u64, count: usize, epoch: Instant) -> Result<Self> {
        ensure!(phase <= MAX_PHASE, "latency phase limit exceeded");
        ensure!(
            (1..=MAX_SAMPLES).contains(&count),
            "latency sample limit exceeded"
        );
        ensure!(
            first.is_multiple_of(4) && first < (1 << 62),
            "invalid first stream"
        );
        ensure!(
            first + 4 * count as u64 <= (1 << 62),
            "latency stream limit exceeded"
        );
        let mut samples = Vec::new();
        samples.try_reserve_exact(count)?;
        samples.resize(
            count,
            Sample {
                stream: 0,
                sent_ns: 0,
                complete_ns: 0,
            },
        );
        std::hint::black_box(&samples); // Fault in ledger storage before timing.
        samples.clear();
        Ok(Self {
            phase,
            first,
            expected: count,
            epoch,
            burst: None,
            samples,
            end_ns: None,
        })
    }

    fn ns(&self, now: Instant) -> Result<u64> {
        Ok(now
            .checked_duration_since(self.epoch)
            .context("latency clock reversed")?
            .as_nanos()
            .try_into()?)
    }

    pub fn send(&mut self, first: u64, count: usize, now: Instant) -> Result<()> {
        ensure!(self.end_ns.is_none(), "latency phase already finished");
        ensure!(
            count > 0 && self.samples.len() + count <= self.expected,
            "unexpected latency burst size"
        );
        ensure!(
            first == self.first + 4 * self.samples.len() as u64,
            "unfinished or wrong latency burst"
        );
        if let Some((old_first, old_count, _)) = self.burst {
            ensure!(
                first == old_first + 4 * old_count as u64,
                "missing latency samples"
            );
        }
        let sent = self.ns(now)?;
        ensure!(
            self.samples
                .last()
                .is_none_or(|last| sent >= last.complete_ns),
            "latency send clock reversed"
        );
        self.burst = Some((first, count, sent));
        Ok(())
    }

    // Batch validates exact bytes, FIN, stream membership and uniqueness before
    // calling this method. The caller reads the clock for EACH valid response.
    pub fn complete(&mut self, stream: u64, now: Instant) -> Result<()> {
        ensure!(self.end_ns.is_none(), "latency phase already finished");
        let (first, count, sent_ns) = self.burst.context("response before send")?;
        ensure!(
            stream >= first
                && stream < first + 4 * count as u64
                && (stream - first).is_multiple_of(4),
            "wrong latency stream"
        );
        ensure!(
            self.samples.len() < self.expected,
            "too many latency samples"
        );
        let complete_ns = self.ns(now)?;
        ensure!(complete_ns > sent_ns, "zero or reversed latency");
        ensure!(
            self.samples
                .last()
                .is_none_or(|last| complete_ns >= last.complete_ns),
            "latency completion clock reversed"
        );
        self.samples.push(Sample {
            stream,
            sent_ns,
            complete_ns,
        });
        Ok(())
    }

    pub fn finish(&mut self, now: Instant) -> Result<()> {
        ensure!(
            self.samples.len() == self.expected,
            "missing latency samples"
        );
        let end = self.ns(now)?;
        ensure!(
            end >= self.samples.last().unwrap().complete_ns,
            "latency end clock reversed"
        );
        self.end_ns = Some(end);
        Ok(())
    }

    pub fn metadata(&self) -> Value {
        json!({"version": 1, "phase": self.phase, "first_stream": self.first,
            "expected": self.expected, "count": self.samples.len(), "end_ns": self.end_ns,
            "bytes": 32 + 24 * self.samples.len()})
    }

    // Only called after the controller has stopped wall/CPU measurement. Sorting
    // permits exact bounded-memory quantiles across all files, outside timing.
    // A partial failure export is diagnostic and can never pass success gates.
    pub fn export(&mut self, path: &Path, partial: bool) -> Result<Value> {
        ensure!(partial || self.end_ns.is_some(), "unfinished latency phase");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        self.samples
            .sort_unstable_by_key(|sample| sample.duration());
        let mut out = std::io::BufWriter::with_capacity(65536, file);
        self.write(&mut out)?;
        out.flush()?;
        Ok(self.metadata())
    }

    fn write(&self, out: &mut impl Write) -> Result<()> {
        out.write_all(MAGIC)?;
        for value in [self.phase as u64, self.first, self.samples.len() as u64] {
            out.write_all(&value.to_le_bytes())?;
        }
        for sample in &self.samples {
            for value in [sample.stream, sample.sent_ns, sample.complete_ns] {
                out.write_all(&value.to_le_bytes())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn every_authenticated_response_has_its_own_clock_and_stream_identity() {
        let now = Instant::now();
        let mut l = Ledger::new(3, 128, 4, now).unwrap();
        let mut b = crate::Batch::new(128, 4);
        l.send(128, 4, now + Duration::from_nanos(10)).unwrap();
        for (id, ns) in [(140, 20), (128, 23), (136, 31), (132, 40)] {
            b.response_timed(99, id, 0, true, crate::RESPONSE, Some(&mut l), || {
                now + Duration::from_nanos(ns)
            })
            .unwrap();
        }
        b.complete().unwrap();
        l.finish(now + Duration::from_nanos(50)).unwrap();
        assert_eq!(
            l.samples
                .iter()
                .map(|s| (s.stream, s.sent_ns, s.complete_ns))
                .collect::<Vec<_>>(),
            [(140, 10, 20), (128, 10, 23), (136, 10, 31), (132, 10, 40)]
        );
        assert_eq!(l.samples.capacity(), 4); // Completion did not grow storage.
    }

    #[test]
    fn invalid_responses_never_read_a_clock_or_create_successful_samples() {
        let now = Instant::now();
        let mut l = Ledger::new(0, 4, 2, now).unwrap();
        let mut b = crate::Batch::new(4, 2);
        l.send(4, 2, now).unwrap();
        for (id, offset, fin, data) in [
            (0, 0, true, crate::RESPONSE),
            (12, 0, true, crate::RESPONSE),
            (5, 0, true, crate::RESPONSE),
            (4, 1, true, crate::RESPONSE),
            (4, 0, false, crate::RESPONSE),
            (4, 0, true, b"wrong status/body".as_slice()),
            (4, 0, true, &crate::RESPONSE[..crate::RESPONSE.len() - 1]),
        ] {
            assert!(
                b.response_timed(1, id, offset, fin, data, Some(&mut l), || panic!(
                    "invalid response read the clock"
                ))
                .is_err()
            );
            assert_eq!(l.samples.len(), 0);
            assert_eq!(b.completed, 0);
        }
        assert!(
            b.response_timed(1, 4, 0, true, crate::RESPONSE, Some(&mut l), || now)
                .is_err()
        );
        assert_eq!(b.completed, 0);
        b.response_timed(1, 4, 0, true, crate::RESPONSE, Some(&mut l), || {
            now + Duration::from_nanos(3)
        })
        .unwrap();
        assert!(
            b.response_timed(2, 4, 0, true, crate::RESPONSE, Some(&mut l), || panic!(
                "duplicate read the clock"
            ))
            .is_err()
        );
        assert_eq!(l.samples.len(), 1);
        assert!(l.finish(now + Duration::from_nanos(4)).is_err());
    }

    #[test]
    fn disabled_sampling_has_no_clock_reads_and_phase_windows_are_disjoint() {
        crate::Batch::new(0, 1)
            .response_timed(1, 0, 0, true, crate::RESPONSE, None, || {
                panic!("disabled clock read")
            })
            .unwrap();
        let now = Instant::now();
        for (phase, first) in [(0, 0), (1, 8)] {
            let mut l = Ledger::new(phase, first, 2, now).unwrap();
            for i in 0..2 {
                let id = first + i * 4;
                l.send(id, 1, now + Duration::from_nanos(10 * i)).unwrap();
                crate::Batch::new(id, 1)
                    .response_timed(1, id, 0, true, crate::RESPONSE, Some(&mut l), || {
                        now + Duration::from_nanos(10 * i + 2)
                    })
                    .unwrap();
            }
            l.finish(now + Duration::from_nanos(20)).unwrap();
            assert_eq!(l.metadata()["phase"], phase);
            assert_eq!(l.metadata()["first_stream"], first);
            assert!(l.samples.iter().all(|s| s.duration() == 2));
        }
    }

    #[test]
    fn bounds_are_checked_before_allocation() {
        let now = Instant::now();
        for (phase, first, count) in [
            (65, 0, 1),
            (0, 1, 1),
            (0, 0, 0),
            (0, 0, MAX_SAMPLES + 1),
            (0, (1 << 62) - 4, 2),
            (0, u64::MAX, 1),
        ] {
            assert!(Ledger::new(phase, first, count, now).is_err());
        }
        assert_eq!(std::mem::size_of::<Sample>(), 24);
    }

    #[test]
    fn clocks_and_incomplete_bursts_cannot_produce_a_finished_ledger() {
        let now = Instant::now();
        let mut l = Ledger::new(1, 4, 2, now).unwrap();
        assert!(l.complete(4, now).is_err());
        assert!(l.send(8, 2, now).is_err());
        l.send(4, 2, now).unwrap();
        assert!(l.complete(4, now).is_err());
        assert!(l.complete(4, now - Duration::from_nanos(1)).is_err());
        assert!(l.complete(12, now + Duration::from_nanos(1)).is_err());
        l.complete(8, now + Duration::from_nanos(10)).unwrap();
        assert!(l.finish(now + Duration::from_nanos(11)).is_err());
        assert!(l.send(8, 1, now + Duration::from_nanos(11)).is_err());
        assert!(l.complete(4, now + Duration::from_nanos(9)).is_err());
        l.complete(4, now + Duration::from_nanos(12)).unwrap();
        assert!(l.finish(now + Duration::from_nanos(11)).is_err());
        l.finish(now + Duration::from_nanos(13)).unwrap();
        assert!(l.complete(4, now + Duration::from_nanos(14)).is_err());
        assert_eq!(l.metadata()["count"], 2);
    }

    #[test]
    fn export_has_exact_little_endian_timestamps_and_propagates_write_failure() {
        let now = Instant::now();
        let mut l = Ledger::new(2, 128, 1, now).unwrap();
        l.send(128, 1, now + Duration::from_nanos(10)).unwrap();
        l.complete(128, now + Duration::from_nanos(37)).unwrap();
        l.finish(now + Duration::from_nanos(40)).unwrap();
        let mut bytes = Vec::new();
        l.write(&mut bytes).unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        let fields: Vec<_> = bytes[8..]
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(fields, [2, 128, 1, 128, 10, 37]);
        let mut truncated = &mut [0u8; 55][..];
        assert!(l.write(&mut truncated).is_err());
    }
}
