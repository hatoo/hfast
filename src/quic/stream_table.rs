//! Request storage bounded by the stream window, even behind an old gap.
//!
//! The advertised limit is at most `finished + window`. Thus at most `window`
//! stream numbers below that limit are not complete, including unseen gaps.
//! Every disjoint completed range needs a gap separating it from the next, so
//! both the active map and the completed ranges are bounded by that window.
//! Keeping every completed dense slot instead would grow with connection age.

use std::collections::HashMap;

#[derive(Default)]
enum Slot<T> {
    #[default]
    Unseen,
    Active(T),
    Complete,
}

#[derive(Default)]
struct Sparse<T> {
    active: HashMap<u64, T>,
    /// Sorted, disjoint, non-adjacent half-open ranges of completed streams.
    complete: Vec<(u64, u64)>,
}

impl<T> Sparse<T> {
    fn is_complete(&self, n: u64) -> bool {
        let i = self.complete.partition_point(|&(start, _)| start <= n);
        i > 0 && n < self.complete[i - 1].1
    }

    fn complete(&mut self, n: u64, base: &mut u64) {
        let i = self.complete.partition_point(|&(_, end)| end < n);
        if i < self.complete.len() && self.complete[i].0 <= n + 1 {
            let range = &mut self.complete[i];
            range.0 = range.0.min(n);
            range.1 = range.1.max(n + 1);
            if i + 1 < self.complete.len() && self.complete[i].1 == self.complete[i + 1].0 {
                self.complete[i].1 = self.complete[i + 1].1;
                self.complete.remove(i + 1);
            }
        } else {
            self.complete.insert(i, (n, n + 1));
        }
        if self.complete[0].0 == *base {
            *base = self.complete.remove(0).1;
        }
    }
}

pub(super) struct StreamTable<T> {
    /// Everything below this stream number has completed in both directions.
    base: u64,
    dense: Vec<Slot<T>>,
    /// Keep direct indexing for ordinary traffic. Switch only when a gap has
    /// retained more than two windows of slots (at least 16), then keep that representation
    /// for the rest of the connection.
    dense_limit: u64,
    /// Allocate the uncommon representation only after the dense span is full.
    sparse: Option<Box<Sparse<T>>>,
}

impl<T: Default> StreamTable<T> {
    pub(super) fn new(window: u64) -> Self {
        Self {
            base: 0,
            dense: Vec::new(),
            dense_limit: window.saturating_mul(2).max(16),
            sparse: None,
        }
    }

    /// The caller enforces the advertised absolute stream limit. Unseen lower
    /// streams need no sparse entry, but must remain available after migration.
    pub(super) fn get_or_insert(&mut self, n: u64) -> Option<&mut T> {
        let offset = n.checked_sub(self.base)?;
        if self.sparse.is_none() && offset >= self.dense_limit {
            self.make_sparse();
        }
        if let Some(sparse) = &mut self.sparse {
            if sparse.is_complete(n) {
                return None;
            }
            return Some(sparse.active.entry(n).or_default());
        }
        let i = usize::try_from(offset).ok()?;
        if i >= self.dense.len() {
            self.dense.resize_with(i + 1, Slot::default);
        }
        if matches!(self.dense[i], Slot::Unseen) {
            self.dense[i] = Slot::Active(T::default());
        }
        match &mut self.dense[i] {
            Slot::Active(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn get_mut(&mut self, n: u64) -> Option<&mut T> {
        if let Some(sparse) = &mut self.sparse {
            return sparse.active.get_mut(&n);
        }
        let i = usize::try_from(n.checked_sub(self.base)?).ok()?;
        match self.dense.get_mut(i)? {
            Slot::Active(value) => Some(value),
            _ => None,
        }
    }

    /// Mark an existing request complete exactly once. Dense prefix removal
    /// is deferred to retire(), so an ACK batch shifts the remaining slots once.
    pub(super) fn complete(&mut self, n: u64) -> bool {
        if let Some(sparse) = &mut self.sparse {
            if sparse.active.remove(&n).is_none() {
                return false;
            }
            sparse.complete(n, &mut self.base);
            return true;
        }
        let Some(i) = n
            .checked_sub(self.base)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        let Some(slot @ Slot::Active(_)) = self.dense.get_mut(i) else {
            return false;
        };
        *slot = Slot::Complete;
        true
    }

    pub(super) fn retire(&mut self) {
        let n = self
            .dense
            .iter()
            .take_while(|s| matches!(s, Slot::Complete))
            .count();
        if n > 0 {
            self.dense.drain(..n);
            self.base += n as u64;
        }
    }

    fn make_sparse(&mut self) {
        let mut sparse = Sparse::default();
        for (i, slot) in std::mem::take(&mut self.dense).into_iter().enumerate() {
            let n = self.base + i as u64;
            match slot {
                Slot::Unseen => {}
                Slot::Active(value) => {
                    sparse.active.insert(n, value);
                }
                Slot::Complete => {
                    if let Some(last) = sparse.complete.last_mut()
                        && last.1 == n
                    {
                        last.1 += 1;
                    } else {
                        sparse.complete.push((n, n + 1));
                    }
                }
            }
        }
        if sparse
            .complete
            .first()
            .is_some_and(|&(start, _)| start == self.base)
        {
            self.base = sparse.complete.remove(0).1;
        }
        self.sparse = Some(Box::new(sparse));
    }

    #[cfg(test)]
    pub(super) fn base(&self) -> u64 {
        self.base
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.dense.is_empty()
            && self
                .sparse
                .as_ref()
                .is_none_or(|s| s.active.is_empty() && s.complete.is_empty())
    }

    #[cfg(test)]
    pub(super) fn retained_capacity(&self) -> usize {
        self.dense.capacity()
            + self
                .sparse
                .as_ref()
                .map_or(0, |s| s.active.capacity() + s.complete.capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_preserves_active_values_completed_ranges_and_unseen_gaps() {
        let mut table = StreamTable::<u64>::new(8);
        for n in [0, 1, 3, 4, 5] {
            *table.get_or_insert(n).unwrap() = n + 100;
        }
        for n in [1, 3, 4] {
            assert!(table.complete(n));
        }
        assert!(table.sparse.is_none());
        *table.get_or_insert(16).unwrap() = 116;
        assert_eq!(
            table.dense.capacity(),
            0,
            "release the pinned dense allocation"
        );
        assert_eq!(table.base(), 0);
        assert_eq!(table.sparse.as_ref().unwrap().complete, [(1, 2), (3, 5)]);
        for n in [0, 5, 16] {
            assert_eq!(table.get_mut(n), Some(&mut (n + 100)));
        }
        for n in [1, 3, 4] {
            assert!(table.get_or_insert(n).is_none());
            assert!(!table.complete(n));
        }
        assert!(table.get_or_insert(2).is_some());
        assert!(table.complete(2));
        assert_eq!(table.sparse.as_ref().unwrap().complete, [(1, 5)]);
        assert!(table.complete(0));
        assert_eq!(table.base(), 5);
        assert!(table.complete(5));
        assert_eq!(table.base(), 6);
        assert!(table.get_or_insert(0).is_none());
        assert!(
            table.get_or_insert(6).is_some(),
            "higher ids do not close unseen gaps"
        );
    }

    #[test]
    fn completed_ranges_coalesce_in_every_order() {
        fn check(order: &mut [u64], at: usize) {
            if at < order.len() {
                for i in at..order.len() {
                    order.swap(at, i);
                    check(order, at + 1);
                    order.swap(at, i);
                }
                return;
            }
            let mut table = StreamTable::<()>::new(1);
            table.make_sparse();
            for &n in order.iter() {
                table.get_or_insert(n).unwrap();
            }
            let mut done = [false; 6];
            for &n in order.iter() {
                assert!(table.complete(n));
                assert!(!table.complete(n), "completion must be idempotent");
                done[n as usize] = true;
                let base = done.iter().take_while(|&&v| v).count() as u64;
                assert_eq!(table.base(), base);
                let sparse = table.sparse.as_ref().unwrap();
                for (i, &done) in done.iter().enumerate() {
                    assert_eq!(i < base as usize || sparse.is_complete(i as u64), done);
                }
                assert!(sparse.complete.windows(2).all(|r| r[0].1 < r[1].0));
            }
            assert!(table.is_empty());
        }
        check(&mut [0, 1, 2, 3, 4, 5], 0);
    }

    #[test]
    fn migration_retires_a_completed_prefix_before_the_next_ack_batch() {
        let mut table = StreamTable::<()>::new(1);
        table.get_or_insert(0).unwrap();
        assert!(table.complete(0));
        // Deliberately migrate before retire(), as can happen within a batch.
        table.get_or_insert(16).unwrap();
        assert_eq!(table.base(), 1);
        assert!(table.get_or_insert(0).is_none());
        assert!(table.get_or_insert(1).is_some());
    }

    #[test]
    fn regular_batches_keep_direct_indexing_and_reuse_capacity() {
        let mut table = StreamTable::<u64>::new(64);
        for batch in 0..1000 {
            let start = batch * 64;
            for n in start..start + 64 {
                *table.get_or_insert(n).unwrap() = n;
            }
            for n in (start..start + 64).rev() {
                assert_eq!(table.get_mut(n).copied(), Some(n));
                assert!(table.complete(n));
            }
            table.retire();
            assert_eq!(table.base(), start + 64);
            assert!(table.sparse.is_none());
            assert_eq!(table.dense.capacity(), 64);
        }
    }

    #[test]
    fn sparse_state_tracks_a_reference_model_across_many_credit_windows() {
        let mut table = StreamTable::<u64>::new(64);
        let mut model = vec![0_u8; 64]; // unseen, active, complete
        let mut finished = 0;
        let mut seed = 0x1234_5678_u64;
        table.get_or_insert(0).unwrap();
        model[0] = 1; // Pin the lowest stream for the whole run.
        for step in 0..100_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let limit = finished + 64;
            model.resize(limit, 0);
            let n = 1 + (seed >> 16) as usize % (limit - 1);
            if seed & 1 == 0 {
                let got = table.get_or_insert(n as u64);
                assert_eq!(got.is_none(), model[n] == 2);
                if let Some(value) = got {
                    if model[n] == 1 {
                        assert_eq!(*value, n as u64);
                    }
                    *value = n as u64;
                    model[n] = 1;
                }
            } else {
                assert_eq!(table.complete(n as u64), model[n] == 1);
                if model[n] == 1 {
                    model[n] = 2;
                    finished += 1;
                }
                table.retire();
            }
            assert_eq!(table.base(), 0);
            if let Some(sparse) = &table.sparse {
                assert!(sparse.active.len() <= 64);
                assert!(sparse.complete.len() <= 64);
                assert!(sparse.complete.windows(2).all(|r| r[0].1 < r[1].0));
            }
            if step % 1000 == 0 {
                for (i, &state) in model.iter().enumerate() {
                    assert_eq!(table.get_mut(i as u64).is_some(), state == 1);
                }
            }
        }
        assert!(table.sparse.is_some());
        assert!(finished > 1000);
        for (n, state) in model.iter_mut().enumerate() {
            if *state != 2 {
                table.get_or_insert(n as u64).unwrap();
                assert!(table.complete(n as u64));
                *state = 2;
            }
        }
        assert_eq!(table.base(), model.len() as u64);
        assert!(table.is_empty());
    }

    #[test]
    fn very_large_stream_numbers_do_not_allocate_the_missing_span() {
        let mut table = StreamTable::<()>::new(64);
        let last = (1 << 60) - 1; // Largest client bidi number in a QUIC varint id.
        table.get_or_insert(last).unwrap();
        assert!(table.complete(last));
        assert!(table.get_or_insert(last).is_none());
        assert!(table.get_or_insert(0).is_some());
        assert_eq!(table.base(), 0);
        assert!(table.retained_capacity() < 16);
    }
}
