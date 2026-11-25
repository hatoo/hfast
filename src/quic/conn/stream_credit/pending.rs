//! FIFO credit updates with constant-time cancellation by a live slot handle.
//!
//! A stream owns its handle until it is written or cancelled. Vacant slots are
//! reused, so allocation follows the maximum number of simultaneous queued
//! updates, not the number of credit transmissions over a connection's lifetime.

pub(super) const UNQUEUED: usize = usize::MAX;

#[derive(Clone, Copy)]
struct Slot {
    id: u64,
    prev: usize,
    next: usize,
}

pub(super) struct PendingQueue {
    slots: Vec<Slot>,
    head: usize,
    tail: usize,
    free: usize,
}

impl PendingQueue {
    pub(super) fn new() -> Self {
        Self {
            slots: Vec::new(),
            head: UNQUEUED,
            tail: UNQUEUED,
            free: UNQUEUED,
        }
    }

    pub(super) fn front(&self) -> Option<u64> {
        (self.head != UNQUEUED).then(|| self.slots[self.head].id)
    }

    pub(super) fn push(&mut self, id: u64) -> usize {
        let slot = Slot {
            id,
            prev: self.tail,
            next: UNQUEUED,
        };
        let index = if self.free == UNQUEUED {
            let index = self.slots.len();
            self.slots.push(slot);
            index
        } else {
            let index = self.free;
            self.free = self.slots[index].next;
            self.slots[index] = slot;
            index
        };
        if self.tail == UNQUEUED {
            self.head = index;
        } else {
            self.slots[self.tail].next = index;
        }
        self.tail = index;
        index
    }

    /// The caller must relinquish the handle after removing its live entry.
    pub(super) fn remove(&mut self, index: usize) {
        let slot = self.slots[index];
        if slot.prev == UNQUEUED {
            self.head = slot.next;
        } else {
            self.slots[slot.prev].next = slot.next;
        }
        if slot.next == UNQUEUED {
            self.tail = slot.prev;
        } else {
            self.slots[slot.next].prev = slot.prev;
        }
        self.slots[index].next = self.free;
        self.free = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn assert_queue(queue: &PendingQueue, expected: &VecDeque<(usize, u64)>) {
        assert_eq!(queue.front(), expected.front().map(|&(_, id)| id));
        let mut at = queue.head;
        let mut prev = UNQUEUED;
        let mut visited = vec![false; queue.slots.len()];
        for &(handle, id) in expected {
            assert_eq!(at, handle);
            assert!(!visited[at]);
            visited[at] = true;
            let slot = queue.slots[at];
            assert_eq!((slot.id, slot.prev), (id, prev));
            prev = at;
            at = slot.next;
        }
        assert_eq!(at, UNQUEUED);
        assert_eq!(queue.tail, prev);
        at = queue.free;
        while at != UNQUEUED {
            assert!(!visited[at], "free slots are disjoint and acyclic");
            visited[at] = true;
            at = queue.slots[at].next;
        }
        assert!(visited.into_iter().all(|seen| seen), "no lost slots");
    }

    #[test]
    fn arbitrary_cancellation_and_reuse_match_fifo() {
        let mut queue = PendingQueue::new();
        let mut expected = VecDeque::new();
        let mut rng = 1u64;
        for id in 0..20_000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            if !expected.is_empty() && rng % 3 != 0 {
                let at = rng as usize % expected.len();
                let (handle, _) = expected.remove(at).unwrap();
                queue.remove(handle);
            } else {
                expected.push_back((queue.push(id), id));
            }
            assert_queue(&queue, &expected);
        }
        while let Some((handle, _)) = expected.pop_front() {
            queue.remove(handle);
            assert_queue(&queue, &expected);
        }
    }

    #[test]
    fn drained_cohorts_reuse_all_storage_in_both_directions() {
        let mut queue = PendingQueue::new();
        for round in 0..8 {
            let mut expected = (0..4096)
                .map(|id| (queue.push(id), id))
                .collect::<VecDeque<_>>();
            assert_eq!(queue.slots.len(), 4096);
            assert_queue(&queue, &expected);
            while !expected.is_empty() {
                let (handle, _) = if round % 2 == 0 {
                    expected.pop_front().unwrap()
                } else {
                    expected.pop_back().unwrap()
                };
                queue.remove(handle);
            }
            assert_queue(&queue, &expected);
        }
    }
}
