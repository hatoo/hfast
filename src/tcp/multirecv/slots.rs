//! Connection identities fit in the low 60 bits of an io_uring token. Slots are
//! independent of file descriptors, and reuse advances a per-slot generation.
//! An exhausted generation permanently retires its slot instead of wrapping.

const INDEX_BITS: u32 = 24;
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
const GENERATION_STEP: u64 = 1 << INDEX_BITS;
const MAX_GENERATION: u64 = (1 << (60 - INDEX_BITS)) - 1;

fn initial_key(index: usize) -> u64 {
    assert!(index <= INDEX_MASK as usize, "connection slots exhausted");
    GENERATION_STEP | index as u64
}

struct Slot<T> {
    key: u64,
    value: Option<T>,
}

pub(super) struct Slots<T> {
    entries: Vec<Slot<T>>,
    free: Vec<usize>,
}

impl<T> Slots<T> {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
        }
    }

    pub(super) fn insert(&mut self, value: T) -> u64 {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.entries[index];
            assert!(slot.value.is_none() && slot.key >> INDEX_BITS < MAX_GENERATION);
            slot.key += GENERATION_STEP;
            slot.value = Some(value);
            slot.key
        } else {
            let index = self.entries.len();
            let key = initial_key(index);
            self.entries.push(Slot {
                key,
                value: Some(value),
            });
            key
        }
    }

    pub(super) fn get_mut(&mut self, key: u64) -> Option<&mut T> {
        let slot = self.entries.get_mut((key & INDEX_MASK) as usize)?;
        if slot.key == key {
            slot.value.as_mut()
        } else {
            None
        }
    }

    pub(super) fn remove(&mut self, key: u64) -> Option<T> {
        let index = (key & INDEX_MASK) as usize;
        let slot = self.entries.get_mut(index)?;
        if slot.key != key {
            return None;
        }
        let value = slot.value.take()?;
        if key >> INDEX_BITS < MAX_GENERATION {
            self.free.push(index);
        }
        Some(value)
    }

    #[cfg(test)]
    pub(super) fn get(&self, key: u64) -> Option<&T> {
        let slot = self.entries.get((key & INDEX_MASK) as usize)?;
        if slot.key == key {
            slot.value.as_ref()
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(super) fn iter(&self) -> impl Iterator<Item = (u64, &T)> {
        self.entries
            .iter()
            .filter_map(|s| s.value.as_ref().map(|v| (s.key, v)))
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }
}

#[cfg(test)]
mod tests;
