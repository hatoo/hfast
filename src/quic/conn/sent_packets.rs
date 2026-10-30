//! Fragment packet identities. The first transmission needs no allocation;
//! retries spill into a vector. Ordinary control and CRYPTO histories keep Vec.

use std::ops::Deref;

/// Storage operations needed by the shared control/fragment delivery rules.
pub(super) trait PacketHistory: Default + Deref<Target = [u64]> {
    fn push(&mut self, pn: u64);
    fn clear(&mut self);
}

impl PacketHistory for Vec<u64> {
    fn push(&mut self, pn: u64) {
        Vec::push(self, pn);
    }

    fn clear(&mut self) {
        Vec::clear(self);
    }
}

#[derive(Clone)]
pub(super) enum SentPackets {
    Inline(Option<u64>),
    Heap(Vec<u64>),
}

impl SentPackets {
    pub fn new() -> Self {
        Self::Inline(None)
    }

    pub fn one(pn: u64) -> Self {
        Self::Inline(Some(pn))
    }

    pub fn push(&mut self, pn: u64) {
        match self {
            Self::Inline(None) => *self = Self::one(pn),
            Self::Inline(Some(first)) => {
                // Match Vec::push's initial capacity so a third transmission
                // does not introduce a reallocation compared with the old path.
                let mut packets = Vec::with_capacity(4);
                packets.push(*first);
                packets.push(pn);
                *self = Self::Heap(packets);
            }
            Self::Heap(packets) => packets.push(pn),
        }
    }

    pub fn clear(&mut self) {
        match self {
            Self::Inline(first) => *first = None,
            // Keep retry storage for subsequent credit generations, as Vec did.
            Self::Heap(packets) => packets.clear(),
        }
    }

    pub fn remove_first(&mut self) {
        match self {
            Self::Inline(first) => {
                first.take().expect("nonempty packet history");
            }
            Self::Heap(packets) => {
                packets.remove(0);
            }
        }
    }

    pub fn as_slice(&self) -> &[u64] {
        match self {
            Self::Inline(first) => first.as_slice(),
            Self::Heap(packets) => packets,
        }
    }

    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        match self {
            Self::Inline(_) => 1,
            Self::Heap(packets) => packets.capacity(),
        }
    }
}

impl Default for SentPackets {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketHistory for SentPackets {
    fn push(&mut self, pn: u64) {
        SentPackets::push(self, pn);
    }

    fn clear(&mut self) {
        SentPackets::clear(self);
    }
}

impl Deref for SentPackets {
    type Target = [u64];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spilling_reserves_normal_growth_and_clear_reuses_retry_storage() {
        let mut packets = SentPackets::one(7);
        assert!(matches!(packets, SentPackets::Inline(Some(7))));
        packets.push(11);
        let SentPackets::Heap(heap) = &packets else {
            panic!("the second transmission must spill");
        };
        let allocation = heap.as_ptr();
        assert_eq!(heap.capacity(), 4);
        packets.push(19);
        packets.push(23);
        assert_eq!(packets.as_slice(), [7, 11, 19, 23]);
        assert_eq!(packets.as_slice().as_ptr(), allocation);
        packets.clear();
        assert!(packets.is_empty());
        assert_eq!(packets.capacity(), 4);
        packets.push(31);
        assert_eq!(packets.as_slice(), [31]);
        assert_eq!(packets.as_slice().as_ptr(), allocation);
    }

    #[test]
    fn packet_values_order_duplicates_and_independent_clones_survive_spilling() {
        for values in [
            vec![],
            vec![0],
            vec![u64::MAX],
            vec![0, 0, u64::MAX, (1 << 62) - 1, 0],
            (0..65).collect(),
        ] {
            let mut packets = SentPackets::new();
            let mut expected = Vec::new();
            for pn in values {
                let previous = packets.clone();
                packets.push(pn);
                assert_eq!(previous.as_slice(), expected);
                expected.push(pn);
                assert_eq!(packets.as_slice(), expected);
                assert_eq!(packets.last(), expected.last());
            }
            let original = packets.clone();
            let original_values = expected.clone();
            while !expected.is_empty() {
                assert_eq!(packets.as_slice(), expected);
                packets.remove_first();
                expected.remove(0);
            }
            assert!(packets.is_empty());
            packets.push(17);
            assert_eq!(packets.as_slice(), [17]);
            packets.clear();
            assert!(packets.is_empty());
            packets.push(21);
            packets.push(34);
            assert_eq!(packets.as_slice(), [21, 34]);
            assert_eq!(original.as_slice(), original_values);
        }
    }

    #[test]
    fn clearing_each_history_size_does_not_revive_old_packet_numbers() {
        for count in 0..65 {
            let mut packets = SentPackets::new();
            for pn in 0..count {
                packets.push(pn);
            }
            let previous = packets.clone();
            packets.clear();
            assert!(packets.is_empty());
            assert_eq!(previous.as_slice(), (0..count).collect::<Vec<_>>());
            packets.push(u64::MAX);
            assert_eq!(packets.as_slice(), [u64::MAX]);
            packets.clear();
            assert_eq!(packets.last(), None);
        }
    }
}
