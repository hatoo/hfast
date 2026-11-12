//! Putting the handshake back in order
//!
//! CRYPTO frames arrive at an offset and may arrive out of order. Almost
//! always they arrive in order and this is an append, so the out-of-order case
//! is kept out of the way rather than made fast. Request streams need none of
//! this: nothing in a request is read.

/// Data for one direction of one stream, in order, with what has arrived early
/// held aside
#[derive(Default)]
pub struct Assembler {
    /// Contiguous bytes not yet taken by the reader
    buf: Vec<u8>,
    /// Offset of the byte after `buf`, which is the next one wanted
    end: u64,
    /// Pieces past `end`, each with the offset it starts at
    early: Vec<(u64, Vec<u8>)>,
}

impl Assembler {
    pub fn push(&mut self, offset: u64, data: &[u8]) {
        if offset > self.end {
            // Out of order. Keeping it whole is enough; it is looked at again
            // only when the gap in front of it is filled.
            self.early.push((offset, data.to_vec()));
            return;
        }
        self.append(offset, data);
        if !self.early.is_empty() {
            self.drain_early();
        }
    }

    /// Append the part of `data` that is not already held
    fn append(&mut self, offset: u64, data: &[u8]) {
        let skip = (self.end - offset) as usize;
        if let Some(fresh) = data.get(skip..) {
            self.buf.extend_from_slice(fresh);
            self.end += fresh.len() as u64;
        }
    }

    #[cold]
    fn drain_early(&mut self) {
        loop {
            let Some(i) = self
                .early
                .iter()
                .position(|(o, d)| *o <= self.end && *o + d.len() as u64 > self.end)
            else {
                // Drop what is wholly behind us and stop
                self.early.retain(|(o, d)| *o + d.len() as u64 > self.end);
                return;
            };
            let (offset, data) = self.early.swap_remove(i);
            self.append(offset, &data);
        }
    }

    pub fn read(&self) -> &[u8] {
        &self.buf
    }

    pub fn consume(&mut self, n: usize) {
        self.buf.drain(..n.min(self.buf.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_in_order_is_just_appended() {
        let mut a = Assembler::default();
        a.push(0, b"abc");
        a.push(3, b"def");
        assert_eq!(a.read(), b"abcdef");
        a.consume(4);
        assert_eq!(a.read(), b"ef");
    }

    #[test]
    fn data_that_arrives_early_waits_for_the_gap_to_fill() {
        let mut a = Assembler::default();
        a.push(6, b"ghi");
        a.push(3, b"def");
        assert_eq!(a.read(), b"", "nothing contiguous yet");
        a.push(0, b"abc");
        assert_eq!(a.read(), b"abcdefghi");
    }

    /// A retransmission repeats what already arrived, and must not be appended
    /// a second time
    #[test]
    fn data_that_arrives_twice_is_counted_once() {
        let mut a = Assembler::default();
        a.push(0, b"abcdef");
        a.push(0, b"abcdef");
        a.push(3, b"defghi");
        assert_eq!(a.read(), b"abcdefghi");
    }

    #[test]
    fn fragment_permutations_match_byte_coverage_with_partial_reads() {
        fn check(order: &[usize]) {
            let bytes: Vec<_> = (0..48).map(|i| (i * 37 + 11) as u8).collect();
            let mut covered = [false; 48];
            let mut consumed = 0;
            let mut a = Assembler::default();
            for (step, &chunk) in order.iter().enumerate() {
                let start = chunk * 8;
                let end = start + 8;
                // Same-offset duplicates and overlaps use new fragment pushes.
                for (start, end) in [
                    (start, end),
                    (start, end),
                    (start.saturating_sub(3), (end + 3).min(bytes.len())),
                ] {
                    a.push(start as u64, &bytes[start..end]);
                    covered[start..end].fill(true);
                    let available = covered.iter().take_while(|&&v| v).count();
                    assert_eq!(a.read(), &bytes[consumed..available], "{order:?}");
                    if step % 2 == 0 {
                        let n = a.read().len() / 2;
                        a.consume(n);
                        consumed += n;
                        assert_eq!(a.read(), &bytes[consumed..available]);
                    }
                }
            }
            assert_eq!(a.read(), &bytes[consumed..]);
            assert!(a.early.is_empty());
            a.consume(usize::MAX);
            a.push(0, &bytes);
            assert!(a.read().is_empty());
            a.push(bytes.len() as u64, b"next");
            assert_eq!(a.read(), b"next");
        }
        fn permute(order: &mut [usize], at: usize) {
            if at == order.len() {
                check(order);
            } else {
                for i in at..order.len() {
                    order.swap(at, i);
                    permute(order, at + 1);
                    order.swap(at, i);
                }
            }
        }
        permute(&mut [0, 1, 2, 3, 4, 5], 0);
    }

    #[test]
    fn independent_gaps_and_empty_fragments_do_not_release_missing_bytes() {
        let mut a = Assembler::default();
        a.push(12, b"mnop");
        a.push(4, b"ef");
        a.push(8, b"ijkl");
        a.push(6, b"");
        a.push(16, b"");
        a.push(0, b"ab");
        assert_eq!(a.read(), b"ab");
        a.consume(2);
        a.push(2, b"cd");
        assert_eq!(a.read(), b"cdef");
        a.consume(3);
        a.push(0, b"abcdef");
        assert_eq!(a.read(), b"f");
        a.push(6, b"gh");
        assert_eq!(a.read(), b"fghijklmnop");
        assert!(a.early.is_empty());
    }

    #[test]
    fn long_reversed_fragment_chain_and_duplicates_deliver_exactly_once() {
        let bytes: Vec<_> = (0..4096).map(|i| (i * 17) as u8).collect();
        let mut a = Assembler::default();
        for i in (1..bytes.len()).rev() {
            a.push(i as u64, &bytes[i..i + 1]);
            a.push(i as u64, &bytes[i..(i + 4).min(bytes.len())]);
        }
        assert!(a.read().is_empty());
        a.push(0, &bytes[..1]);
        assert_eq!(a.read(), bytes);
        assert!(a.early.is_empty());
        a.consume(bytes.len());
        a.push(0, &bytes);
        assert!(a.read().is_empty());
    }

    #[test]
    fn repeated_gap_closures_across_queue_size_boundaries_deliver_once() {
        for count in [31, 32, 63, 64, 65, 66, 127, 128] {
            let mut a = Assembler::default();
            let mut offset = 0;
            // Reuse the queue after a large flight, including when the first
            // gap closure leaves only a small suffix behind another hole.
            for _ in 0..3 {
                let bytes: Vec<_> = (0..count + 2).map(|i| (i * 29 + 3) as u8).collect();
                let gap = bytes.len() / 2;
                for i in (1..bytes.len()).rev().filter(|&i| i != gap) {
                    a.push(offset + i as u64, &bytes[i..i + 1]);
                }
                assert!(a.read().is_empty());
                a.push(offset, &bytes[..1]);
                assert_eq!(a.read(), &bytes[..gap]);
                a.consume(gap);
                a.push(offset + gap as u64 + 1, &bytes[gap + 1..]);
                assert!(a.read().is_empty());
                a.push(offset + gap as u64, &bytes[gap..gap + 1]);
                assert_eq!(a.read(), &bytes[gap..]);
                assert!(a.early.is_empty());
                a.consume(usize::MAX);
                a.push(offset, &bytes);
                assert!(a.read().is_empty());
                offset += bytes.len() as u64;
            }
        }
    }
}
