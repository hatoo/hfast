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
}
