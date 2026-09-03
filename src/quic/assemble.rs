//! Putting a stream back in order
//!
//! Both CRYPTO and STREAM data arrive at an offset and may arrive out of
//! order. Almost always they arrive in order and this is an append, so the
//! out-of-order case is kept out of the way rather than made fast.

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
    /// The offset the peer said the stream ends at, once it has said so
    fin: Option<u64>,
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

    /// Note that the stream ends here
    pub fn finish(&mut self, offset: u64) {
        self.fin = Some(offset);
    }

    /// Whether everything the peer sent has arrived and been read
    pub fn is_finished(&self) -> bool {
        self.fin == Some(self.end) && self.buf.is_empty()
    }

    /// Whether the peer has said where the stream ends and everything up to
    /// there has arrived
    pub fn is_complete(&self) -> bool {
        self.fin == Some(self.end)
    }

    pub fn read(&self) -> &[u8] {
        &self.buf
    }

    pub fn consume(&mut self, n: usize) {
        self.buf.drain(..n.min(self.buf.len()));
    }

    /// Give the buffer back for the next stream on this connection to use
    pub fn take_buf(&mut self) -> Vec<u8> {
        self.early.clear();
        self.end = 0;
        self.fin = None;
        let mut buf = std::mem::take(&mut self.buf);
        buf.clear();
        buf
    }

    pub fn with_buf(buf: Vec<u8>) -> Self {
        Assembler {
            buf,
            end: 0,
            early: Vec::new(),
            fin: None,
        }
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
    fn a_stream_is_finished_once_everything_up_to_the_end_has_arrived() {
        let mut a = Assembler::default();
        a.push(0, b"abc");
        a.finish(6);
        assert!(!a.is_complete());
        a.push(3, b"def");
        assert!(a.is_complete());
        assert!(!a.is_finished(), "not read yet");
        a.consume(6);
        assert!(a.is_finished());
    }

    #[test]
    fn a_buffer_comes_back_empty_and_reusable() {
        let mut a = Assembler::default();
        a.push(0, b"abc");
        a.push(9, b"early");
        a.finish(3);
        let buf = a.take_buf();
        assert!(buf.is_empty());
        let mut a = Assembler::with_buf(buf);
        a.push(0, b"xy");
        assert_eq!(a.read(), b"xy");
        assert!(!a.is_complete(), "the old fin did not carry over");
    }
}
