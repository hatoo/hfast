//! Frames (RFC 9000 Section 19)
//!
//! Only the ones a server has to understand to answer a well-behaved client.
//! Anything else with a known shape is skipped rather than refused, because a
//! frame this server has no use for is not a reason to drop the connection.

use super::wire::{Error, Reader, Result, put_varint, varint_len};

pub const PADDING: u64 = 0x00;
pub const PING: u64 = 0x01;
pub const ACK: u64 = 0x02;
pub const RESET_STREAM: u64 = 0x04;
pub const CRYPTO: u64 = 0x06;
pub const STREAM: u64 = 0x08;
pub const MAX_DATA: u64 = 0x10;
pub const MAX_STREAM_DATA: u64 = 0x11;
pub const MAX_STREAMS_BIDI: u64 = 0x12;
pub const PATH_CHALLENGE: u64 = 0x1a;
pub const PATH_RESPONSE: u64 = 0x1b;
pub const CONNECTION_CLOSE: u64 = 0x1c;
pub const HANDSHAKE_DONE: u64 = 0x1e;

#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    /// Largest acknowledged, and the ranges below it, newest first
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
        /// The raw gap/range pairs, walked by [`AckRanges`]
        rest: &'a [u8],
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        limit: u64,
    },
    MaxStreams {
        bidi: bool,
        limit: u64,
    },
    StopSending {
        id: u64,
        error_code: u64,
    },
    ResetStream {
        id: u64,
        error_code: u64,
        final_size: u64,
    },
    PathChallenge([u8; 8]),
    Close,
    /// A frame with a known shape and nothing here to do about it
    Ignored,
}

/// Walks the frames in a decrypted payload
pub struct Frames<'a> {
    r: Reader<'a>,
}

impl<'a> Frames<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Frames {
            r: Reader::new(payload),
        }
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        Some(read_frame(&mut self.r))
    }
}

fn read_frame<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>> {
    let ty = r.varint()?;
    Ok(match ty {
        PADDING => {
            // A run of them is one frame's worth of work, not one each: a
            // 1200-byte Initial is mostly padding
            while r.peek() == Ok(0) {
                r.byte()?;
            }
            Frame::Padding
        }
        PING => Frame::Ping,
        ACK | 0x03 => {
            let largest = r.varint()?;
            let delay = r.varint()?;
            let count = r.varint()?;
            let first_range = r.varint()?;
            let start = r.position();
            for _ in 0..count {
                r.varint()?;
                r.varint()?;
            }
            let rest = r.slice_between(start)?;
            if ty == 0x03 {
                // ECN counts
                for _ in 0..3 {
                    r.varint()?;
                }
            }
            Frame::Ack {
                largest,
                delay,
                first_range,
                rest,
            }
        }
        RESET_STREAM => {
            let id = r.varint()?;
            let error_code = r.varint()?;
            let final_size = r.varint()?;
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            }
        }
        0x05 => {
            let id = r.varint()?;
            let error_code = r.varint()?;
            Frame::StopSending { id, error_code }
        }
        CRYPTO => {
            let offset = r.varint()?;
            let data = r.varint_slice()?;
            Frame::Crypto { offset, data }
        }
        0x07 => {
            r.varint_slice()?;
            Frame::Ignored
        }
        0x08..=0x0f => {
            let id = r.varint()?;
            let offset = if ty & 0x04 != 0 { r.varint()? } else { 0 };
            let data = if ty & 0x02 != 0 {
                r.varint_slice()?
            } else {
                r.rest()
            };
            Frame::Stream {
                id,
                offset,
                data,
                fin: ty & 0x01 != 0,
            }
        }
        MAX_DATA => Frame::MaxData(r.varint()?),
        MAX_STREAM_DATA => {
            let id = r.varint()?;
            Frame::MaxStreamData {
                id,
                limit: r.varint()?,
            }
        }
        MAX_STREAMS_BIDI | 0x13 => Frame::MaxStreams {
            bidi: ty == MAX_STREAMS_BIDI,
            limit: r.varint()?,
        },
        0x14 | 0x16 | 0x17 => {
            r.varint()?;
            Frame::Ignored
        }
        0x15 => {
            r.varint()?;
            r.varint()?;
            Frame::Ignored
        }
        0x18 => {
            r.varint()?;
            r.varint()?;
            let len = r.byte()? as usize;
            r.slice(len)?;
            r.slice(16)?;
            Frame::Ignored
        }
        0x19 => {
            r.varint()?;
            Frame::Ignored
        }
        PATH_CHALLENGE | PATH_RESPONSE => {
            let data: [u8; 8] = r.slice(8)?.try_into().map_err(|_| Error)?;
            match ty {
                PATH_CHALLENGE => Frame::PathChallenge(data),
                _ => Frame::Ignored,
            }
        }
        CONNECTION_CLOSE | 0x1d => {
            r.varint()?;
            if ty == CONNECTION_CLOSE {
                r.varint()?;
            }
            r.varint_slice()?;
            Frame::Close
        }
        HANDSHAKE_DONE => Frame::Ignored,
        _ => return Err(Error),
    })
}

/// The ranges an ACK frame acknowledges, largest first
pub struct AckRanges<'a> {
    r: Reader<'a>,
    next_largest: u64,
    first: Option<(u64, u64)>,
}

impl<'a> AckRanges<'a> {
    pub fn new(largest: u64, first_range: u64, rest: &'a [u8]) -> Self {
        AckRanges {
            r: Reader::new(rest),
            next_largest: largest.saturating_sub(first_range),
            first: Some((largest.saturating_sub(first_range), largest)),
        }
    }
}

impl Iterator for AckRanges<'_> {
    /// `(smallest, largest)`, inclusive
    type Item = (u64, u64);

    fn next(&mut self) -> Option<(u64, u64)> {
        if let Some(f) = self.first.take() {
            return Some(f);
        }
        let gap = self.r.varint().ok()?;
        let len = self.r.varint().ok()?;
        let largest = self.next_largest.checked_sub(gap + 2)?;
        let smallest = largest.checked_sub(len)?;
        self.next_largest = smallest;
        Some((smallest, largest))
    }
}

// ---- writing --------------------------------------------------------------

pub fn put_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    put_varint(out, CRYPTO);
    put_varint(out, offset);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// A STREAM frame with an explicit offset and length, so it can be followed by
/// another frame in the same packet
pub fn put_stream(out: &mut Vec<u8>, id: u64, offset: u64, fin: bool, data: &[u8]) {
    put_varint(out, STREAM | 0x04 | 0x02 | u64::from(fin));
    put_varint(out, id);
    put_varint(out, offset);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// What a STREAM frame costs before its data
pub fn stream_overhead(id: u64, offset: u64, len: usize) -> usize {
    1 + varint_len(id) + varint_len(offset) + varint_len(len as u64)
}

pub fn put_ack(out: &mut Vec<u8>, ranges: &[(u64, u64)], delay: u64) {
    let Some(&(first_smallest, largest)) = ranges.first() else {
        return;
    };
    put_varint(out, ACK);
    put_varint(out, largest);
    put_varint(out, delay);
    put_varint(out, ranges.len() as u64 - 1);
    put_varint(out, largest - first_smallest);
    let mut next_largest = first_smallest;
    for &(smallest, largest) in &ranges[1..] {
        put_varint(out, next_largest - largest - 2);
        put_varint(out, largest - smallest);
        next_largest = smallest;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(payload: &[u8]) -> Vec<Frame<'_>> {
        Frames::new(payload).map(|f| f.unwrap()).collect()
    }

    #[test]
    fn a_stream_frame_gives_up_its_pieces() {
        let mut out = Vec::new();
        put_stream(&mut out, 4, 100, true, b"hello");
        assert_eq!(
            frames(&out),
            [Frame::Stream {
                id: 4,
                offset: 100,
                data: b"hello",
                fin: true
            }]
        );
    }

    /// A STREAM frame without the LEN bit runs to the end of the packet
    #[test]
    fn a_stream_frame_can_run_to_the_end() {
        let mut out = vec![0x08 | 0x04];
        put_varint(&mut out, 8);
        put_varint(&mut out, 0);
        out.extend_from_slice(b"tail");
        assert_eq!(
            frames(&out),
            [Frame::Stream {
                id: 8,
                offset: 0,
                data: b"tail",
                fin: false
            }]
        );
    }

    #[test]
    fn padding_is_one_frame_however_long_it_runs() {
        let mut out = vec![0u8; 1000];
        out.push(0x01);
        assert_eq!(frames(&out), [Frame::Padding, Frame::Ping]);
    }

    #[test]
    fn ack_ranges_come_back_largest_first() {
        let ranges = [(90u64, 100u64), (80, 85), (70, 70)];
        let mut out = Vec::new();
        put_ack(&mut out, &ranges, 3);
        let Frame::Ack {
            largest,
            delay,
            first_range,
            rest,
        } = frames(&out).pop().unwrap()
        else {
            panic!("not an ack");
        };
        assert_eq!((largest, delay), (100, 3));
        let back: Vec<_> = AckRanges::new(largest, first_range, rest).collect();
        assert_eq!(back, ranges);
    }

    #[test]
    fn crypto_round_trips() {
        let mut out = Vec::new();
        put_crypto(&mut out, 42, b"tls");
        assert_eq!(
            frames(&out),
            [Frame::Crypto {
                offset: 42,
                data: b"tls"
            }]
        );
    }

    #[test]
    fn an_unknown_frame_type_is_an_error() {
        assert!(Frames::new(&[0x3f]).next().unwrap().is_err());
    }

    #[test]
    fn reset_and_stop_preserve_fields_and_reject_truncation() {
        let mut reset = vec![RESET_STREAM as u8];
        for value in [1 << 30, 0x10c, (1 << 40) + 3] {
            put_varint(&mut reset, value);
        }
        assert_eq!(
            frames(&reset),
            [Frame::ResetStream {
                id: 1 << 30,
                error_code: 0x10c,
                final_size: (1 << 40) + 3,
            }]
        );
        for n in 1..reset.len() {
            assert!(Frames::new(&reset[..n]).next().unwrap().is_err());
        }
        let mut stop = vec![0x05];
        for value in [8, 0x10c] {
            put_varint(&mut stop, value);
        }
        assert_eq!(
            frames(&stop),
            [Frame::StopSending {
                id: 8,
                error_code: 0x10c
            }]
        );
        for n in 1..stop.len() {
            assert!(Frames::new(&stop[..n]).next().unwrap().is_err());
        }
    }

    #[test]
    fn the_frames_a_client_sends_that_need_no_answer_are_skipped() {
        // NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, DATA_BLOCKED
        let mut out = vec![0x18];
        put_varint(&mut out, 1);
        put_varint(&mut out, 0);
        out.push(4);
        out.extend_from_slice(&[9, 9, 9, 9]);
        out.extend_from_slice(&[0u8; 16]);
        out.push(0x19);
        put_varint(&mut out, 0);
        out.push(0x14);
        put_varint(&mut out, 1000);
        assert_eq!(
            frames(&out),
            [Frame::Ignored, Frame::Ignored, Frame::Ignored]
        );
    }
}
