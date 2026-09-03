//! The bytes on the wire: variable-length integers, connection ids, packet
//! numbers and header protection (RFC 9000 Sections 16 and 17, RFC 9001
//! Section 5.4)

use rustls::quic::HeaderProtectionKey;

pub type Result<T> = std::result::Result<T, Error>;

/// Anything wrong with a packet is a reason to drop it, and QUIC says so:
/// a datagram that cannot be parsed or decrypted is discarded rather than
/// answered (RFC 9000 Section 5.2). So there is one error and no detail.
#[derive(Debug, PartialEq, Eq)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed QUIC packet")
    }
}

// ---- variable-length integers (RFC 9000 Section 16) -----------------------

/// Reads from a packet, refusing to run off the end
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn peek(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(Error)
    }

    pub fn slice(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error)?;
        let s = self.buf.get(self.pos..end).ok_or(Error)?;
        self.pos = end;
        Ok(s)
    }

    /// The two most significant bits of the first byte say how many bytes the
    /// whole number takes: one, two, four or eight.
    pub fn varint(&mut self) -> Result<u64> {
        let first = self.byte()?;
        let len = 1usize << (first >> 6);
        let mut v = (first & 0x3f) as u64;
        for _ in 1..len {
            v = (v << 8) | self.byte()? as u64;
        }
        Ok(v)
    }

    /// A length-prefixed run of bytes, which is how most frames carry data
    pub fn varint_slice(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        self.slice(usize::try_from(n).map_err(|_| Error)?)
    }

    /// The bytes between an earlier position and where the reader is now
    pub fn slice_between(&self, start: usize) -> Result<&'a [u8]> {
        self.buf.get(start..self.pos).ok_or(Error)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let r = &self.buf[self.pos.min(self.buf.len())..];
        self.pos = self.buf.len();
        r
    }
}

/// How many bytes `v` takes as a varint
pub const fn varint_len(v: u64) -> usize {
    match v {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

// ---- connection ids -------------------------------------------------------

/// RFC 9000 Section 17.2: at most 20 bytes, and inline rather than boxed
/// because one is compared and copied on every packet.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; Self::MAX],
}

impl ConnectionId {
    pub const MAX: usize = 20;

    pub fn new(slice: &[u8]) -> Result<Self> {
        if slice.len() > Self::MAX {
            return Err(Error);
        }
        let mut bytes = [0u8; Self::MAX];
        bytes[..slice.len()].copy_from_slice(slice);
        Ok(ConnectionId {
            len: slice.len() as u8,
            bytes,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }
}

// ---- packet numbers (RFC 9000 Appendix A) ---------------------------------

/// The fewest bytes that leave `pn` unambiguous against what the peer has
/// already acknowledged
pub fn encode_packet_number(pn: u64, largest_acked: Option<u64>) -> (u64, usize) {
    // RFC 9000 Section 17.1: the width has to represent more than twice the
    // distance from what the peer has acknowledged, or the two candidates the
    // peer picks between are equally near
    let range = 2 * match largest_acked {
        Some(l) => pn.saturating_sub(l),
        None => pn + 1,
    };
    let len = match range {
        0..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xff_ffff => 3,
        _ => 4,
    };
    let mask = if len == 8 {
        u64::MAX
    } else {
        (1 << (len * 8)) - 1
    };
    (pn & mask, len)
}

/// Widen a truncated packet number to the one nearest what we expect next
pub fn decode_packet_number(largest_pn: u64, truncated: u64, nbits: u32) -> u64 {
    let win = 1u64 << nbits;
    let half = win / 2;
    let expected = largest_pn.wrapping_add(1);
    let candidate = (expected & !(win - 1)) | truncated;
    if candidate + half <= expected && candidate + win < (1 << 62) {
        candidate + win
    } else if candidate > expected + half && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

// ---- header protection (RFC 9001 Section 5.4) -----------------------------

const SAMPLE_OFFSET: usize = 4;
const SAMPLE_LEN: usize = 16;

/// Mask the first byte and the packet number in place. The packet must already
/// be encrypted, because the mask comes from its ciphertext.
pub fn protect_header(
    hp: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: usize,
) -> Result<()> {
    let sample = sample(packet, pn_offset)?;
    let (first, rest) = packet.split_at_mut(1);
    let pn = rest
        .get_mut(pn_offset - 1..pn_offset - 1 + pn_len)
        .ok_or(Error)?;
    hp.encrypt_in_place(&sample, &mut first[0], pn)
        .map_err(|_| Error)
}

/// Undo header protection, returning the revealed first byte and the packet
/// number length it names
pub fn unprotect_header(
    hp: &dyn HeaderProtectionKey,
    packet: &mut [u8],
    pn_offset: usize,
) -> Result<(u8, usize)> {
    let sample = sample(packet, pn_offset)?;
    let (first, rest) = packet.split_at_mut(1);
    // The length lives in bits the mask also covers, so unmask the longest a
    // packet number can be and read the length back out of the first byte
    let pn = rest
        .get_mut(pn_offset - 1..pn_offset - 1 + 4)
        .ok_or(Error)?;
    hp.decrypt_in_place(&sample, &mut first[0], pn)
        .map_err(|_| Error)?;
    Ok((first[0], (first[0] & 0x03) as usize + 1))
}

fn sample(packet: &[u8], pn_offset: usize) -> Result<[u8; SAMPLE_LEN]> {
    let start = pn_offset + SAMPLE_OFFSET;
    let s = packet.get(start..start + SAMPLE_LEN).ok_or(Error)?;
    let mut out = [0u8; SAMPLE_LEN];
    out.copy_from_slice(s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9000 Appendix A.1 gives these as the worked examples
    #[test]
    fn varints_round_trip_at_every_width() {
        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1073741823,
            1073741824,
            (1 << 62) - 1,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            assert_eq!(out.len(), varint_len(v), "width of {v}");
            assert_eq!(Reader::new(&out).varint(), Ok(v));
        }
    }

    /// The spec's own examples of the encoding, byte for byte
    #[test]
    fn varints_match_the_spec() {
        let mut out = Vec::new();
        put_varint(&mut out, 151_288_809_941_952_652);
        assert_eq!(out, [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        assert_eq!(
            Reader::new(&[0x9d, 0x7f, 0x3e, 0x7d]).varint(),
            Ok(494_878_333)
        );
        assert_eq!(Reader::new(&[0x7b, 0xbd]).varint(), Ok(15_293));
        assert_eq!(Reader::new(&[0x25]).varint(), Ok(37));
    }

    #[test]
    fn a_reader_stops_at_the_end() {
        let mut r = Reader::new(&[0x40]);
        assert_eq!(
            r.varint(),
            Err(Error),
            "two-byte varint, one byte of buffer"
        );
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.slice(4), Err(Error));
        assert_eq!(r.slice(3), Ok(&[1u8, 2, 3][..]));
        assert!(r.is_empty());
    }

    /// RFC 9000 Appendix A.2
    #[test]
    fn packet_numbers_are_truncated_to_what_is_unambiguous() {
        assert_eq!(encode_packet_number(0xac5c02, Some(0xabe8b3)), (0x5c02, 2));
        assert_eq!(
            encode_packet_number(0xace8fe, Some(0xabe8b3)),
            (0xace8fe, 3)
        );
    }

    /// RFC 9000 Appendix A.3
    #[test]
    fn packet_numbers_widen_to_the_nearest_candidate() {
        assert_eq!(decode_packet_number(0xa82f30ea, 0x9b32, 16), 0xa82f9b32);
    }

    #[test]
    fn a_connection_id_is_at_most_twenty_bytes() {
        assert!(ConnectionId::new(&[0u8; 21]).is_err());
        let id = ConnectionId::new(&[1, 2, 3]).unwrap();
        assert_eq!(id.as_slice(), &[1, 2, 3]);
        assert_eq!(id.len(), 3);
        assert_eq!(ConnectionId::new(&[]).unwrap().len(), 0);
    }
}
