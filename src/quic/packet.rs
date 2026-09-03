//! Packet headers (RFC 9000 Section 17)
//!
//! Only as much as a server needs: enough of a long header to route a packet
//! to its connection and find where the protected part starts, and a short
//! header read against the connection id length this server hands out.

use super::wire::{varint_len, ConnectionId, Error, Reader, Result};

/// QUIC version 1 (RFC 9000 Section 15)
pub const VERSION_1: u32 = 0x0000_0001;

/// The connection ids this server issues. One byte is enough to be unique per
/// worker and keeps every short header a byte shorter; the routing that
/// matters is done by the kernel, which hands a client's datagrams to the same
/// socket for as long as its address does not change.
pub const LOCAL_CID_LEN: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Space {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
}

impl Kind {
    pub fn space(self) -> Option<Space> {
        match self {
            Kind::Initial => Some(Space::Initial),
            Kind::Handshake => Some(Space::Handshake),
            Kind::Short | Kind::ZeroRtt => Some(Space::Data),
            Kind::Retry => None,
        }
    }
}

pub struct Header<'a> {
    pub kind: Kind,
    pub dcid: ConnectionId,
    /// The peer's own id, which only a long header carries
    pub scid: ConnectionId,
    pub version: u32,
    pub token: &'a [u8],
    /// Where the packet number starts, counted from the start of the datagram
    pub pn_offset: usize,
    /// Where this packet ends. A long header says so; a short header runs to
    /// the end of the datagram.
    pub end: usize,
}

/// Read the header of the packet starting at `at` in `datagram`
///
/// A datagram may hold several packets, one after another, as long as every
/// one but the last has a long header (RFC 9000 Section 12.2).
pub fn parse(datagram: &[u8], at: usize) -> Result<Header<'_>> {
    let mut r = Reader::new(&datagram[at.min(datagram.len())..]);
    let first = r.peek()?;
    if first & 0x80 == 0 {
        // Short header: the id is ours, so its length is not on the wire
        r.byte()?;
        let dcid = ConnectionId::new(r.slice(LOCAL_CID_LEN)?)?;
        return Ok(Header {
            kind: Kind::Short,
            dcid,
            scid: ConnectionId::default(),
            version: VERSION_1,
            token: &[],
            pn_offset: at + r.position(),
            end: datagram.len(),
        });
    }

    r.byte()?;
    let version = u32::from_be_bytes(r.slice(4)?.try_into().map_err(|_| Error)?);
    let dcid_len = r.byte()? as usize;
    let dcid = ConnectionId::new(r.slice(dcid_len)?)?;
    let scid_len = r.byte()? as usize;
    let scid = ConnectionId::new(r.slice(scid_len)?)?;

    // A version this server does not speak has no defined shape past here
    if version != VERSION_1 {
        return Err(Error);
    }
    let kind = match (first >> 4) & 0x03 {
        0 => Kind::Initial,
        1 => Kind::ZeroRtt,
        2 => Kind::Handshake,
        _ => Kind::Retry,
    };
    if kind == Kind::Retry {
        // Nothing follows that this server reads: a client does not send one
        return Ok(Header {
            kind,
            dcid,
            scid,
            version,
            token: &[],
            pn_offset: at + r.position(),
            end: datagram.len(),
        });
    }

    let token = match kind {
        Kind::Initial => r.varint_slice()?,
        _ => &[],
    };
    let length = r.varint()?;
    let pn_offset = at + r.position();
    let end = pn_offset
        .checked_add(usize::try_from(length).map_err(|_| Error)?)
        .ok_or(Error)?;
    if end > datagram.len() {
        return Err(Error);
    }
    Ok(Header {
        kind,
        dcid,
        scid,
        version,
        token,
        pn_offset,
        end,
    })
}

/// Write a long header, leaving the length field to be filled in later
///
/// Returns where the length field starts, since its value is only known once
/// the payload has been written and encrypted.
pub fn put_long_header(
    out: &mut Vec<u8>,
    kind: Kind,
    dcid: &ConnectionId,
    scid: &ConnectionId,
    pn_len: usize,
    payload_hint: usize,
) -> usize {
    let ty = match kind {
        Kind::Initial => 0,
        Kind::ZeroRtt => 1,
        Kind::Handshake => 2,
        Kind::Retry | Kind::Short => 3,
    };
    out.push(0xc0 | (ty << 4) | (pn_len as u8 - 1));
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid.as_slice());
    out.push(scid.len() as u8);
    out.extend_from_slice(scid.as_slice());
    if kind == Kind::Initial {
        out.push(0); // no token: this server does not send Retry
    }
    let length_at = out.len();
    // Reserved so the payload lands where it will finally sit; the value is
    // written back once the packet is whole.
    let length = (payload_hint + pn_len + super::TAG_LEN) as u64;
    super::wire::put_varint(out, length.max(0x4000));
    length_at
}

/// The width the length field was reserved at, so it can be overwritten
pub const LENGTH_FIELD_LEN: usize = 4;

/// Overwrite the reserved length field now that the packet is whole
pub fn patch_length(out: &mut [u8], length_at: usize, length: u64) -> Result<()> {
    let field = out
        .get_mut(length_at..length_at + LENGTH_FIELD_LEN)
        .ok_or(Error)?;
    if varint_len(length) > LENGTH_FIELD_LEN {
        return Err(Error);
    }
    field.copy_from_slice(&(length as u32 | 0x8000_0000).to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long(kind: u8, dcid: &[u8], scid: &[u8], token: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xc0 | (kind << 4)];
        v.extend_from_slice(&VERSION_1.to_be_bytes());
        v.push(dcid.len() as u8);
        v.extend_from_slice(dcid);
        v.push(scid.len() as u8);
        v.extend_from_slice(scid);
        if kind == 0 {
            super::super::wire::put_varint(&mut v, token.len() as u64);
            v.extend_from_slice(token);
        }
        super::super::wire::put_varint(&mut v, payload.len() as u64);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn an_initial_gives_up_its_ids_and_its_token() {
        let d = long(0, &[1, 2, 3, 4], &[9, 9], b"tok", &[0xaa; 40]);
        let h = parse(&d, 0).unwrap();
        assert_eq!(h.kind, Kind::Initial);
        assert_eq!(h.dcid.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(h.scid.as_slice(), &[9, 9]);
        assert_eq!(h.token, b"tok");
        assert_eq!(h.end, d.len());
        assert_eq!(h.kind.space(), Some(Space::Initial));
    }

    /// Two packets in one datagram, which is how a client's Initial and
    /// Handshake arrive together
    #[test]
    fn a_datagram_can_carry_a_second_packet() {
        let mut d = long(0, &[1, 2, 3, 4], &[], b"", &[0xaa; 30]);
        let first_end = d.len();
        d.extend_from_slice(&long(2, &[1, 2, 3, 4], &[], b"", &[0xbb; 20]));
        let h = parse(&d, 0).unwrap();
        assert_eq!(h.end, first_end);
        let h2 = parse(&d, h.end).unwrap();
        assert_eq!(h2.kind, Kind::Handshake);
        assert_eq!(h2.end, d.len());
    }

    #[test]
    fn a_short_header_is_read_against_our_own_id_length() {
        let mut d = vec![0x40];
        d.extend_from_slice(&[7u8; LOCAL_CID_LEN]);
        d.extend_from_slice(&[0xcc; 30]);
        let h = parse(&d, 0).unwrap();
        assert_eq!(h.kind, Kind::Short);
        assert_eq!(h.dcid.as_slice(), &[7u8; LOCAL_CID_LEN]);
        assert_eq!(h.pn_offset, 1 + LOCAL_CID_LEN);
        assert_eq!(h.end, d.len());
    }

    #[test]
    fn a_packet_that_claims_more_than_it_has_is_refused() {
        let mut d = long(2, &[1], &[], b"", &[0xaa; 10]);
        // Say the payload is longer than the datagram
        let n = d.len();
        d[n - 11] = 0x7f;
        assert!(parse(&d, 0).is_err());
    }

    #[test]
    fn another_version_is_not_parsed_past_the_ids() {
        let mut d = long(0, &[1], &[], b"", &[0xaa; 10]);
        d[1..5].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert!(parse(&d, 0).is_err());
    }

    #[test]
    fn a_reserved_length_field_can_be_written_back() {
        let mut out = Vec::new();
        let dcid = ConnectionId::new(&[1, 2, 3]).unwrap();
        let scid = ConnectionId::new(&[4]).unwrap();
        let at = put_long_header(&mut out, Kind::Handshake, &dcid, &scid, 2, 100);
        assert_eq!(out.len() - at, LENGTH_FIELD_LEN);
        patch_length(&mut out, at, 118).unwrap();
        let h = {
            out.extend_from_slice(&[0u8; 118]);
            parse(&out, 0).unwrap()
        };
        assert_eq!(h.kind, Kind::Handshake);
        assert_eq!(h.end, out.len());
    }
}
