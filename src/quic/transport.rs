//! Transport parameters (RFC 9000 Section 18)
//!
//! They ride inside the TLS handshake as an extension, so rustls carries them
//! and this only says what they mean.

use super::wire::{ConnectionId, Reader, Result, put_varint};

const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const MAX_IDLE_TIMEOUT: u64 = 0x01;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;

/// What the peer told us it will accept
#[derive(Debug, Clone, Copy)]
pub struct Peer {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_udp_payload_size: u64,
    pub ack_delay_exponent: u32,
    pub max_ack_delay: u64,
}

impl Default for Peer {
    /// RFC 9000 Section 18.2 gives every one of these a default, and a peer
    /// that says nothing means the default rather than zero.
    fn default() -> Self {
        Peer {
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_udp_payload_size: 65527,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
        }
    }
}

pub fn decode(buf: &[u8]) -> Result<Peer> {
    let mut p = Peer::default();
    let mut r = Reader::new(buf);
    while !r.is_empty() {
        let id = r.varint()?;
        let body = r.varint_slice()?;
        let mut v = Reader::new(body);
        match id {
            INITIAL_MAX_DATA => p.initial_max_data = v.varint()?,
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                p.initial_max_stream_data_bidi_local = v.varint()?
            }
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                p.initial_max_stream_data_bidi_remote = v.varint()?
            }
            INITIAL_MAX_STREAM_DATA_UNI => p.initial_max_stream_data_uni = v.varint()?,
            INITIAL_MAX_STREAMS_BIDI => p.initial_max_streams_bidi = v.varint()?,
            INITIAL_MAX_STREAMS_UNI => p.initial_max_streams_uni = v.varint()?,
            MAX_UDP_PAYLOAD_SIZE => p.max_udp_payload_size = v.varint()?,
            ACK_DELAY_EXPONENT => p.ack_delay_exponent = v.varint()? as u32,
            MAX_ACK_DELAY => p.max_ack_delay = v.varint()?,
            // Everything else is either about a path this server does not
            // change or an id it does not hand out
            _ => {}
        }
    }
    Ok(p)
}

/// What this server offers
pub struct Local {
    /// The id the client addressed its first packet to, which a server has to
    /// echo so the client knows nobody rewrote it (RFC 9000 Section 7.3)
    pub original_dcid: ConnectionId,
    /// The id this server will answer to from now on
    pub initial_scid: ConnectionId,
    pub max_streams_bidi: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
}

pub fn encode(l: &Local) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    put_cid(
        &mut out,
        ORIGINAL_DESTINATION_CONNECTION_ID,
        &l.original_dcid,
    );
    put_cid(&mut out, INITIAL_SOURCE_CONNECTION_ID, &l.initial_scid);
    for (id, value) in [
        // Long enough that a run never idles out, short enough that a client
        // that walks away is eventually forgotten
        (MAX_IDLE_TIMEOUT, 30_000),
        (MAX_UDP_PAYLOAD_SIZE, super::MAX_DATAGRAM as u64),
        (INITIAL_MAX_DATA, l.initial_max_data),
        (
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            l.initial_max_stream_data,
        ),
        (
            INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            l.initial_max_stream_data,
        ),
        (INITIAL_MAX_STREAM_DATA_UNI, l.initial_max_stream_data),
        (INITIAL_MAX_STREAMS_BIDI, l.max_streams_bidi),
        // The client's control stream and its two QPACK streams
        (INITIAL_MAX_STREAMS_UNI, 8),
        (ACK_DELAY_EXPONENT, 3),
        (MAX_ACK_DELAY, 25),
    ] {
        put_varint(&mut out, id);
        put_varint(&mut out, super::wire::varint_len(value) as u64);
        put_varint(&mut out, value);
    }
    // A client that moves address mid-run is not something this answers
    put_varint(&mut out, DISABLE_ACTIVE_MIGRATION);
    put_varint(&mut out, 0);
    out
}

fn put_cid(out: &mut Vec<u8>, id: u64, cid: &ConnectionId) {
    put_varint(out, id);
    put_varint(out, cid.len() as u64);
    out.extend_from_slice(cid.as_slice());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_encoded_can_be_read_back() {
        let local = Local {
            original_dcid: ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            initial_scid: ConnectionId::new(&[9; 8]).unwrap(),
            max_streams_bidi: 1024,
            initial_max_data: 1 << 30,
            initial_max_stream_data: 1 << 20,
        };
        let p = decode(&encode(&local)).unwrap();
        assert_eq!(p.initial_max_streams_bidi, 1024);
        assert_eq!(p.initial_max_data, 1 << 30);
        assert_eq!(p.initial_max_stream_data_bidi_remote, 1 << 20);
        assert_eq!(p.max_udp_payload_size, super::super::MAX_DATAGRAM as u64);
        assert_eq!(p.ack_delay_exponent, 3);
    }

    /// A parameter this server has no use for must not stop it reading the
    /// ones it does
    #[test]
    fn unknown_parameters_are_skipped() {
        let mut buf = Vec::new();
        put_varint(&mut buf, 0x3fff); // no such parameter
        put_varint(&mut buf, 3);
        buf.extend_from_slice(&[1, 2, 3]);
        put_varint(&mut buf, INITIAL_MAX_DATA);
        put_varint(&mut buf, 4);
        put_varint(&mut buf, 1_000_000);
        assert_eq!(decode(&buf).unwrap().initial_max_data, 1_000_000);
    }

    #[test]
    fn a_peer_that_says_nothing_gets_the_defaults() {
        let p = decode(&[]).unwrap();
        assert_eq!(p.max_udp_payload_size, 65527);
        assert_eq!(p.ack_delay_exponent, 3);
        assert_eq!(p.max_ack_delay, 25);
        assert_eq!(p.initial_max_data, 0);
    }

    #[test]
    fn a_truncated_parameter_is_an_error() {
        let mut buf = Vec::new();
        put_varint(&mut buf, INITIAL_MAX_DATA);
        put_varint(&mut buf, 8);
        buf.extend_from_slice(&[0, 0]);
        assert!(decode(&buf).is_err());
    }
}
