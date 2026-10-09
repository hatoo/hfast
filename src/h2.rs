//! HTTP/2 over cleartext, one constant response
//!
//! A request's stream id is in the clear in the frame header, and the response
//! is the same bytes every time, so neither direction needs an HPACK codec:
//! see the README for why that is allowed rather than merely convenient.

/// The client's connection preface (RFC 9113 Section 3.4), which is also what
/// tells this server it is not talking HTTP/1.1
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADER_LEN: usize = 9;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const CONTINUATION: u8 = 0x9;

/// ACK on a SETTINGS or a PING, END_STREAM on a DATA
const FLAG_ACK_OR_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// HPACK, static table only and no indexing, which is all a client that sends
/// `SETTINGS_HEADER_TABLE_SIZE = 0` will let the encoder use anyway.
///
/// `0x88`              indexed field 8, `:status: 200`
/// `0x0f 0x10 0x0a ..` literal without indexing, name 31 (content-type)
/// `0x0f 0x0d 0x02 ..` literal without indexing, name 28 (content-length)
const HEADER_BLOCK: &[u8] = b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33";
const BODY: &[u8] = b"Hello, World!";

/// Two entries: max concurrent streams and the initial window, both set out of
/// the way so a client never waits on this server for a credit.
const SERVER_SETTINGS: &[u8] = &[
    0, 0, 12, SETTINGS, 0, 0, 0, 0, 0, //
    0, 3, 0x7f, 0xff, 0xff, 0xff, // MAX_CONCURRENT_STREAMS
    0, 4, 0x7f, 0xff, 0xff, 0xff, // INITIAL_WINDOW_SIZE
];
const SETTINGS_ACK: &[u8] = &[0, 0, 0, SETTINGS, FLAG_ACK_OR_END_STREAM, 0, 0, 0, 0];

pub struct Conn {
    /// Stream whose header block is waiting for END_HEADERS, or zero. Only
    /// one block can be open on a connection; its payload need not be retained.
    header_stream: u32,
}

impl Conn {
    /// Queues the server's own SETTINGS, which RFC 9113 Section 3.4 requires to
    /// be the first thing it sends
    pub fn new(out: &mut Vec<u8>) -> Self {
        out.extend_from_slice(SERVER_SETTINGS);
        Conn { header_stream: 0 }
    }

    /// Answer every whole frame in `buf`, returning how many bytes were used,
    /// or `None` if the connection should close.
    pub fn drive(&mut self, buf: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        let mut at = 0;
        while buf.len() - at >= FRAME_HEADER_LEN {
            let h = &buf[at..];
            // The length is the top three bytes of the header and the type is
            // the fourth, so one 32-bit load carries both
            let head = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
            let len = (head >> 8) as usize;
            let kind = head as u8;
            let flags = h[4];
            let end = FRAME_HEADER_LEN + len;
            if h.len() < end {
                break;
            }
            let stream = u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]);
            let payload = &h[FRAME_HEADER_LEN..end];

            // RFC 9113 Section 6.10: a field block cannot be interleaved with
            // any other frame, including a CONTINUATION for another stream.
            if self.header_stream != 0 && (kind != CONTINUATION || stream != self.header_stream) {
                return None;
            }
            match kind {
                // Every request is the same request; the only thing worth
                // reading out of one is which stream to answer on.
                HEADERS => {
                    if stream == 0 {
                        return None;
                    }
                    if flags & FLAG_END_HEADERS != 0 {
                        respond(out, stream);
                    } else {
                        self.header_stream = stream;
                    }
                }
                CONTINUATION => {
                    if self.header_stream == 0 {
                        return None;
                    }
                    if flags & FLAG_END_HEADERS != 0 {
                        self.header_stream = 0;
                        respond(out, stream);
                    }
                }
                SETTINGS => {
                    if flags & FLAG_ACK_OR_END_STREAM == 0 {
                        out.extend_from_slice(SETTINGS_ACK);
                    }
                }
                PING => {
                    if flags & FLAG_ACK_OR_END_STREAM == 0 && len == 8 {
                        out.extend_from_slice(&[0, 0, 8, PING, FLAG_ACK_OR_END_STREAM, 0, 0, 0, 0]);
                        out.extend_from_slice(payload);
                    }
                }
                GOAWAY => return None,
                // WINDOW_UPDATE, RST_STREAM, PRIORITY and the
                // rest need no answer: this server's windows are never the
                // thing running out, and it holds no per-stream state to reset.
                _ => {}
            }
            at += end;
        }
        Some(at)
    }
}

#[inline(always)]
fn respond(out: &mut Vec<u8>, stream_id: u32) {
    let id = stream_id.to_be_bytes();
    out.reserve(2 * FRAME_HEADER_LEN + HEADER_BLOCK.len() + BODY.len());
    let n = HEADER_BLOCK.len() as u8;
    out.extend_from_slice(&[
        0,
        0,
        n,
        HEADERS,
        FLAG_END_HEADERS,
        id[0],
        id[1],
        id[2],
        id[3],
    ]);
    out.extend_from_slice(HEADER_BLOCK);
    let b = BODY.len() as u8;
    out.extend_from_slice(&[
        0,
        0,
        b,
        DATA,
        FLAG_ACK_OR_END_STREAM,
        id[0],
        id[1],
        id[2],
        id[3],
    ]);
    out.extend_from_slice(BODY);
}

#[cfg(test)]
mod continuation_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut v = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        v.extend_from_slice(&stream.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn the_first_thing_out_is_settings() {
        let mut out = Vec::new();
        let _ = Conn::new(&mut out);
        assert_eq!(
            &out[..FRAME_HEADER_LEN],
            &SERVER_SETTINGS[..FRAME_HEADER_LEN]
        );
    }

    #[test]
    fn a_headers_frame_is_answered_on_its_own_stream() {
        let mut out = Vec::new();
        let mut c = Conn::new(&mut out);
        out.clear();
        let f = frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_ACK_OR_END_STREAM,
            5,
            b"\x82",
        );
        assert_eq!(c.drive(&f, &mut out), Some(f.len()));
        // HEADERS then DATA, both on stream 5
        assert_eq!(out[3], HEADERS);
        assert_eq!(u32::from_be_bytes([out[5], out[6], out[7], out[8]]), 5);
        let data = FRAME_HEADER_LEN + HEADER_BLOCK.len();
        assert_eq!(out[data + 3], DATA);
        assert_eq!(
            u32::from_be_bytes([out[data + 5], out[data + 6], out[data + 7], out[data + 8]]),
            5
        );
        assert_eq!(&out[data + FRAME_HEADER_LEN..], BODY);
    }

    #[test]
    fn a_frame_that_has_not_all_arrived_is_left_alone() {
        let mut out = Vec::new();
        let mut c = Conn::new(&mut out);
        out.clear();
        let f = frame(HEADERS, FLAG_END_HEADERS, 1, b"\x82\x86");
        assert_eq!(c.drive(&f[..f.len() - 1], &mut out), Some(0));
        assert!(out.is_empty());
        assert_eq!(c.drive(&f, &mut out), Some(f.len()));
        assert!(!out.is_empty());
    }

    #[test]
    fn settings_are_acknowledged_but_an_acknowledgement_is_not() {
        let mut out = Vec::new();
        let mut c = Conn::new(&mut out);
        out.clear();
        c.drive(&frame(SETTINGS, 0, 0, b""), &mut out);
        assert_eq!(out, SETTINGS_ACK);
        out.clear();
        c.drive(&frame(SETTINGS, FLAG_ACK_OR_END_STREAM, 0, b""), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn a_ping_comes_back_with_its_payload() {
        let mut out = Vec::new();
        let mut c = Conn::new(&mut out);
        out.clear();
        c.drive(&frame(PING, 0, 0, b"12345678"), &mut out);
        assert_eq!(out[3], PING);
        assert_eq!(out[4], FLAG_ACK_OR_END_STREAM);
        assert_eq!(&out[FRAME_HEADER_LEN..], b"12345678");
    }

    #[test]
    fn a_goaway_closes_the_connection() {
        let mut out = Vec::new();
        let mut c = Conn::new(&mut out);
        assert_eq!(c.drive(&frame(GOAWAY, 0, 0, &[0; 8]), &mut out), None);
    }
}
