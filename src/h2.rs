//! HTTP/2 over cleartext, one constant response
//!
//! A request's stream id is in the clear in the frame header, and the response
//! is the same bytes every time, so neither direction needs an HPACK codec:
//! see the README for why that is allowed rather than merely convenient.

use std::collections::VecDeque;

/// The client's connection preface (RFC 9113 Section 3.4), which is also what
/// tells this server it is not talking HTTP/1.1
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADER_LEN: usize = 9;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const INITIAL_WINDOW: u32 = 65_535;
const MAX_WINDOW: u32 = 0x7fff_ffff;
const PROTOCOL_ERROR: u32 = 1;
const FLOW_CONTROL_ERROR: u32 = 3;
const FRAME_SIZE_ERROR: u32 = 6;

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

/// Generous request stream limits. These are independent of the peer's receive
/// windows that constrain our responses.
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
    header_is_request: bool,
    closing: bool,
    last_stream: u32,
    send_window: u32,
    initial_window: u32,
    /// Only unfinished response bodies need stream credit and an offset.
    /// Ordinary requests never allocate. Stream IDs stay sorted for lookup;
    /// finished interior slots are reclaimed once at least half are retired.
    pending: VecDeque<Pending>,
    /// Everything before this cursor is retired or has no stream credit.
    resume_at: usize,
    retired: usize,
}

struct Pending {
    stream: u32,
    /// SETTINGS can reduce this below zero after some DATA has been sent.
    window: i32,
    /// BODY.len() also marks a cancelled or completed interior slot.
    sent: u8,
}

impl Conn {
    /// Queues the server's own SETTINGS, which RFC 9113 Section 3.4 requires to
    /// be the first thing it sends
    pub fn new(out: &mut Vec<u8>) -> Self {
        out.extend_from_slice(SERVER_SETTINGS);
        Conn {
            header_stream: 0,
            header_is_request: false,
            closing: false,
            last_stream: 0,
            send_window: INITIAL_WINDOW,
            initial_window: INITIAL_WINDOW,
            pending: VecDeque::new(),
            resume_at: 0,
            retired: 0,
        }
    }

    /// TCP must finish writing GOAWAY before closing, even after a short send.
    pub fn is_closing(&self) -> bool {
        self.closing
    }

    /// Answer every whole frame in `buf`, returning how many bytes were used,
    /// or `None` if the connection should close.
    pub fn drive(&mut self, buf: &[u8], out: &mut Vec<u8>) -> Option<usize> {
        if self.closing {
            return Some(buf.len());
        }
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
                    if stream & 1 == 0 {
                        return None;
                    }
                    // A later field block on an existing stream is a trailer,
                    // not another request or a fresh send window.
                    let is_request = stream > self.last_stream;
                    if is_request {
                        self.last_stream = stream;
                    }
                    if flags & FLAG_END_HEADERS != 0 {
                        if is_request {
                            self.respond(out, stream);
                        }
                    } else {
                        self.header_stream = stream;
                        self.header_is_request = is_request;
                    }
                }
                CONTINUATION => {
                    if self.header_stream == 0 {
                        return None;
                    }
                    if flags & FLAG_END_HEADERS != 0 {
                        self.header_stream = 0;
                        if self.header_is_request {
                            self.respond(out, stream);
                        }
                    }
                }
                SETTINGS => {
                    if stream != 0 {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                    if !len.is_multiple_of(6) || flags & FLAG_ACK_OR_END_STREAM != 0 && len != 0 {
                        return self.fail(out, buf.len(), FRAME_SIZE_ERROR);
                    }
                    if flags & FLAG_ACK_OR_END_STREAM == 0 {
                        for setting in payload.as_chunks::<6>().0 {
                            let id = u16::from_be_bytes([setting[0], setting[1]]);
                            let value = u32::from_be_bytes(setting[2..].try_into().unwrap());
                            match id {
                                4 => {
                                    if value > MAX_WINDOW {
                                        return self.fail(out, buf.len(), FLOW_CONTROL_ERROR);
                                    }
                                    let delta = value as i32 - self.initial_window as i32;
                                    for response in &mut self.pending {
                                        if response.sent as usize == BODY.len() {
                                            continue;
                                        }
                                        let Some(window) = response.window.checked_add(delta)
                                        else {
                                            return self.fail(out, buf.len(), FLOW_CONTROL_ERROR);
                                        };
                                        response.window = window;
                                    }
                                    self.initial_window = value;
                                    if delta > 0 {
                                        self.resume_at = 0;
                                    }
                                }
                                2 if value > 1 => {
                                    return self.fail(out, buf.len(), PROTOCOL_ERROR);
                                }
                                5 if !(16_384..=16_777_215).contains(&value) => {
                                    return self.fail(out, buf.len(), PROTOCOL_ERROR);
                                }
                                _ => {}
                            }
                        }
                        out.extend_from_slice(SETTINGS_ACK);
                        self.resume(out);
                    }
                }
                WINDOW_UPDATE => {
                    if len != 4 {
                        return self.fail(out, buf.len(), FRAME_SIZE_ERROR);
                    }
                    let increment = u32::from_be_bytes(payload.try_into().unwrap()) & MAX_WINDOW;
                    if stream == 0 {
                        if increment == 0 {
                            return self.fail(out, buf.len(), PROTOCOL_ERROR);
                        }
                        if increment > MAX_WINDOW - self.send_window {
                            return self.fail(out, buf.len(), FLOW_CONTROL_ERROR);
                        }
                        self.send_window += increment;
                        self.resume(out);
                    } else {
                        if stream > self.last_stream || stream & 1 == 0 {
                            return self.fail(out, buf.len(), PROTOCOL_ERROR);
                        }
                        if let Some(index) = self.pending_index(stream) {
                            let response = &mut self.pending[index];
                            match response.window.checked_add(increment as i32) {
                                Some(window) if increment != 0 => {
                                    response.window = window;
                                    if send_body(out, &mut self.send_window, response) {
                                        self.retire(index);
                                    } else if response.window > 0 {
                                        self.resume_at = self.resume_at.min(index);
                                    }
                                }
                                _ => {
                                    self.retire(index);
                                    reset(
                                        out,
                                        stream,
                                        if increment == 0 {
                                            PROTOCOL_ERROR
                                        } else {
                                            FLOW_CONTROL_ERROR
                                        },
                                    );
                                }
                            }
                        }
                        // Late credit for a completed or reset response is legal.
                    }
                }
                RST_STREAM => {
                    if len != 4 {
                        return self.fail(out, buf.len(), FRAME_SIZE_ERROR);
                    }
                    if stream == 0 || stream > self.last_stream || stream & 1 == 0 {
                        return self.fail(out, buf.len(), PROTOCOL_ERROR);
                    }
                    if let Some(index) = self.pending_index(stream) {
                        self.retire(index);
                    }
                }
                PING => {
                    if flags & FLAG_ACK_OR_END_STREAM == 0 && len == 8 {
                        out.extend_from_slice(&[0, 0, 8, PING, FLAG_ACK_OR_END_STREAM, 0, 0, 0, 0]);
                        out.extend_from_slice(payload);
                    }
                }
                GOAWAY => return None,
                // Request DATA and PRIORITY need no response here.
                _ => {}
            }
            at += end;
        }
        Some(at)
    }

    fn respond(&mut self, out: &mut Vec<u8>, stream: u32) {
        if self.send_window >= BODY.len() as u32 && self.initial_window >= BODY.len() as u32 {
            self.send_window -= BODY.len() as u32;
            respond(out, stream);
        } else {
            headers(out, stream);
            let mut response = Pending {
                stream,
                window: self.initial_window as i32,
                sent: 0,
            };
            if !send_body(out, &mut self.send_window, &mut response) {
                self.pending.push_back(response);
            }
        }
    }

    fn pending_index(&self, stream: u32) -> Option<usize> {
        self.pending
            .binary_search_by_key(&stream, |p| p.stream)
            .ok()
            .filter(|&index| self.pending[index].sent as usize != BODY.len())
    }

    fn retire(&mut self, index: usize) {
        if index == 0 {
            self.pending.pop_front();
            self.resume_at = self.resume_at.saturating_sub(1);
        } else if index + 1 == self.pending.len() {
            self.pending.pop_back();
            self.resume_at = self.resume_at.min(self.pending.len());
        } else {
            self.pending[index].sent = BODY.len() as u8;
            self.retired += 1;
        }
        if self.retired != 0 {
            self.reclaim();
        }
    }

    fn reclaim(&mut self) {
        // In-order and reverse-order completion stay constant-time. Interior
        // holes never shift a suffix on each grant and retain less than twice
        // the live entries between compactions.
        while self
            .pending
            .front()
            .is_some_and(|p| p.sent as usize == BODY.len())
        {
            self.pending.pop_front();
            self.retired -= 1;
            self.resume_at = self.resume_at.saturating_sub(1);
        }
        while self
            .pending
            .back()
            .is_some_and(|p| p.sent as usize == BODY.len())
        {
            self.pending.pop_back();
            self.retired -= 1;
        }
        self.resume_at = self.resume_at.min(self.pending.len());
        if self.retired != 0 && self.retired >= self.pending.len() - self.retired {
            let mut before = 0;
            let mut index = 0;
            self.pending.retain(|p| {
                let live = p.sent as usize != BODY.len();
                if !live && index < self.resume_at {
                    before += 1;
                }
                index += 1;
                live
            });
            self.resume_at -= before;
            self.retired = 0;
        }
    }

    fn resume(&mut self, out: &mut Vec<u8>) {
        if self.send_window == 0 || self.resume_at == self.pending.len() {
            return;
        }
        // A grant covering every remaining body can retire them in one pass.
        // Every survivor then has exhausted its stream credit.
        if (self.send_window as usize) / BODY.len() >= self.pending.len() {
            if self.retired == 0 {
                self.pending
                    .retain_mut(|response| !send_body(out, &mut self.send_window, response));
            } else {
                self.pending.retain_mut(|response| {
                    response.sent as usize != BODY.len()
                        && !send_body(out, &mut self.send_window, response)
                });
            }
            self.retired = 0;
            self.resume_at = self.pending.len();
            return;
        }
        // Ready queues keep the direct front drain. Cursor and tombstone
        // bookkeeping is needed only once a blocked response is encountered.
        if self.resume_at == 0 && self.retired == 0 {
            while self.send_window != 0 {
                let Some(response) = self.pending.front_mut() else {
                    return;
                };
                if !send_body(out, &mut self.send_window, response) {
                    break;
                }
                self.pending.pop_front();
            }
            if self.send_window == 0 {
                return;
            }
        }
        while self.send_window != 0 && self.resume_at < self.pending.len() {
            let response = &mut self.pending[self.resume_at];
            if response.sent as usize == BODY.len() || response.window <= 0 {
                self.resume_at += 1;
            } else if send_body(out, &mut self.send_window, response) {
                self.retired += 1;
                self.resume_at += 1;
            } else if response.window <= 0 {
                self.resume_at += 1;
            }
        }
        self.reclaim();
    }

    fn fail(&mut self, out: &mut Vec<u8>, used: usize, error: u32) -> Option<usize> {
        out.extend_from_slice(&[0, 0, 8, GOAWAY, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&self.last_stream.to_be_bytes());
        out.extend_from_slice(&error.to_be_bytes());
        self.pending.clear();
        self.resume_at = 0;
        self.retired = 0;
        self.closing = true;
        Some(used)
    }
}

fn reset(out: &mut Vec<u8>, stream: u32, error: u32) {
    out.extend_from_slice(&[0, 0, 4, RST_STREAM, 0]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(&error.to_be_bytes());
}

/// Returns true only after constructing the final DATA with END_STREAM.
fn send_body(out: &mut Vec<u8>, connection_window: &mut u32, response: &mut Pending) -> bool {
    let n = (*connection_window)
        .min(response.window.max(0) as u32)
        .min((BODY.len() - response.sent as usize) as u32) as u8;
    if n == 0 {
        return false;
    }
    let start = response.sent as usize;
    response.sent += n;
    let done = response.sent as usize == BODY.len();
    out.extend_from_slice(&[0, 0, n, DATA, u8::from(done)]);
    out.extend_from_slice(&response.stream.to_be_bytes());
    out.extend_from_slice(&BODY[start..response.sent as usize]);
    *connection_window -= u32::from(n);
    response.window -= i32::from(n);
    done
}

fn headers(out: &mut Vec<u8>, stream: u32) {
    out.extend_from_slice(&[0, 0, HEADER_BLOCK.len() as u8, HEADERS, FLAG_END_HEADERS]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(HEADER_BLOCK);
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
mod flow_control_tests;

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
