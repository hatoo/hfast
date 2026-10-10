use super::*;

// Frozen dcb83ef parser. It deliberately keeps the original complete-buffer
// behavior, including permissive fields and delayed malformed-length errors.
#[allow(dead_code)]
mod reference {

    /// The whole response. `Connection: keep-alive` is the default in HTTP/1.1 and
    /// saying so again would only make the reply longer.
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";

    /// What `parse` found at the front of the buffer
    pub enum Request {
        /// A whole request, this many bytes long
        Whole(usize),
        /// The headers are incomplete; wait for more bytes
        Partial,
        /// The headers are complete. Consume all of `buf`, then wait for this many
        /// more body bytes before responding. The body itself need not be retained.
        Body(usize),
        /// Not something this will answer
        Bad,
    }

    /// Measure the request at the front of `buf`
    pub fn parse(buf: &[u8]) -> Request {
        let Some(end) = find_empty_line(buf) else {
            return Request::Partial;
        };
        // A GET or a HEAD carries no body, and that is every request a load
        // generator sends at this. Anything else has to be asked how long it is.
        if buf.starts_with(b"GET ") || buf.starts_with(b"HEAD ") {
            return Request::Whole(end);
        }
        let Some(body) = content_length(&buf[..end]) else {
            return Request::Bad;
        };
        let available = buf.len() - end;
        if body <= available {
            // The complete request fits in buf, so this addition cannot overflow.
            Request::Whole(end + body)
        } else if end.checked_add(body).is_some() {
            Request::Body(body - available)
        } else {
            Request::Bad
        }
    }

    pub fn respond(out: &mut Vec<u8>) {
        out.extend_from_slice(RESPONSE);
    }

    /// Offset just past the empty line that ends the header block
    ///
    /// RFC 9112 Section 2.2 spells the line ending CRLF, and a vectorised search for
    /// the four bytes beats walking the request looking for one of them.
    fn find_empty_line(buf: &[u8]) -> Option<usize> {
        memchr::memmem::find(buf, b"\r\n\r\n").map(|i| i + 4)
    }

    /// The declared body length, or `None` if the header is there but unreadable.
    /// A request without one has no body.
    fn content_length(head: &[u8]) -> Option<usize> {
        const NAME: &[u8] = b"content-length:";
        let mut i = 0;
        while i + NAME.len() <= head.len() {
            let line_start = i;
            let line_end = match memchr::memchr(b'\n', &head[i..]) {
                Some(n) => i + n,
                None => head.len(),
            };
            let line = &head[line_start..line_end];
            if line.len() > NAME.len() && line[..NAME.len()].eq_ignore_ascii_case(NAME) {
                let mut n: usize = 0;
                let mut seen = false;
                for &b in &line[NAME.len()..] {
                    match b {
                        b' ' | b'\t' if !seen => {}
                        b'0'..=b'9' => {
                            seen = true;
                            n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
                        }
                        b'\r' | b' ' | b'\t' => break,
                        _ => return None,
                    }
                }
                return seen.then_some(n);
            }
            if line_end == head.len() {
                break;
            }
            i = line_end + 1;
        }
        Some(0)
    }
}

#[derive(Default)]
struct Reference {
    buf: Vec<u8>,
    remaining: usize,
    out: Vec<u8>,
}

impl Reference {
    fn consume(&mut self, data: &[u8]) -> bool {
        self.buf.extend_from_slice(data);
        let mut at = 0;
        if self.remaining > 0 {
            let n = self.remaining.min(self.buf.len());
            self.remaining -= n;
            at = n;
            if self.remaining > 0 {
                self.buf.clear();
                return true;
            }
            reference::respond(&mut self.out);
        }
        loop {
            match reference::parse(&self.buf[at..]) {
                reference::Request::Whole(n) => {
                    reference::respond(&mut self.out);
                    at += n;
                }
                reference::Request::Body(n) => {
                    self.remaining = n;
                    self.buf.clear();
                    return true;
                }
                reference::Request::Partial => {
                    self.buf.drain(..at);
                    return true;
                }
                reference::Request::Bad => return false,
            }
        }
    }
}

fn compare(wire: &[u8], parts: impl IntoIterator<Item = usize>) {
    let mut conn = Conn::new();
    let mut reference = Reference::default();
    let mut at = 0;
    for n in parts {
        let end = (at + n).min(wire.len());
        let expected = reference.consume(&wire[at..end]);
        let actual = consume(&mut conn, &wire[at..end]);
        assert_eq!(
            actual,
            expected,
            "liveness at {at}..{end} of {}",
            wire.len()
        );
        assert_eq!(conn.outbuf, reference.out, "response at {at}..{end}");
        if !expected {
            return;
        }
        conn.outbuf.clear();
        reference.out.clear();
        at = end;
    }
    assert_eq!(at, wire.len());
}

#[test]
fn delimiter_search_threshold_preserves_fragmented_pipelines_and_errors() {
    for padding in [0, 15, 31, 47, 63, 64, 65, 127] {
        for length in ["3".to_owned(), "invalid".to_owned(), usize::MAX.to_string()] {
            let wire = format!(
                "GET / HTTP/1.1\r\nX: {}\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\nabcGET / HTTP/1.1\r\n\r\n",
                "x".repeat(padding)
            );
            for split in 0..=wire.len() {
                compare(wire.as_bytes(), [split, 0, wire.len() - split]);
            }
            for chunk in [1, 3, 4, 15, 16, 31, 32, 63, 64, 65, 127, 128] {
                compare(
                    wire.as_bytes(),
                    std::iter::repeat_n(chunk, wire.len().div_ceil(chunk)),
                );
            }
        }
    }
}

#[test]
fn three_part_splits_match_frozen_parser_and_error_timing() {
    let mut cases = vec![
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        b"HEAD / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n".to_vec(),
        b"PRINT / HTTP/1.1\r\n\r\n".to_vec(),
        b"\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\nContent-Length:3\nX:a\r\n\r\nabc".to_vec(),
        b"POST / HTTP/1.1\r\r\nX: y\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nContent-Length:\nContent-Length: 2\r\n\r\nab".to_vec(),
        b"POST / HTTP/1.1\r\nContent-Length:3\rignored\n\r\nabc".to_vec(),
        b"Content-Length: 1\r\n\r\nx".to_vec(),
    ];
    for value in [
        "", " ", "\t", "-1", "+1", "0", "0003", "3", "3x", "3 x", "3\tx", " 3", "\t3", "3\rX",
        "3\x00",
    ] {
        cases.push(
            format!("POST / HTTP/1.1\r\ncOnTeNt-LeNgTh:{value}\r\nContent-Length:9\r\n\r\nabc")
                .into_bytes(),
        );
    }
    for value in [
        usize::MAX.to_string(),
        format!("{}0", usize::MAX),
        (usize::MAX - 100).to_string(),
    ] {
        cases.push(format!("POST / HTTP/1.1\r\nContent-Length:{value}\r\n\r\nabc").into_bytes());
    }
    for wire in cases {
        for first in 0..=wire.len() {
            for second in first..=wire.len() {
                compare(&wire, [first, 0, second - first, 0, wire.len() - second, 0]);
            }
        }
    }
}

#[test]
fn every_fragment_size_preserves_header_plus_body_overflow_boundary() {
    for padding in [0, 100, 8192] {
        let mut request = format!(
            "POST / HTTP/1.1\r\nX: {}\r\nContent-Length: {}\r\n\r\n",
            "a".repeat(padding),
            usize::MAX
        );
        let limit = usize::MAX - request.len();
        for length in [limit - 1, limit, limit + 1] {
            request = format!(
                "POST / HTTP/1.1\r\nX: {}\r\nContent-Length: {length}\r\n\r\n",
                "a".repeat(padding)
            );
            for chunk in [1, 3, 15, 53, 4096, 16384] {
                compare(
                    request.as_bytes(),
                    std::iter::repeat_n(chunk, request.len().div_ceil(chunk)),
                );
            }
        }
    }
}

#[test]
fn seeded_headers_bodies_and_pipelines_match_after_every_receive() {
    for seed in 1u64..=32 {
        let mut state = seed;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut wire = Vec::new();
        for i in 0..64 {
            let method = ["GET", "HEAD", "POST", "PUT", "PRINT"][next() as usize % 5];
            wire.extend_from_slice(format!("{method} / HTTP/1.1\r\n").as_bytes());
            for _ in 0..next() % 10 {
                let size = if i % 13 == 0 {
                    16384
                } else {
                    next() as usize % 100
                };
                wire.extend_from_slice(format!("X-Ignore: {}\r\n", "a".repeat(size)).as_bytes());
            }
            let size = next() as usize % 100;
            wire.extend_from_slice(
                format!("Content-Length: {size}\r\nContent-Length: invalid\r\n\r\n").as_bytes(),
            );
            if method != "GET" && method != "HEAD" {
                wire.extend((0..size).map(|_| next() as u8));
            }
        }
        let mut parts = vec![0];
        let mut left = wire.len();
        while left != 0 {
            let n = [1, 3, 53, 4096, 16384][next() as usize % 5].min(left);
            parts.extend_from_slice(&[n, 0]);
            left -= n;
        }
        compare(&wire, parts);
    }
}

#[test]
fn arbitrary_short_headers_preserve_delimiter_and_field_semantics() {
    let alphabet = b"\r\n :012x\t\0\xff";
    for seed in 1u64..=4096 {
        let mut state = seed;
        let mut wire = b"POST / HTTP/1.1\r\nContent-Length:".to_vec();
        for _ in 0..32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            wire.push(alphabet[state as usize % alphabet.len()]);
        }
        wire.extend_from_slice(b"\r\n\r\nabcGET / HTTP/1.1\r\n\r\n");
        for chunk in [1, 3, 17, 53, 16384] {
            compare(
                &wire,
                std::iter::repeat_n(chunk, wire.len().div_ceil(chunk)),
            );
        }
    }
}

#[test]
fn fragmented_headers_need_no_input_allocation_even_for_single_long_lines() {
    for method in ["GET", "HEAD", "POST"] {
        for chunk in [1, 53, 16384] {
            let mut conn = Conn::new();
            // Start with enough bytes to settle the protocol without buffering.
            assert!(consume(
                &mut conn,
                format!("{method} / HTTP/1.1\r\n").as_bytes()
            ));
            let head = format!("X: {}\r\nContent-Length: 1\r\n\r\n", "a".repeat(1 << 20));
            for part in head.as_bytes()[..head.len() - 1].chunks(chunk) {
                assert!(consume(&mut conn, part));
                assert!(conn.outbuf.is_empty());
                assert!(conn.inbuf.is_empty());
                assert_eq!(conn.inbuf.capacity(), 0);
            }
            assert!(consume(&mut conn, b"\n"));
            if method == "POST" {
                assert!(conn.outbuf.is_empty());
                assert!(consume(&mut conn, b"x"));
            }
            let mut expected = Vec::new();
            h1::respond(&mut expected);
            assert_eq!(conn.outbuf, expected);
            assert_eq!(conn.inbuf.capacity(), 0);
        }
    }
}
