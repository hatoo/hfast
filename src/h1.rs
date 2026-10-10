//! HTTP/1.1, keep-alive, one constant response
//!
//! A request is over at the first empty line, and the only thing that follows
//! it is a body the request announced. Nothing else about a request changes
//! what comes back, so nothing else is read.

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

/// Only fragmented heads need state. Complete heads keep the single delimiter
/// search below; no request bytes are retained between calls.
#[derive(Default)]
pub struct Head {
    bytes: usize,
    ending: u32,
    method: [u8; 5],
    length: Length,
}

impl Head {
    /// Unlike the stateless parser, `Partial` consumes all of `buf`.
    pub fn parse(&mut self, buf: &[u8]) -> Request {
        let end = if self.bytes == 0 {
            match parse(buf) {
                Request::Partial => None,
                complete => return complete,
            }
        } else {
            self.find_end(buf)
        };
        let head = &buf[..end.unwrap_or(buf.len())];
        if self.bytes < self.method.len() {
            let n = head.len().min(self.method.len() - self.bytes);
            self.method[self.bytes..self.bytes + n].copy_from_slice(&head[..n]);
        }
        let Some(bytes) = self.bytes.checked_add(head.len()) else {
            return Request::Bad;
        };
        self.bytes = bytes;
        let bodyless = self.method.starts_with(b"GET ") || self.method == *b"HEAD ";
        if !bodyless {
            self.length.feed(head);
        }
        let Some(end) = end else {
            // The next delimiter can start in the last three bytes. Keeping
            // four also makes split detection a simple rolling comparison.
            if head.len() >= 4 {
                self.ending = u32::from_be_bytes(head[head.len() - 4..].try_into().unwrap());
            } else if self.bytes == head.len() {
                for &b in head {
                    self.ending = (self.ending << 8) | u32::from(b);
                }
            }
            return Request::Partial;
        };
        let length = if bodyless {
            Some(0)
        } else {
            self.length.value()
        };
        *self = Self::default();
        let Some(body) = length.filter(|&n| bytes.checked_add(n).is_some()) else {
            return Request::Bad;
        };
        let available = buf.len() - end;
        if body <= available {
            Request::Whole(end + body)
        } else {
            Request::Body(body - available)
        }
    }

    fn find_end(&mut self, buf: &[u8]) -> Option<usize> {
        // Only the first three bytes can finish a delimiter from the previous
        // receive. Search within this receive with the usual vectorised scan.
        for (i, &b) in buf.iter().take(3).enumerate() {
            self.ending = (self.ending << 8) | u32::from(b);
            if self.ending == u32::from_be_bytes(*b"\r\n\r\n") {
                return Some(i + 1);
            }
        }
        find_empty_line(buf)
    }
}

/// Streaming form of `content_length`: skip unrelated lines without retaining
/// them, and remember the first field's result until the head is complete.
enum Length {
    Name(usize),
    Number { n: usize, seen: bool },
    Ignore,
    Done(Option<usize>),
}

impl Default for Length {
    fn default() -> Self {
        Self::Name(0)
    }
}

impl Length {
    fn feed(&mut self, mut buf: &[u8]) {
        const NAME: &[u8] = b"content-length:";
        while let Some((&b, rest)) = buf.split_first() {
            match self {
                Self::Done(_) => return,
                Self::Ignore => {
                    let Some(lf) = memchr::memchr(b'\n', buf) else {
                        return;
                    };
                    buf = &buf[lf + 1..];
                    *self = Self::Name(0);
                    continue;
                }
                Self::Name(i) => {
                    if b == b'\n' {
                        // A name with no following byte is not a field in the
                        // original parser (line.len() must exceed NAME.len()).
                        *i = 0;
                    } else if *i == NAME.len() {
                        *self = Self::Number { n: 0, seen: false };
                        continue;
                    } else if b.to_ascii_lowercase() == NAME[*i] {
                        *i += 1;
                    } else {
                        *self = Self::Ignore;
                    }
                }
                Self::Number { n, seen } => match b {
                    b' ' | b'\t' if !*seen => {}
                    b'0'..=b'9' => {
                        if let Some(value) = n
                            .checked_mul(10)
                            .and_then(|n| n.checked_add((b - b'0') as usize))
                        {
                            *n = value;
                            *seen = true;
                        } else {
                            *self = Self::Done(None);
                        }
                    }
                    b'\r' | b' ' | b'\t' | b'\n' => *self = Self::Done(seen.then_some(*n)),
                    _ => *self = Self::Done(None),
                },
            }
            buf = rest;
        }
    }

    fn value(&self) -> Option<usize> {
        match self {
            Self::Done(n) => *n,
            // Every complete head ends with LF, so any matching field has
            // already finished. No matching field means a zero length body.
            _ => Some(0),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(buf: &[u8]) -> Option<usize> {
        match parse(buf) {
            Request::Whole(n) => Some(n),
            _ => None,
        }
    }

    #[test]
    fn a_get_ends_at_the_empty_line() {
        let r = b"GET /plaintext HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(whole(r), Some(r.len()));
    }

    #[test]
    fn two_requests_in_one_read_are_measured_one_at_a_time() {
        let one = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut both = one.to_vec();
        both.extend_from_slice(one);
        assert_eq!(whole(&both), Some(one.len()));
    }

    #[test]
    fn a_request_that_has_not_all_arrived_is_partial() {
        assert!(matches!(
            parse(b"GET / HTTP/1.1\r\nHost:"),
            Request::Partial
        ));
        assert!(matches!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"),
            Request::Body(3)
        ));
    }

    /// A body would otherwise be read as the request that follows it
    #[test]
    fn a_body_belongs_to_the_request_that_declared_it() {
        let r = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde";
        assert_eq!(whole(r), Some(r.len()));
        let r = b"POST / HTTP/1.1\r\ncontent-length:  5 \r\n\r\nabcde";
        assert_eq!(whole(r), Some(r.len()), "name and value are loosely spelt");
    }

    #[test]
    fn a_post_without_a_length_has_no_body() {
        let r = b"POST / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(whole(r), Some(r.len()));
    }

    #[test]
    fn overflowing_lengths_are_rejected_before_body_consumption() {
        for length in [usize::MAX.to_string(), format!("{}0", usize::MAX)] {
            let request = format!("POST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
            assert!(matches!(parse(request.as_bytes()), Request::Bad));
        }
        let request = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            usize::MAX - 100
        );
        assert!(matches!(parse(request.as_bytes()), Request::Body(n) if n == usize::MAX - 100));
        let header_len = request.len();
        let last_valid = usize::MAX - header_len;
        let request = format!("POST / HTTP/1.1\r\nContent-Length: {last_valid}\r\n\r\n");
        assert_eq!(request.len(), header_len);
        assert!(matches!(parse(request.as_bytes()), Request::Body(n) if n == last_valid));
        let request = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            last_valid + 1
        );
        assert!(matches!(parse(request.as_bytes()), Request::Bad));
    }
}
