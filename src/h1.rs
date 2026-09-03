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
    /// Nothing complete yet; wait for more bytes
    Partial,
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
    let body = if buf.starts_with(b"GET ") || buf.starts_with(b"HEAD ") {
        0
    } else {
        match content_length(&buf[..end]) {
            Some(n) => n,
            None => return Request::Bad,
        }
    };
    match buf.len() >= end + body {
        true => Request::Whole(end + body),
        false => Request::Partial,
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
            Request::Partial
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
}
