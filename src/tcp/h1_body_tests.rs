use super::*;

const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";

fn request(body: &[u8]) -> Vec<u8> {
    let mut wire =
        format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}

/// Expected response boundaries come from the generated requests, independent
/// of the parser. Compare after every receive, including empty receives.
fn check_parts(requests: &[Vec<u8>], parts: impl IntoIterator<Item = usize>) {
    let wire = requests.concat();
    let mut total = 0;
    let ends: Vec<_> = requests
        .iter()
        .map(|request| {
            total += request.len();
            total
        })
        .collect();
    let mut conn = Conn::new();
    let mut at = 0;
    let mut replied = 0;
    for size in parts {
        let end = (at + size).min(wire.len());
        assert!(consume(&mut conn, &wire[at..end]));
        let complete = ends.iter().filter(|&&n| n <= end).count();
        assert_eq!(conn.outbuf, RESPONSE.repeat(complete - replied), "at {end}");
        conn.outbuf.clear();
        replied = complete;
        at = end;
    }
    assert_eq!(at, wire.len());
    assert_eq!(replied, requests.len());
    assert!(conn.inbuf.is_empty());
}

#[test]
fn every_split_preserves_body_completion_and_pipelining() {
    let requests = vec![
        request(b"GET /fake HTTP/1.1\r\n\r\n\0\xff"),
        request(b""),
        b"GET / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n".to_vec(),
        request(b"a"),
        b"POST / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"HEAD / HTTP/1.1\r\nContent-Length: 100\r\n\r\n".to_vec(),
        request(b"\r\n\r\n"),
    ];
    let len = requests.iter().map(Vec::len).sum::<usize>();
    for split in 0..=len {
        check_parts(&requests, [split, 0, len - split, 0]);
    }
    for chunk in 1..=len {
        check_parts(&requests, std::iter::repeat_n(chunk, len.div_ceil(chunk)));
    }
}

#[test]
fn seeded_receive_partitions_match_independent_request_boundaries() {
    for seed in 1u64..=32 {
        let mut state = seed;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let requests: Vec<_> = (0..128)
            .map(|i| {
                if i % 5 == 0 {
                    b"GET / HTTP/1.1\r\n\r\n".to_vec()
                } else {
                    let len = next() as usize % if i % 13 == 0 { 65536 } else { 1024 };
                    let body: Vec<_> = (0..len).map(|_| next() as u8).collect();
                    request(&body)
                }
            })
            .collect();
        let mut left = requests.iter().map(Vec::len).sum::<usize>();
        let mut parts = vec![0];
        while left != 0 {
            let n = [1, 3, 53, 4096, 16384][next() as usize % 5].min(left);
            parts.extend_from_slice(&[n, 0]);
            left -= n;
        }
        check_parts(&requests, parts);
    }
}

#[test]
fn large_fragmented_bodies_do_not_grow_the_input_buffer() {
    let chunk = b"GET /body-not-a-request HTTP/1.1\r\n\r\n".repeat(512);
    let size = chunk.len() * 1024 + 1;
    let head = format!("POST / HTTP/1.1\r\nContent-Length: {size}\r\n\r\n");
    for split in [0, 1, head.len() - 1, head.len()] {
        let mut conn = Conn::new();
        assert!(consume(&mut conn, &head.as_bytes()[..split]));
        let mut first = head.as_bytes()[split..].to_vec();
        first.extend_from_slice(&chunk);
        assert!(consume(&mut conn, &first));
        let capacity = conn.inbuf.capacity();
        assert!(conn.inbuf.is_empty());
        for _ in 1..1024 {
            assert!(consume(&mut conn, &chunk));
            assert!(conn.inbuf.is_empty());
            assert_eq!(conn.inbuf.capacity(), capacity);
            assert!(conn.outbuf.is_empty(), "must wait for the final body byte");
        }
        assert!(consume(&mut conn, b"xGET / HTTP/1.1\r\n"));
        assert_eq!(conn.outbuf, RESPONSE);
        assert!(conn.inbuf.is_empty(), "partial headers are consumed too");
        conn.outbuf.clear();
        assert!(consume(&mut conn, b"\r\n"));
        assert_eq!(conn.outbuf, RESPONSE);
        assert!(conn.inbuf.is_empty());
    }
}

#[test]
fn declared_length_policies_are_preserved() {
    let requests = vec![
        b"PUT / HTTP/1.1\r\ncOnTeNt-LeNgTh:\t 3 \tignored\r\n\r\nabc".to_vec(),
        b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 9\r\n\r\nx".to_vec(),
        b"POST / HTTP/1.1\r\nContent-Length: 0002\r\n\r\nxy".to_vec(),
        b"GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n".to_vec(),
        b"HEAD / HTTP/1.1\r\nContent-Length: 1\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
    ];
    let len = requests.iter().map(Vec::len).sum::<usize>();
    check_parts(&requests, std::iter::repeat_n(1, len));
    check_parts(&requests, [len]);
}

#[test]
fn malformed_and_overflowing_lengths_close_at_every_header_split() {
    for length in [
        "".to_string(),
        "-1".to_string(),
        "+1".to_string(),
        "1x".to_string(),
        usize::MAX.to_string(),
        format!("{}0", usize::MAX),
    ] {
        let head = format!("POST / HTTP/1.1\r\nContent-Length: {length}\r\n\r\n");
        for split in 0..head.len() {
            let mut conn = Conn::new();
            assert!(consume(&mut conn, &head.as_bytes()[..split]));
            assert!(!consume(&mut conn, &head.as_bytes()[split..]));
            assert!(conn.outbuf.is_empty());
        }
    }
}

#[test]
fn huge_valid_length_consumes_bytes_without_allocating_or_responding() {
    let mut conn = Conn::new();
    let head = format!(
        "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        usize::MAX - 100
    );
    assert!(consume(&mut conn, head.as_bytes()));
    for _ in 0..128 {
        assert!(consume(&mut conn, b"GET /still-body HTTP/1.1\r\n\r\n"));
        assert!(conn.outbuf.is_empty());
        assert!(conn.inbuf.is_empty());
        assert_eq!(conn.inbuf.capacity(), 0);
    }
}

#[test]
fn abandoned_requests_leave_no_state_in_replacement_connections() {
    let wire = request(b"body\r\n\r\nGET / HTTP/1.1\r\n\r\n");
    for end in 0..wire.len() {
        let mut old = Conn::new();
        assert!(consume(&mut old, &wire[..end]));
        assert!(old.outbuf.is_empty());
        drop(old);
        let mut replacement = Conn::new();
        assert!(consume(&mut replacement, b"GET / HTTP/1.1\r\n\r\n"));
        assert_eq!(replacement.outbuf, RESPONSE);
        assert!(replacement.inbuf.is_empty());
    }
}
