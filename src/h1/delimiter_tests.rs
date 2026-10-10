use super::find_empty_line;

fn compare(buf: &[u8]) {
    // Independent scalar oracle, plus the frozen pre-optimization search.
    let expected = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    assert_eq!(find_empty_line(buf), expected, "length {}", buf.len());
    assert_eq!(
        find_empty_line(buf),
        memchr::memmem::find(buf, b"\r\n\r\n").map(|i| i + 4)
    );
}

#[test]
fn every_delimiter_position_around_search_and_vector_boundaries() {
    for len in (0..=160).chain([255, 256, 257, 511, 512, 513, 1023, 1024, 1025]) {
        let mut buf = vec![b'x'; len];
        compare(&buf);
        if len < 4 {
            continue;
        }
        for at in 0..=len - 4 {
            buf[at..at + 4].copy_from_slice(b"\r\n\r\n");
            compare(&buf);
            buf[at..at + 4].fill(b'x');
        }
    }
}

#[test]
fn unaligned_buffers_overlaps_and_partial_suffixes_find_the_first_delimiter() {
    for alignment in 0..32 {
        for padding in [0, 1, 3, 15, 16, 31, 32, 59, 60, 63, 64, 65, 127, 128] {
            for suffix in [b"".as_slice(), b"\r", b"\r\n", b"\r\n\r", b"\r\n\r\n\r\n"] {
                let mut buf = vec![b'x'; alignment + padding];
                buf.extend_from_slice(suffix);
                compare(&buf[alignment..]);
                buf.extend_from_slice(b"\r\n\r\nbody\r\n\r\n");
                compare(&buf[alignment..]);
            }
        }
    }
}

#[test]
fn cr_heavy_and_periodic_haystacks_preserve_first_match() {
    for pattern in [
        b"\r".as_slice(),
        b"\n",
        b"\r\n",
        b"\r\r\n",
        b"\r\nx",
        b"\r\n\rx",
        b"\0\xff",
    ] {
        for len in [3, 4, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 1024, 16384] {
            let mut buf: Vec<u8> = pattern.iter().copied().cycle().take(len).collect();
            compare(&buf);
            buf.extend_from_slice(b"\r\n\r\n");
            compare(&buf);
        }
    }
}

#[test]
fn seeded_binary_haystacks_match_both_oracles() {
    let mut state = 0x98cf_3612_901e_d75au64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for case in 0..4096 {
        let len = next() as usize % 2048;
        let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if case % 2 == 0 {
            for b in &mut buf {
                *b = b"\r\n\rx\0"[*b as usize % 5];
            }
        }
        compare(&buf);
        if len >= 4 {
            for _ in 0..3 {
                let at = next() as usize % (len - 3);
                buf[at..at + 4].copy_from_slice(b"\r\n\r\n");
                compare(&buf);
            }
        }
    }
}

#[test]
fn workers_can_share_the_prepared_searcher() {
    std::thread::scope(|scope| {
        for worker in 0..8 {
            scope.spawn(move || {
                for at in 0..256 {
                    let mut buf = vec![b'x'; 512 + worker];
                    buf[at..at + 4].copy_from_slice(b"\r\n\r\n");
                    compare(&buf);
                }
            });
        }
    });
}
