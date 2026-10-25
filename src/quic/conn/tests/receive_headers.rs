use super::*;

fn initial_keys() -> Keys {
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    Keys::initial(
        Version::V1,
        suite,
        suite.quic.unwrap(),
        &[1; 8],
        Side::Server,
    )
}

// Deliberately write non-minimal varints as well as canonical ones. Both are
// legal, and neither the token nor the length has a fixed header offset.
fn sized_varint(out: &mut Vec<u8>, value: usize, width: usize) {
    assert!(matches!(width, 1 | 2 | 4 | 8));
    assert!((value as u64) < (1u64 << (8 * width - 2)));
    let bytes = (value as u64).to_be_bytes();
    let start = out.len();
    out.extend_from_slice(&bytes[8 - width..]);
    out[start] |= width.trailing_zeros() as u8 * 64;
}

fn long_header(kind: Kind, token: &[u8], length: usize, width: usize) -> Vec<u8> {
    let ty = match kind {
        Kind::Initial => 0,
        Kind::ZeroRtt => 1,
        Kind::Handshake => 2,
        Kind::Retry => 3,
        Kind::Short => unreachable!(),
    };
    let mut packet = vec![0xc0 | ty << 4];
    packet.extend_from_slice(&packet::VERSION_1.to_be_bytes());
    for id in [[3; 8], [2; 8]] {
        packet.push(id.len() as u8);
        packet.extend_from_slice(&id);
    }
    if kind == Kind::Initial {
        sized_varint(&mut packet, token.len(), varint_len(token.len() as u64));
        packet.extend_from_slice(token);
    }
    if kind != Kind::Retry {
        sized_varint(&mut packet, length, width);
    }
    packet
}

fn long_packet(
    conn: &Connection,
    kind: Kind,
    pn: u64,
    pn_len: usize,
    token: &[u8],
    length_width: usize,
    body: &[u8],
) -> Vec<u8> {
    let mut plain = body.to_vec();
    plain.resize(plain.len().max(4 - pn_len), 0);
    let mut packet = long_header(kind, token, pn_len + plain.len() + TAG_LEN, length_width);
    packet[0] |= (pn_len - 1) as u8;
    let pn_offset = packet.len();
    packet.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
    let header_end = packet.len();
    packet.extend_from_slice(&plain);
    let keys = conn.remote_keys(kind.space().unwrap()).unwrap();
    let (header, payload) = packet.split_at_mut(header_end);
    let tag = keys.packet.encrypt_in_place(pn, header, payload).unwrap();
    packet.extend_from_slice(tag.as_ref());
    protect_header(keys.header.as_ref(), &mut packet, pn_offset, pn_len).unwrap();
    packet
}

// Independently compare datagram-relative and packet-relative header offsets.
fn assert_reparsed_offsets(datagram: &[u8]) {
    let mut at = 0;
    while at < datagram.len() {
        let header = packet::parse(datagram, at).unwrap();
        let isolated = packet::parse(&datagram[at..header.end], 0).unwrap();
        assert_eq!(header.pn_offset - at, isolated.pn_offset);
        assert_eq!(header.end - at, isolated.end);
        assert_eq!(header.kind, isolated.kind);
        at = header.end;
    }
}

#[test]
fn coalesced_finished_authenticates_the_following_short_packet() {
    let (mut conn, finished) = data_connection_before_finished();
    conn.initial = Some(initial_keys());
    let mut crypto = Vec::new();
    frame::put_crypto(&mut crypto, 0, &finished);
    let mut datagram = long_packet(&conn, Kind::Initial, 7, 1, b"token", 2, &[1]);
    datagram.extend(long_packet(&conn, Kind::Handshake, 9, 2, &[], 4, &crypto));
    let mut request = Vec::new();
    frame::put_stream(&mut request, 0, 0, true, b"request");
    datagram.extend(peer_data_packet(&conn, 11, &request));
    assert_reparsed_offsets(&datagram);
    conn.recv(&mut datagram).unwrap();
    assert!(!conn.tls.is_handshaking());
    assert!(conn.initial.is_none());
    assert!(conn.handshake.is_none());
    assert!(conn.spaces[0].ack.ranges.is_empty());
    assert!(conn.spaces[1].ack.ranges.is_empty());
    assert_eq!(conn.spaces[2].ack.ranges, [(11, 11)]);
    assert_eq!(conn.ready, [0]);
    assert_eq!(conn.data_seen, 7);
    let (pn, reply) = send_data(&mut conn);
    assert!(frame::Frames::new(&reply).any(|f| matches!(
        f.unwrap(),
        frame::Frame::Stream {
            id: 0,
            fin: true,
            data: RESPONSE,
            ..
        }
    )));
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.finished, 1);
}

#[test]
fn coalesced_tokens_and_length_widths_keep_packet_relative_offsets() {
    let mut conn = connection();
    let mut datagram = Vec::new();
    let mut pn = 0;
    for token_len in [0, 1, 63, 64, 255] {
        for length_width in [1, 2, 4, 8] {
            for pn_len in 1..=4 {
                datagram.extend(long_packet(
                    &conn,
                    Kind::Initial,
                    pn,
                    pn_len,
                    &vec![0x5a; token_len],
                    length_width,
                    &[1],
                ));
                pn += 1;
            }
        }
    }
    assert_reparsed_offsets(&datagram);
    conn.recv(&mut datagram).unwrap();
    assert_eq!(conn.spaces[0].ack.ranges, [(0, pn - 1)]);
    assert!(conn.spaces[0].ack.owed);
    assert_eq!(conn.finished, 0);
    assert_eq!(conn.data_seen, 0);
}

#[test]
fn failed_authentication_and_missing_keys_do_not_shift_later_packets() {
    let mut conn = connection();
    let mut datagram = long_header(Kind::ZeroRtt, &[], 20, 1);
    datagram.extend_from_slice(&[0x42; 20]);
    datagram.extend(long_header(Kind::Handshake, &[], 20, 2));
    datagram.extend_from_slice(&[0x43; 20]); // no Handshake keys yet
    let mut forged = long_packet(&conn, Kind::Initial, 6, 4, b"forged", 4, &[1]);
    *forged.last_mut().unwrap() ^= 1;
    datagram.extend(forged);
    datagram.extend(long_packet(&conn, Kind::Initial, 7, 1, b"valid", 8, &[1]));
    assert_reparsed_offsets(&datagram);
    conn.recv(&mut datagram).unwrap();
    assert_eq!(conn.spaces[0].ack.ranges, [(7, 7)]);
    assert!(conn.spaces[1].ack.ranges.is_empty());
    assert!(conn.spaces[2].ack.ranges.is_empty());
    assert!(conn.initial.is_some());
}

#[test]
fn truncated_protection_sample_cannot_read_the_next_packet() {
    let mut conn = connection();
    for length in 0..20 {
        let mut datagram = long_header(Kind::Initial, b"", length, 1);
        datagram.extend(std::iter::repeat_n(0xaa, length));
        datagram.extend(long_packet(
            &conn,
            Kind::Initial,
            30 + length as u64,
            4,
            &[],
            2,
            &[1],
        ));
        assert_reparsed_offsets(&datagram);
        conn.recv(&mut datagram).unwrap();
    }
    assert_eq!(conn.spaces[0].ack.ranges, [(30, 49)]);
}

#[test]
fn truncated_and_malformed_headers_preserve_preceding_packet_accounting() {
    let conn = connection();
    let valid = long_packet(&conn, Kind::Initial, 7, 4, &[0x5a; 64], 8, &[1]);
    let mut malformed: Vec<Vec<u8>> = (1..valid.len()).map(|n| valid[..n].to_vec()).collect();
    for index in [5, 14] {
        // destination/source CID length
        let mut bad = valid.clone();
        bad[index] = 21;
        malformed.push(bad);
    }
    let mut bad_version = valid.clone();
    bad_version[4] = 2;
    malformed.push(bad_version);
    let mut oversized = long_header(Kind::Initial, &[], 0, 8);
    let start = oversized.len() - 8;
    oversized[start..].fill(0xff);
    malformed.push(oversized);
    for suffix in malformed {
        let mut conn = connection();
        let mut datagram = long_packet(&conn, Kind::Initial, 1, 4, &[], 1, &[1]);
        datagram.extend(suffix);
        assert_eq!(conn.recv(&mut datagram), Err(Error));
        assert_eq!(conn.spaces[0].ack.ranges, [(1, 1)]);
        assert_eq!(conn.finished, 0);
    }
    for empty in [vec![], vec![0; 20], long_header(Kind::Retry, &[], 0, 1)] {
        let mut conn = connection();
        conn.recv(&mut empty.clone()).unwrap();
        assert!(conn.spaces[0].ack.ranges.is_empty());
    }
}

#[test]
fn coalesced_offsets_preserve_packet_number_reconstruction_and_replay() {
    let mut conn = connection();
    for pn_len in 1..=4 {
        for pn in [(1u64 << (pn_len * 8)) - 1, 1u64 << (pn_len * 8)] {
            conn.spaces[0].ack.ranges.clear();
            conn.spaces[0].ack.record(pn - 1, false);
            let packet = long_packet(&conn, Kind::Initial, pn, pn_len, &[0x55; 63], 4, &[1]);
            conn.recv(&mut packet.clone()).unwrap();
            conn.recv(&mut packet.clone()).unwrap();
            assert_eq!(conn.spaces[0].ack.ranges, [(pn - 1, pn)]);
        }
    }
    conn.spaces[0].ack.ranges.clear();
    for pn in [10, 13, 11, 10, 12] {
        let mut packet = long_packet(&conn, Kind::Initial, pn, 1, &[], 2, &[1]);
        conn.recv(&mut packet).unwrap();
    }
    assert_eq!(conn.spaces[0].ack.ranges, [(10, 13)]);
}
