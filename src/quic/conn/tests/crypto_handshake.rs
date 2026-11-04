use super::*;
use crate::quic::wire::Reader;

/// A rustls peer which consumes only authenticated wire output. The server's
/// TLS, flight, packet-number and timer state is never seeded by the fixture.
struct Peer {
    tls: rustls::quic::ClientConnection,
    keys: [Option<Keys>; 3],
    received: [u64; 3],
    crypto: [Assembler; 3],
    finished: Vec<u8>,
    data_receipts: Vec<u64>,
    next_pn: u32,
}

impl Peer {
    fn unstarted(params: Vec<u8>) -> (Connection, Self) {
        let (conn, tls) = tls_tickets::production_pair_with_params(
            crate::quic::endpoint::tls_config(),
            false,
            params,
        );
        let rustls::SupportedCipherSuite::Tls13(suite) =
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let initial = Keys::initial(
            Version::V1,
            suite,
            suite.quic.unwrap(),
            &[1; 8],
            Side::Client,
        );
        let peer = Self {
            tls,
            keys: [Some(initial), None, None],
            received: [0; 3],
            crypto: Default::default(),
            finished: Vec::new(),
            data_receipts: Vec::new(),
            next_pn: 0,
        };
        (conn, peer)
    }

    fn pair() -> (Connection, Self) {
        Self::pair_with_params(tls_tickets::client_params())
    }

    fn pair_with_params(params: Vec<u8>) -> (Connection, Self) {
        let (mut conn, mut peer) = Self::unstarted(params);
        let mut hello = Vec::new();
        assert!(peer.tls.write_hs(&mut hello).is_none());
        let mut body = Vec::new();
        frame::put_crypto(&mut body, 0, &hello);
        peer.send(&mut conn, Space::Initial, &body);
        peer.drain(&mut conn);
        assert!(!peer.tls.is_handshaking());
        assert!(conn.tls.is_handshaking());
        assert!(!peer.finished.is_empty());
        assert!(conn.spaces[0].crypto_out.is_empty());
        assert!(conn.spaces[1].crypto_out.is_empty());
        assert!(!conn.spaces[0].crypto_flight.is_empty());
        assert!(!conn.spaces[1].crypto_flight.is_empty());
        (conn, peer)
    }

    fn send(&mut self, conn: &mut Connection, space: Space, body: &[u8]) {
        let mut out = self.packet(conn, space, body);
        conn.recv(&mut out).unwrap();
    }

    fn packet(&mut self, conn: &Connection, space: Space, body: &[u8]) -> Vec<u8> {
        let keys = &self.keys[space as usize].as_ref().unwrap().local;
        let mut out = Vec::new();
        let length_at = match space {
            Space::Initial | Space::Handshake => Some(packet::put_long_header(
                &mut out,
                if space == Space::Initial {
                    Kind::Initial
                } else {
                    Kind::Handshake
                },
                &if space == Space::Initial {
                    ConnectionId::new(&[1; 8]).unwrap()
                } else {
                    conn.local_cid
                },
                &conn.peer_cid,
                4,
                body.len(),
            )),
            Space::Data => {
                out.push(0x43);
                out.extend_from_slice(conn.local_cid.as_slice());
                None
            }
        };
        let pn = self.next_pn;
        self.next_pn += 1;
        let pn_offset = out.len();
        out.extend_from_slice(&pn.to_be_bytes());
        let header_end = out.len();
        out.extend_from_slice(body);
        if let Some(at) = length_at {
            packet::patch_length(&mut out, at, (4 + body.len() + TAG_LEN) as u64).unwrap();
        }
        let (header, payload) = out.split_at_mut(header_end);
        let tag = keys
            .packet
            .encrypt_in_place(u64::from(pn), header, payload)
            .unwrap();
        out.extend_from_slice(tag.as_ref());
        protect_header(keys.header.as_ref(), &mut out, pn_offset, 4).unwrap();
        out
    }

    /// Return authenticated packet numbers and plaintext, including ACK-only
    /// packets; only CRYPTO goes to the independent TLS implementation.
    fn drain(&mut self, conn: &mut Connection) -> Vec<(Space, u64, Vec<u8>)> {
        let mut receipts = Vec::new();
        loop {
            let mut out = Vec::new();
            if !conn.poll_transmit(&mut out).unwrap() {
                break;
            }
            assert!(out.len() <= MAX_DATAGRAM);
            let mut at = 0;
            while at < out.len() {
                let header = packet::parse(&out, at).unwrap();
                let space = header.kind.space().unwrap();
                let index = space as usize;
                let keys = &self.keys[index].as_ref().unwrap().remote;
                let mut bytes = out[at..header.end].to_vec();
                let pn_offset = header.pn_offset - at;
                let (_, pn_len) =
                    unprotect_header(keys.header.as_ref(), &mut bytes, pn_offset).unwrap();
                let truncated = bytes[pn_offset..pn_offset + pn_len]
                    .iter()
                    .fold(0, |n, b| (n << 8) | u64::from(*b));
                let pn = decode_packet_number(self.received[index], truncated, (pn_len * 8) as u32);
                self.received[index] = pn;
                let (head, payload) = bytes.split_at_mut(pn_offset + pn_len);
                let plain = keys
                    .packet
                    .decrypt_in_place(pn, head, payload)
                    .unwrap()
                    .to_vec();
                for f in frame::Frames::new(&plain) {
                    if let frame::Frame::Crypto { offset, data } = f.unwrap() {
                        let assembled = &mut self.crypto[index];
                        assembled.push(offset, data);
                        if !assembled.read().is_empty() {
                            self.tls.read_hs(assembled.read()).unwrap();
                            assembled.consume(assembled.read().len());
                            match self.tls.write_hs(&mut self.finished) {
                                Some(KeyChange::Handshake { keys }) => self.keys[1] = Some(keys),
                                Some(KeyChange::OneRtt { keys, .. }) => self.keys[2] = Some(keys),
                                None => {}
                            }
                        }
                    }
                }
                receipts.push((space, pn, plain));
                if space == Space::Data {
                    self.data_receipts.push(pn);
                }
                at = header.end;
            }
        }
        receipts
    }

    fn ack(&mut self, conn: &mut Connection, space: Space, pn: u64) {
        let mut body = Vec::new();
        frame::put_ack(&mut body, &[(pn, pn)], 0);
        self.send(conn, space, &body);
    }

    fn complete(&mut self, conn: &mut Connection) {
        let mut body = Vec::new();
        frame::put_crypto(&mut body, 0, &self.finished);
        self.send(conn, Space::Handshake, &body);
        assert!(!conn.tls.is_handshaking());
        assert!(conn.initial.is_none() && conn.handshake.is_none());
        assert!(
            conn.spaces
                .iter()
                .all(|s| s.crypto_flight.is_empty() && s.crypto_out.is_empty())
        );
        // SETTINGS can precede Finished. The server correctly ignores 1-RTT
        // ACKs until now, so settle those authenticated receipts afterwards.
        for pn in std::mem::take(&mut self.data_receipts) {
            self.ack(conn, Space::Data, pn);
        }
        body.clear();
        frame::put_stream(&mut body, 0, 0, true, b"request");
        self.send(conn, Space::Data, &body);
        let packets = self.drain(conn);
        let replies: Vec<_> = packets
            .iter()
            .flat_map(|(_, _, plain)| frame::Frames::new(plain))
            .filter_map(|f| match f.unwrap() {
                frame::Frame::Stream {
                    id: 0,
                    offset,
                    fin,
                    data,
                } => Some((offset, fin, data)),
                _ => None,
            })
            .collect();
        assert_eq!(replies, [(0, true, RESPONSE)]);
        for (space, pn, _) in packets {
            self.ack(conn, space, pn);
        }
        assert_eq!(conn.finished, 1);
        assert!(conn.timeout().is_none());
    }
}

#[test]
fn encrypted_handshake_ack_only_progress_does_not_ack_crypto_or_reset_backoff() {
    let (mut conn, mut peer) = Peer::pair();
    peer.send(&mut conn, Space::Handshake, &[frame::PING as u8]);
    peer.drain(&mut conn);
    assert!(conn.initial.is_none());
    for attempt in 1..=8 {
        conn.on_timeout(conn.timeout().unwrap());
        peer.drain(&mut conn);
        peer.send(&mut conn, Space::Handshake, &[frame::PING as u8]);
        let receipts = peer.drain(&mut conn);
        let (_, ack_only, _) = receipts
            .iter()
            .find(|(space, _, plain)| {
                *space == Space::Handshake
                    && frame::Frames::new(plain).all(|f| {
                        matches!(f.unwrap(), frame::Frame::Ack { .. } | frame::Frame::Padding)
                    })
            })
            .unwrap();
        let deadline = conn.timeout();
        for _ in 0..2 {
            peer.ack(&mut conn, Space::Handshake, *ack_only);
            assert_eq!(conn.pto_count, attempt);
            assert_eq!(conn.timeout(), deadline);
        }
        assert!(
            conn.spaces[1]
                .crypto_flight
                .iter()
                .all(|f| !f.pending && f.sent_in.len() == attempt as usize + 1)
        );
    }
    peer.complete(&mut conn);
}

#[test]
fn encrypted_late_original_ack_cancels_sent_and_queued_crypto_retries() {
    for queued in [false, true] {
        let (mut conn, mut peer) = Peer::pair();
        // This ACK is scoped to Handshake, and also retires Initial keys.
        // ACK pn0 only after several later copies were actually emitted.
        peer.send(&mut conn, Space::Handshake, &[frame::PING as u8]);
        peer.drain(&mut conn);
        for _ in 0..8 {
            conn.on_timeout(conn.timeout().unwrap());
            peer.drain(&mut conn);
        }
        if queued {
            conn.on_timeout(conn.timeout().unwrap());
        }
        peer.ack(&mut conn, Space::Handshake, 0);
        assert!(conn.spaces[1].crypto_flight.is_empty());
        peer.ack(&mut conn, Space::Handshake, 0);
        let packets = peer.drain(&mut conn);
        assert!(packets.iter().all(|(_, _, plain)| {
            frame::Frames::new(plain).all(|f| !matches!(f.unwrap(), frame::Frame::Crypto { .. }))
        }));
        peer.complete(&mut conn);
    }
}

#[test]
fn encrypted_finished_retires_retries_before_accepting_application_data() {
    let (mut conn, mut peer) = Peer::pair();
    let mut request = Vec::new();
    frame::put_stream(&mut request, 0, 0, true, b"request");
    peer.send(&mut conn, Space::Data, &request);
    assert!(conn.streams.is_empty());
    for _ in 0..8 {
        conn.on_timeout(conn.timeout().unwrap());
        peer.drain(&mut conn);
    }
    // Keep the final retry queued when Finished authenticates. Neither old
    // encryption level may retain a timer or emit CRYPTO afterwards.
    conn.on_timeout(conn.timeout().unwrap());
    peer.complete(&mut conn);
}

#[test]
fn encrypted_malformed_transport_parameters_never_activate_application_keys() {
    for malformed in [
        vec![0x3f, 3, 1], // truncated unknown parameter body
        vec![0x40],       // truncated parameter id
        vec![0x3f],       // missing length
        vec![3, 1, 0x40], // truncated integer
        vec![3, 0],       // empty integer
    ] {
        for reorder in [false, true] {
            let mut params = tls_tickets::client_params();
            params.extend_from_slice(&malformed);
            assert_transport_parameters_rejected(params, reorder);
        }
    }
}

#[test]
fn encrypted_valid_and_unknown_transport_parameters_complete_normally() {
    for unknown in [false, true] {
        let mut params = tls_tickets::client_params();
        if unknown {
            // Unknown opaque data need not encode an integer, and an empty
            // unknown parameter is valid too.
            params.extend_from_slice(&[0x3f, 3, 0xff, 0xff, 0xff, 0x3e, 0]);
        }
        let (mut conn, mut peer) = Peer::pair_with_params(params);
        assert!(conn.connected && !conn.is_closing_handshake());
        assert_eq!(conn.peer.initial_max_data, 1 << 30);
        assert_eq!(conn.peer.initial_max_stream_data_uni, 1 << 24);
        peer.complete(&mut conn);
    }
}

fn assert_transport_parameters_rejected(params: Vec<u8>, reorder: bool) {
    let (mut conn, mut peer) = Peer::unstarted(params);
    let mut hello = Vec::new();
    assert!(peer.tls.write_hs(&mut hello).is_none());
    let mut body = Vec::new();
    let end = if reorder {
        let split = hello.len() / 2;
        frame::put_crypto(&mut body, split as u64, &hello[split..]);
        peer.send(&mut conn, Space::Initial, &body);
        peer.send(&mut conn, Space::Initial, &body);
        assert!(!conn.connected);
        body.clear();
        split
    } else {
        hello.len()
    };
    frame::put_crypto(&mut body, 0, &hello[..end]);
    let mut packet = peer.packet(&conn, Space::Initial, &body);
    let original = packet.clone();
    let received = conn.recv(&mut packet);
    assert!(
        !conn.connected,
        "malformed parameters activated the connection"
    );
    assert!(received.is_err());
    assert!(conn.is_closing_handshake());
    assert!(conn.one_rtt_local.is_none() && conn.one_rtt_remote.is_none());
    assert!(conn.key_updates.is_none());
    assert_eq!(conn.peer.initial_max_data, 0);
    assert!(conn.streams.is_empty());

    let deadline = conn.timeout().unwrap();
    let mut out = Vec::new();
    assert!(conn.poll_transmit(&mut out).unwrap());
    assert!(out.len() <= original.len());
    let header = packet::parse(&out, 0).unwrap();
    assert_eq!(header.kind, Kind::Initial);
    assert_eq!(
        packet::parse(&out, header.end).unwrap().kind,
        Kind::Handshake
    );
    // Authenticate and decode the close independently of the server's
    // keys/state. The TLS peer has not received ServerHello.
    let keys = &peer.keys[0].as_ref().unwrap().remote;
    let mut initial = out[..header.end].to_vec();
    let (_, pn_len) =
        unprotect_header(keys.header.as_ref(), &mut initial, header.pn_offset).unwrap();
    let pn = initial[header.pn_offset..header.pn_offset + pn_len]
        .iter()
        .fold(0, |pn, b| (pn << 8) | u64::from(*b));
    let (head, payload) = initial.split_at_mut(header.pn_offset + pn_len);
    let plain = keys.packet.decrypt_in_place(pn, head, payload).unwrap();
    assert_eq!(plain, [0x1c, 0x08, 0, 0]);
    out.clear();
    assert!(!conn.poll_transmit(&mut out).unwrap());
    assert!(!conn.wants_send());

    // An exact encrypted replay and fresh CRYPTO with another packet
    // number cannot revive TLS or retain ordinary flight timers.
    conn.recv(&mut original.clone()).unwrap();
    peer.send(&mut conn, Space::Initial, &body);
    assert!(!conn.connected);
    assert_eq!(conn.timeout(), Some(deadline));
    assert!(
        conn.spaces
            .iter()
            .all(|s| s.crypto_out.is_empty() && s.crypto_flight.is_empty())
    );
    conn.on_timeout(deadline);
    assert!(conn.closed);
    assert!(conn.timeout().is_none());
    assert!(conn.recv(&mut original.clone()).is_err());
    assert!(!conn.wants_send());
    assert!(!conn.poll_transmit(&mut out).unwrap());
    assert!(out.is_empty());
}

/// Rewrite one declaration without introducing a duplicate parameter ID.
fn replace_scalar(params: &[u8], id: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut reader = Reader::new(params);
    while !reader.is_empty() {
        let at = reader.position();
        let current = reader.varint().unwrap();
        reader.varint_slice().unwrap();
        if current != id {
            out.extend_from_slice(reader.slice_between(at).unwrap());
        }
    }
    put_varint(&mut out, id);
    put_varint(&mut out, body.len() as u64);
    out.extend_from_slice(body);
    out
}

#[test]
fn encrypted_scalar_trailing_bytes_never_activate_application_keys() {
    for id in 3..=11 {
        for width in [1usize, 2, 4, 8] {
            for reorder in [false, true] {
                let mut body = 7u64.to_be_bytes()[8 - width..].to_vec();
                body[0] |= (width.trailing_zeros() as u8) << 6;
                body.push(0); // part of this declared scalar, not a new TLV
                let params = replace_scalar(&tls_tickets::client_params(), id, &body);
                assert_transport_parameters_rejected(params, reorder);
            }
        }
    }
}

#[test]
fn encrypted_nonminimal_scalars_preserve_peer_credit_and_complete_normally() {
    for (id, value) in [
        (3, 1200u64),
        (4, 1 << 30),
        (5, 1 << 24),
        (6, 1 << 24),
        (7, 1 << 24),
        (8, 8),
        (9, 8),
        (10, 3),
        (11, 25),
    ] {
        let mut body = value.to_be_bytes();
        body[0] |= 0xc0;
        let params = replace_scalar(&tls_tickets::client_params(), id, &body);
        let (mut conn, mut peer) = Peer::pair_with_params(params);
        assert!(conn.connected && !conn.is_closing_handshake());
        assert_eq!(conn.peer.initial_max_data, 1 << 30);
        assert_eq!(conn.peer.initial_max_stream_data_uni, 1 << 24);
        assert_eq!(
            conn.peer.max_udp_payload_size,
            if id == 3 { 1200 } else { 65527 }
        );
        assert_eq!(conn.peer.ack_delay_exponent, 3);
        assert_eq!(conn.peer.max_ack_delay, 25);
        peer.complete(&mut conn);
    }
}
