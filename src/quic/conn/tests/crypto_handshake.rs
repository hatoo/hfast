use super::*;

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
    fn pair() -> (Connection, Self) {
        let (mut conn, tls) =
            tls_tickets::production_pair(crate::quic::endpoint::tls_config(), false);
        let rustls::SupportedCipherSuite::Tls13(suite) =
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let initial = Keys::initial(
            Version::V1,
            suite,
            suite.quic.unwrap(),
            &[1; 8],
            Side::Client,
        );
        let mut peer = Self {
            tls,
            keys: [Some(initial), None, None],
            received: [0; 3],
            crypto: Default::default(),
            finished: Vec::new(),
            data_receipts: Vec::new(),
            next_pn: 0,
        };
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
        conn.recv(&mut out).unwrap();
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
