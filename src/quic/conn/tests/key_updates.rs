use super::*;

struct Peer {
    keys: Keys,
    next: Secrets,
    phase: bool,
}

impl Peer {
    fn update(&mut self) {
        let next = self.next.next_packet_keys();
        self.keys.local.packet = next.local;
        self.keys.remote.packet = next.remote;
        self.phase = !self.phase;
    }

    fn packet(&self, conn: &Connection, pn: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x43 | (u8::from(self.phase) << 2)];
        packet.extend_from_slice(conn.local_cid.as_slice());
        let pn_offset = packet.len();
        packet.extend_from_slice(&pn.to_be_bytes());
        let end = packet.len();
        packet.extend_from_slice(body);
        let (header, payload) = packet.split_at_mut(end);
        let tag = self
            .keys
            .local
            .packet
            .encrypt_in_place(pn as u64, header, payload)
            .unwrap();
        packet.extend_from_slice(tag.as_ref());
        protect_header(self.keys.local.header.as_ref(), &mut packet, pn_offset, 4).unwrap();
        packet
    }

    fn receive(&self, conn: &mut Connection) -> (u64, Vec<u8>) {
        let pn = conn.spaces[Space::Data as usize].next_pn;
        let mut packet = Vec::new();
        assert!(conn.poll_transmit(&mut packet).unwrap());
        assert!(packet.len() <= MAX_DATAGRAM);
        let offset = 1 + conn.peer_cid.as_slice().len();
        let (first, len) =
            unprotect_header(self.keys.remote.header.as_ref(), &mut packet, offset).unwrap();
        assert_eq!(first & 0x04 != 0, self.phase);
        let (header, payload) = packet.split_at_mut(offset + len);
        let plain = self
            .keys
            .remote
            .packet
            .decrypt_in_place(pn, header, payload)
            .unwrap();
        (pn, plain.to_vec())
    }
}

fn pair(finish: bool) -> (Connection, Peer, Vec<u8>) {
    pair_with_suite(finish, None)
}

fn pair_with_suite(
    finish: bool,
    suite: Option<rustls::SupportedCipherSuite>,
) -> (Connection, Peer, Vec<u8>) {
    let (mut conn, mut client) = connection_and_client_with_suite(suite);
    let mut bytes = Vec::new();
    assert!(client.write_hs(&mut bytes).is_none());
    conn.tls.read_hs(&bytes).unwrap();
    conn.pump_tls();
    let mut peer = None;
    for space in [Space::Initial, Space::Handshake] {
        client
            .read_hs(&conn.spaces[space as usize].crypto_out)
            .unwrap();
        bytes.clear();
        if let Some(KeyChange::OneRtt { keys, next }) = client.write_hs(&mut bytes) {
            peer = Some(Peer {
                keys,
                next,
                phase: false,
            });
        }
        conn.discard(space);
    }
    conn.initial = None;
    if finish {
        finish_handshake(&mut conn, &bytes);
    }
    (conn, peer.unwrap(), bytes)
}

fn request(id: u64) -> Vec<u8> {
    let mut body = Vec::new();
    frame::put_stream(&mut body, id, 0, true, b"request");
    body
}

fn assert_reply(body: &[u8], id: u64) {
    assert!(frame::Frames::new(body).any(|f| f.unwrap()
        == frame::Frame::Stream {
            id,
            offset: 0,
            fin: true,
            data: RESPONSE,
        }));
}

// Excludes only the failure counter, which must advance on an AEAD failure.
fn snapshot(conn: &Connection) -> String {
    let keys = conn.key_updates.as_ref().unwrap();
    format!(
        "{:?}",
        (
            (
                keys.phase,
                keys.first,
                keys.previous_largest,
                keys.previous.as_ref().map(|(_, until)| *until)
            ),
            (
                conn.finished,
                conn.data_seen,
                conn.base_stream,
                conn.ready.clone(),
                conn.unacked.clone()
            ),
            (
                conn.spaces[2].ack.ranges.clone(),
                conn.spaces[2].ack.owed,
                conn.spaces[2].next_pn,
                conn.spaces[2].largest_acked
            ),
            (conn.timeout(), conn.rtt_probe, conn.pto_count, conn.closed),
        )
    )
}

#[test]
fn forced_and_repeated_updates_use_peer_keys_for_exact_replies_and_acks() {
    let (mut conn, mut peer, _) = pair(true);
    for generation in 0..6 {
        peer.update();
        let pn = 10 + generation * 3;
        conn.recv(&mut peer.packet(&conn, pn, &request(u64::from(generation) * 4)))
            .unwrap();
        let (sent, body) = peer.receive(&mut conn);
        assert_reply(&body, u64::from(generation) * 4);
        assert!(frame::Frames::new(&body).any(
            |f| matches!(f.unwrap(), frame::Frame::Ack { largest, .. } if largest == u64::from(pn))
        ));
        let mut ack = Vec::new();
        frame::put_ack(&mut ack, &[(sent, sent)], 0);
        conn.recv(&mut peer.packet(&conn, pn + 1, &ack)).unwrap();
        assert_eq!(conn.finished, u64::from(generation + 1));
        assert!(conn.unacked.is_empty());
        assert_eq!(conn.base_stream, u64::from(generation + 1));
    }
}

#[test]
fn old_and_new_packets_reorder_and_duplicate_across_phase_wrap() {
    let (mut conn, mut peer, _) = pair(true);
    let original = peer.packet(&conn, 10, &request(0));
    peer.update();
    let early = peer.packet(&conn, 11, &request(4));
    let late = peer.packet(&conn, 12, &request(8));
    for packet in [&late, &original, &early, &original, &late, &early] {
        conn.recv(&mut packet.clone()).unwrap();
    }
    assert_eq!(conn.ready.len(), 3);
    assert_eq!(conn.finished, 0);
    assert_eq!(conn.data_seen, 21);
    assert_eq!(conn.key_updates.as_ref().unwrap().first, Some(11));
    let (_, body) = peer.receive(&mut conn);
    for id in [0, 4, 8] {
        assert_reply(&body, id);
    }
    // Second update reuses the phase bit but must never reuse generation 0.
    peer.update();
    conn.recv(&mut peer.packet(&conn, 20, &request(12)))
        .unwrap();
    conn.recv(&mut late.clone()).unwrap(); // retained generation 1
    let before = snapshot(&conn);
    conn.recv(&mut original.clone()).unwrap(); // discarded generation 0
    assert_eq!(snapshot(&conn), before);
    assert_eq!(conn.data_seen, 28);
    assert_eq!(conn.ready, [12]);
    let (_, body) = peer.receive(&mut conn);
    assert_reply(&body, 12);
}

#[test]
fn forged_ciphertext_or_phase_cannot_advance_keys_or_accounting() {
    let (mut conn, mut peer, _) = pair(true);
    conn.recv(&mut peer.packet(&conn, 1, &request(0))).unwrap();
    let mut wrong_phase = peer.packet(&conn, 2, &request(4));
    wrong_phase[0] ^= 4;
    peer.update();
    let valid = peer.packet(&conn, 100, &request(4));
    let mut damaged = valid.clone();
    *damaged.last_mut().unwrap() ^= 0x80;
    let before = snapshot(&conn);
    for packet in [&wrong_phase, &damaged] {
        for _ in 0..3 {
            conn.recv(&mut packet.clone()).unwrap();
        }
        assert_eq!(snapshot(&conn), before);
    }
    assert_eq!(conn.key_updates.as_ref().unwrap().failed_decryptions, 6);
    conn.recv(&mut valid.clone()).unwrap();
    let (_, body) = peer.receive(&mut conn);
    assert_reply(&body, 0);
    assert_reply(&body, 4);
    assert_eq!(conn.unacked.len(), 2);
    assert_eq!(conn.finished, 0);
    // Forged current and next phase after a successful update are also inert.
    let before = snapshot(&conn);
    damaged = peer.packet(&conn, 101, &request(8));
    *damaged.last_mut().unwrap() ^= 1;
    conn.recv(&mut damaged).unwrap();
    peer.update();
    damaged = peer.packet(&conn, 102, &request(8));
    *damaged.last_mut().unwrap() ^= 1;
    conn.recv(&mut damaged).unwrap();
    assert_eq!(snapshot(&conn), before);
    conn.recv(&mut peer.packet(&conn, 103, &request(8)))
        .unwrap();
    assert_eq!(conn.ready, [8]);
    assert_eq!(conn.data_seen, 21);
}

#[test]
fn lost_transition_and_ack_retransmit_with_current_keys() {
    let (mut conn, mut peer, _) = pair(true);
    conn.spaces[2].crypto_out = b"post-handshake crypto".to_vec();
    conn.recv(&mut peer.packet(&conn, 1, &request(0))).unwrap();
    let (_, original) = peer.receive(&mut conn); // this response is lost
    assert_reply(&original, 0);
    peer.update();
    let _lost = peer.packet(&conn, 2, &[1]);
    conn.recv(&mut peer.packet(&conn, 3, &[1])).unwrap(); // PING in new phase
    let (_, lost_ack) = peer.receive(&mut conn);
    assert!(
        frame::Frames::new(&lost_ack)
            .any(|f| matches!(f.unwrap(), frame::Frame::Ack { largest: 3, .. }))
    );
    conn.on_timeout(conn.loss_timeout().unwrap());
    let (sent, retransmitted) = peer.receive(&mut conn);
    assert_reply(&retransmitted, 0);
    assert!(frame::Frames::new(&retransmitted).any(|f| f.unwrap()
        == frame::Frame::Crypto {
            offset: 0,
            data: b"post-handshake crypto"
        }));
    assert!(retransmitted.contains(&(frame::HANDSHAKE_DONE as u8)));
    assert!(frame::Frames::new(&retransmitted).any(|f| f.unwrap()
        == frame::Frame::Stream {
            id: CONTROL_STREAM,
            offset: 0,
            fin: false,
            data: CONTROL_PRELUDE
        }));
    let mut ack = Vec::new();
    frame::put_ack(&mut ack, &[(sent, sent)], 0);
    conn.recv(&mut peer.packet(&conn, 4, &ack)).unwrap();
    assert!(conn.loss_timeout().is_none());
    assert_eq!(conn.finished, 1);
}

#[test]
fn old_receive_key_expires_without_triggering_loss_recovery() {
    let (mut conn, mut peer, _) = pair(true);
    let old = peer.packet(&conn, 1, &request(4));
    peer.update();
    conn.recv(&mut peer.packet(&conn, 2, &request(0))).unwrap();
    let (sent, _) = peer.receive(&mut conn);
    let mut ack = Vec::new();
    frame::put_ack(&mut ack, &[(sent, sent)], 0);
    conn.recv(&mut peer.packet(&conn, 3, &ack)).unwrap();
    assert!(conn.loss_timeout().is_none());
    let deadline = conn.timeout().unwrap();
    conn.on_timeout(deadline - Duration::from_nanos(1));
    assert!(conn.key_updates.as_ref().unwrap().previous.is_some());
    conn.on_timeout(deadline);
    assert!(conn.key_updates.as_ref().unwrap().previous.is_none());
    assert!(conn.timeout().is_none());
    assert!(!conn.wants_send());
    assert_eq!(conn.pto_count, 0);
    let before = snapshot(&conn);
    conn.recv(&mut old.clone()).unwrap();
    assert_eq!(snapshot(&conn), before);
    // Expiry must not lose the prepared next generation.
    peer.update();
    conn.recv(&mut peer.packet(&conn, 4, &request(4))).unwrap();
    assert_eq!(conn.finished, 1);
    assert_eq!(conn.ready, [4]);
}

#[test]
fn data_and_key_updates_wait_for_the_finished_message() {
    let (mut conn, mut peer, _) = pair(false);
    for pn in 0..2 {
        conn.recv(&mut peer.packet(&conn, pn, &request(0))).unwrap();
        peer.update();
    }
    assert_eq!(conn.finished, 0);
    assert!(conn.spaces[2].ack.ranges.is_empty());
    assert_eq!(conn.key_updates.as_ref().unwrap().first, None);
    let (mut conn, mut peer, finished) = pair(false);
    peer.update();
    let packet = peer.packet(&conn, 1, &request(0));
    conn.recv(&mut packet.clone()).unwrap();
    finish_handshake(&mut conn, &finished);
    conn.recv(&mut packet.clone()).unwrap();
    assert_eq!(conn.ready, [0]);
    assert_reply(&peer.receive(&mut conn).1, 0);
}

#[test]
fn authenticated_packet_numbers_cannot_cross_generation_boundaries() {
    let (mut conn, mut peer, _) = pair(true);
    conn.recv(&mut peer.packet(&conn, 10, &[1])).unwrap();
    peer.update();
    conn.recv(&mut peer.packet(&conn, 20, &[1])).unwrap();
    // A current-generation packet below an accepted previous-generation PN
    // authenticates, but violates the monotonic generation order.
    let before = snapshot(&conn);
    assert!(conn.recv(&mut peer.packet(&conn, 9, &request(0))).is_err());
    assert_eq!(snapshot(&conn), before);
}

#[test]
fn authentication_failure_limit_survives_key_updates() {
    let (mut conn, mut peer, _) = pair(true);
    let limit = conn
        .one_rtt_remote
        .as_ref()
        .unwrap()
        .packet
        .integrity_limit();
    conn.key_updates.as_mut().unwrap().failed_decryptions = limit - 2;
    peer.update();
    conn.recv(&mut peer.packet(&conn, 1, &[1])).unwrap();
    let mut bad = peer.packet(&conn, 2, &[1]);
    *bad.last_mut().unwrap() ^= 1;
    conn.recv(&mut bad.clone()).unwrap();
    assert!(conn.recv(&mut bad).is_err());
    assert_eq!(conn.key_updates.as_ref().unwrap().failed_decryptions, limit);
}

fn cipher_suites() -> [rustls::SupportedCipherSuite; 3] {
    use rustls::crypto::ring::cipher_suite::*;
    [
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

fn ciphertext(key: &dyn PacketKey, pn: u64) -> Vec<u8> {
    let mut payload = b"generation equivalence".to_vec();
    let tag = key.encrypt_in_place(pn, b"header", &mut payload).unwrap();
    payload.extend_from_slice(tag.as_ref());
    payload
}

#[test]
fn deferred_send_keys_match_eager_ciphertext_for_every_generation_and_cipher() {
    for suite in cipher_suites() {
        let (conn, _, _) = pair_with_suite(true, Some(suite));
        assert_eq!(conn.tls.negotiated_cipher_suite().unwrap(), suite);
        let mut reference = conn.key_updates.as_ref().unwrap().secrets.clone();
        let mut updates = KeyUpdates::new(reference.clone());
        for generation in 1..=16 {
            let expected = reference.next_packet_keys();
            assert_eq!(
                ciphertext(updates.next_remote.as_ref(), generation),
                ciphertext(expected.remote.as_ref(), generation)
            );
            let prepared = std::ptr::from_ref(updates.next_remote.as_ref());
            let actual = updates.advance();
            assert!(std::ptr::addr_eq(prepared, actual.remote.as_ref()));
            assert_eq!(
                ciphertext(actual.local.as_ref(), generation),
                ciphertext(expected.local.as_ref(), generation)
            );
            assert_eq!(
                ciphertext(actual.remote.as_ref(), generation),
                ciphertext(expected.remote.as_ref(), generation)
            );
        }
    }
}

#[test]
fn forgeries_allocate_nothing_and_authenticated_updates_retain_bounded_keys() {
    use crate::test_alloc::{Counts, measure};
    for suite in cipher_suites() {
        let (mut conn, mut peer, _) = pair_with_suite(true, Some(suite));
        // Establish the ACK range outside allocation measurement.
        conn.recv(&mut peer.packet(&conn, 1, &[1])).unwrap();
        let key_size = std::mem::size_of_val(peer.keys.local.packet.as_ref()) as isize;
        for generation in 1..=12 {
            peer.update();
            let pn = generation + 1;
            let valid = peer.packet(&conn, pn, &[1]);
            let mut forged = valid.clone();
            *forged.last_mut().unwrap() ^= 1;
            let expected = snapshot(&conn);
            let prepared =
                std::ptr::from_ref(conn.key_updates.as_ref().unwrap().next_remote.as_ref());
            let (_, counts) = measure(|| conn.recv(&mut forged).unwrap());
            assert_eq!(counts, Counts::default());
            assert_eq!(snapshot(&conn), expected);
            assert!(std::ptr::addr_eq(
                prepared,
                conn.key_updates.as_ref().unwrap().next_remote.as_ref()
            ));
            let mut valid = valid;
            let (_, counts) = measure(|| conn.recv(&mut valid).unwrap());
            // Only the first update adds a retained previous key. Subsequent
            // updates replace it, regardless of how often the phase bit wraps.
            assert_eq!(counts.live, if generation == 1 { key_size } else { 0 });
            assert!(std::ptr::addr_eq(
                prepared,
                conn.one_rtt_remote.as_ref().unwrap().packet.as_ref()
            ));
            assert_eq!(conn.spaces[2].ack.ranges, [(1, u64::from(pn))]);
            let mut wrong_phase = peer.packet(&conn, pn + 1, &[1]);
            wrong_phase[0] ^= 4;
            let expected = snapshot(&conn);
            let (_, counts) = measure(|| conn.recv(&mut wrong_phase).unwrap());
            assert_eq!(counts, Counts::default());
            assert_eq!(snapshot(&conn), expected);
        }
        // Even an authenticated transition must pass generation ordering
        // before deriving or replacing any keys.
        peer.update();
        let mut backwards = peer.packet(&conn, 13, &[1]);
        let expected = snapshot(&conn);
        let (result, counts) = measure(|| conn.recv(&mut backwards));
        assert!(result.is_err());
        assert_eq!(counts, Counts::default());
        assert_eq!(snapshot(&conn), expected);
    }
}
