use super::*;

#[path = "transmit_reference.rs"]
mod reference;

fn keys(seed: u8) -> Keys {
    let rustls::SupportedCipherSuite::Tls13(suite) =
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    Keys::initial(
        Version::V1,
        suite,
        suite.quic.unwrap(),
        &[seed; 8],
        Side::Server,
    )
}

fn connection(confirmed: bool, spaces: u8) -> Connection {
    let mut conn = if confirmed {
        tests::data_connection()
    } else {
        tests::connection()
    };
    // Fixed protection keys let separately constructed connections emit the
    // same ciphertext. Real TLS handshakes are covered by the recovery tests.
    conn.initial = (spaces & 1 != 0).then(|| keys(1));
    conn.handshake = (spaces & 2 != 0).then(|| keys(2));
    conn.one_rtt_local = (spaces & 4 != 0).then(|| keys(3).local);
    conn.spaces = Default::default();
    conn.connected = spaces & 4 != 0;
    conn.control.pending = false;
    conn.handshake_done.pending = false;
    conn.max_streams_bidi = 1024;
    conn.streams_credit.told = 1024;
    conn
}

fn state(conn: &Connection) -> String {
    let spaces: Vec<_> = conn
        .spaces
        .iter()
        .map(|s| {
            (
                s.next_pn,
                s.largest_acked,
                &s.ack.ranges,
                s.ack.owed,
                &s.crypto_out,
                s.crypto_offset,
                s.crypto_flight
                    .iter()
                    .map(|f| (&f.sent_in, f.offset, &f.data, f.pending))
                    .collect::<Vec<_>>(),
                s.oldest_sent.is_some(),
            )
        })
        .collect();
    let streams: Vec<_> = conn
        .streams
        .iter()
        .map(|s| match s {
            StreamSlot::Unseen => None,
            StreamSlot::Complete => Some((true, 0, false, false, false, false, false)),
            StreamSlot::Active(r) => Some((
                false,
                r.size,
                r.fin,
                r.answered,
                r.stopped,
                r.sent,
                r.send_done,
            )),
        })
        .collect();
    let flight = |f: &ControlFlight| (f.sent_in.clone(), f.pending);
    format!(
        "{:?}",
        (
            spaces,
            streams,
            (&conn.ready, &conn.unacked, conn.base_stream, conn.finished),
            (
                flight(&conn.control),
                flight(&conn.handshake_done),
                conn.path_response
            ),
            (
                conn.streams_credit.told,
                flight(&conn.streams_credit.flight)
            ),
            (conn.data_credit.told, flight(&conn.data_credit.flight)),
            conn.resets
                .iter()
                .map(|r| (r.id, r.error_code, r.final_size, flight(&r.flight)))
                .collect::<Vec<_>>(),
            (conn.pto_count, conn.rtt_probe.map(|(s, pn, _)| (s, pn))),
        )
    )
}

fn compare(candidate: &mut Connection, reference: &mut Connection, prefix: usize) -> Vec<u8> {
    let pns = candidate.spaces.each_ref().map(|s| s.next_pn);
    let mut actual = vec![0xa5; prefix];
    let mut expected = actual.clone();
    let result = candidate.poll_transmit(&mut actual);
    let old_result = reference.reference_poll_transmit(&mut expected);
    assert_eq!(result.is_ok(), old_result.is_ok());
    assert_eq!(result.unwrap(), old_result.unwrap());
    assert_eq!(actual, expected, "encrypted datagram differs");
    assert_eq!(state(candidate), state(reference), "transmit state differs");
    assert!(actual.len() - prefix <= MAX_DATAGRAM);
    assert!(actual[..prefix].iter().all(|&b| b == 0xa5));
    let mut at = prefix;
    let mut plain = Vec::new();
    while at < actual.len() {
        let (space, pn_offset, end) = if actual[at] & 0x80 == 0 {
            (Space::Data, at + 1 + candidate.peer_cid.len(), actual.len())
        } else {
            let h = packet::parse(&actual, at).unwrap();
            (h.kind.space().unwrap(), h.pn_offset, h.end)
        };
        let keys = candidate.local_keys(space).unwrap();
        let packet = &mut actual[at..end];
        let pn_at = pn_offset - at;
        let (_, pn_len) = unprotect_header(keys.header.as_ref(), packet, pn_at).unwrap();
        let (header, body) = packet.split_at_mut(pn_at + pn_len);
        let payload = keys
            .packet
            .decrypt_in_place(pns[space as usize], header, body)
            .unwrap();
        for frame in frame::Frames::new(payload) {
            frame.unwrap();
        }
        plain.extend_from_slice(payload);
        at = end;
    }
    plain
}

#[test]
fn empty_spaces_restore_the_output_and_do_not_spend_packet_numbers() {
    for mask in 0..8 {
        let mut candidate = connection(false, mask);
        let mut reference = connection(false, mask);
        for prefix in [0, 1, 63, 4096, 16384] {
            assert!(compare(&mut candidate, &mut reference, prefix).is_empty());
            assert!(candidate.spaces.iter().all(|s| s.next_pn == 0));
        }
    }
}

#[test]
fn packet_number_widths_padding_and_ack_only_classification_match() {
    for pn in [
        0,
        126,
        127,
        32766,
        32767,
        8388606,
        8388607,
        (1 << 32) - 1,
        1 << 40,
    ] {
        for recently_acked in [false, true] {
            for kind in 0..5 {
                let mut candidate = connection(true, 4);
                let mut reference = connection(true, 4);
                for conn in [&mut candidate, &mut reference] {
                    let st = &mut conn.spaces[Space::Data as usize];
                    st.next_pn = pn;
                    st.largest_acked = recently_acked.then_some(pn.saturating_sub(1));
                    match kind {
                        0 => st.ack.record(7, true),
                        1 => conn.handshake_done.pending = true,
                        2 => conn.path_response = Some([0x5a; 8]),
                        3 => conn.control.pending = true,
                        _ => conn.on_stream(0, 0, b"request", true).unwrap(),
                    }
                }
                let plain = compare(&mut candidate, &mut reference, 65);
                assert!(!plain.is_empty());
                assert_eq!(candidate.timeout().is_some(), kind != 0);
                if kind == 1 {
                    assert_eq!(plain, [frame::HANDSHAKE_DONE as u8, 0, 0]);
                }
                assert!(compare(&mut candidate, &mut reference, 65).is_empty());
            }
        }
    }
}

#[test]
fn coalesced_crypto_uses_payload_relative_room_at_every_prefix() {
    for crypto_len in [0, 1, 63, 64, 256, 1024, 1100, 1144, 2048] {
        for prefix in [0, 63, 16384] {
            let mut candidate = connection(false, 7);
            let mut reference = connection(false, 7);
            for conn in [&mut candidate, &mut reference] {
                for (i, st) in conn.spaces.iter_mut().enumerate() {
                    st.crypto_offset = (1 << 30) + i as u64;
                    st.crypto_out = vec![0x3c + i as u8; crypto_len];
                    for pn in [0, 2, 4, 6, 8, 10, 12, 14] {
                        st.ack.record(pn, true);
                    }
                }
                conn.control.pending = true;
            }
            for _ in 0..16 {
                if compare(&mut candidate, &mut reference, prefix).is_empty() {
                    break;
                }
            }
            assert!(candidate.spaces.iter().all(|s| s.crypto_out.is_empty()));
            assert!(!candidate.wants_send());
        }
    }
}

#[test]
fn full_response_packets_keep_frame_order_credit_and_recovery() {
    for requests in [1, 8, 32, 128] {
        let mut candidate = connection(true, 4);
        let mut reference = connection(true, 4);
        for conn in [&mut candidate, &mut reference] {
            for id in 0..requests {
                conn.on_stream(id * 4, 0, b"request", true).unwrap();
            }
            conn.control.pending = true;
            conn.handshake_done.pending = true;
            conn.path_response = Some([7; 8]);
            conn.finished = 512;
            conn.data_seen = 1 << 29;
            conn.resets.push(ResetFlight {
                id: 1000,
                error_code: 0x10c,
                final_size: 63,
                flight: ControlFlight::new(),
            });
            for pn in [0, 2, 10, 12, 64, 4096] {
                conn.spaces[2].ack.record(pn, true);
            }
        }
        for _ in 0..16 {
            if compare(&mut candidate, &mut reference, 16384).is_empty() {
                break;
            }
        }
        assert!(candidate.ready.is_empty());
        for conn in [&mut candidate, &mut reference] {
            let now = conn.timeout().unwrap();
            conn.on_timeout(now);
        }
        for _ in 0..16 {
            if compare(&mut candidate, &mut reference, 17).is_empty() {
                break;
            }
        }
        // A sparse ACK followed by its duplicate and late gap fills must
        // retire exactly the same flights after retransmission.
        for ranges in [
            &[(3, 3), (1, 1)][..],
            &[(3, 3), (1, 1)],
            &[(0, 2)],
            &[(0, 31)],
        ] {
            for conn in [&mut candidate, &mut reference] {
                tests::acknowledge(conn, Space::Data, ranges);
            }
            assert_eq!(state(&candidate), state(&reference));
            compare(&mut candidate, &mut reference, 0);
        }
    }
}

#[test]
fn crypto_retransmissions_split_identically_when_sparse_acks_take_room() {
    let mut candidate = connection(false, 1);
    let mut reference = connection(false, 1);
    for conn in [&mut candidate, &mut reference] {
        conn.spaces[0].crypto_out = vec![0x31; 2200];
    }
    for _ in 0..3 {
        compare(&mut candidate, &mut reference, 0);
    }
    for conn in [&mut candidate, &mut reference] {
        conn.on_timeout(conn.timeout().unwrap());
        for pn in [0, 2, 4, 6, 8, 10, 12, 14] {
            conn.spaces[0].ack.record(pn, true);
        }
    }
    for _ in 0..4 {
        compare(&mut candidate, &mut reference, 16384);
    }
    assert!(candidate.spaces[0].crypto_flight.iter().all(|f| !f.pending));
    for ranges in [&[(1, 1)][..], &[(1, 1)], &[(0, 0)]] {
        for conn in [&mut candidate, &mut reference] {
            tests::acknowledge(conn, Space::Initial, ranges);
        }
        assert_eq!(state(&candidate), state(&reference));
    }
}

#[test]
fn insufficient_datagram_room_preserves_output_and_pending_work() {
    for remaining in 0..PACKET_OVERHEAD + 4 {
        let mut conn = connection(false, 1);
        conn.spaces[0].crypto_out = vec![0x61; 64];
        let before = state(&conn);
        let mut out = vec![0xa5; MAX_DATAGRAM - remaining];
        conn.write_packet(&mut out, Space::Initial, 0).unwrap();
        assert_eq!(out, vec![0xa5; MAX_DATAGRAM - remaining]);
        assert_eq!(state(&conn), before);
    }
}

#[test]
fn connection_id_widths_preserve_coalesced_headers() {
    for peer_len in [0, 1, 8, ConnectionId::MAX] {
        for local_len in [0, 1, 8, ConnectionId::MAX] {
            let mut candidate = connection(false, 7);
            let mut reference = connection(false, 7);
            for conn in [&mut candidate, &mut reference] {
                conn.peer_cid = ConnectionId::new(&[2; ConnectionId::MAX][..peer_len]).unwrap();
                conn.local_cid = ConnectionId::new(&[3; ConnectionId::MAX][..local_len]).unwrap();
                for st in &mut conn.spaces {
                    st.next_pn = 1 << 32;
                    st.crypto_out = vec![0x32; 128];
                }
                conn.control.pending = true;
            }
            assert!(!compare(&mut candidate, &mut reference, 16384).is_empty());
            assert!(!candidate.wants_send());
        }
    }
}

#[test]
fn missing_key_error_keeps_the_same_output_and_frame_accounting() {
    let mut candidate = connection(false, 0);
    let mut reference = connection(false, 0);
    for conn in [&mut candidate, &mut reference] {
        conn.spaces[0].crypto_out = vec![0x42; 64];
        conn.spaces[0].ack.record(7, true);
    }
    let mut out = vec![0xa5; 65];
    let mut expected = out.clone();
    assert!(
        candidate
            .write_packet(&mut out, Space::Initial, 65)
            .is_err()
    );
    assert!(
        reference
            .reference_write_packet_into(&mut expected, Space::Initial, 65, &mut Vec::new())
            .is_err()
    );
    assert_eq!(out, expected);
    assert_eq!(state(&candidate), state(&reference));
}
