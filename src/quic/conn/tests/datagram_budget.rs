use super::*;

const SPACES: [Space; 3] = [Space::Initial, Space::Handshake, Space::Data];
const PACKET_NUMBERS: [u64; 4] = [0, 127, 32767, 8388607];

fn for_space(space: Space) -> Connection {
    match space {
        Space::Initial => connection(),
        Space::Handshake => data_connection_before_finished().0,
        Space::Data => credit_connection(),
    }
}

fn sparse_ranges() -> Vec<(u64, u64)> {
    (0..8)
        .rev()
        .map(|i| (i << 48, (i << 48) + (1 << 40)))
        .collect()
}

// Parse the emitted header and authenticate every ciphertext byte, including
// packets appended after another packet or an earlier datagram's storage.
fn decrypt(conn: &Connection, out: &[u8], at: usize, space: Space, pn: u64) -> (usize, Vec<u8>) {
    let (end, pn_offset) = if space == Space::Data {
        (out.len(), at + 1 + conn.peer_cid.len())
    } else {
        let header = packet::parse(out, at).unwrap();
        assert_eq!(header.kind.space(), Some(space));
        assert_eq!(header.dcid, conn.peer_cid);
        assert_eq!(header.scid, conn.local_cid);
        (header.end, header.pn_offset)
    };
    let keys = conn.local_keys(space).unwrap();
    let mut bytes = out[at..end].to_vec();
    let pn_offset = pn_offset - at;
    let (_, pn_len) = unprotect_header(keys.header.as_ref(), &mut bytes, pn_offset).unwrap();
    let truncated = bytes[pn_offset..pn_offset + pn_len]
        .iter()
        .fold(0u64, |n, &b| (n << 8) | u64::from(b));
    assert_eq!(
        (truncated, pn_len),
        encode_packet_number(pn, conn.spaces[space as usize].largest_acked)
    );
    let (header, body) = bytes.split_at_mut(pn_offset + pn_len);
    let plain = keys.packet.decrypt_in_place(pn, header, body).unwrap();
    // Also reject malformed/truncated frame encodings.
    frame::Frames::new(plain)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    (end, plain.to_vec())
}

fn assert_ack(plain: &[u8], expected: &[(u64, u64)]) {
    let frames = frame::Frames::new(plain)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let [
        frame::Frame::Ack {
            largest,
            first_range,
            rest,
            delay,
        },
    ] = frames.as_slice()
    else {
        panic!("expected only ACK, got {frames:?}");
    };
    assert_eq!(*delay, 0);
    assert_eq!(
        frame::AckRanges::new(*largest, *first_range, rest).collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn full_crypto_fits_for_every_peer_cid_and_packet_number_width() {
    for space in SPACES {
        for cid_len in 0..=ConnectionId::MAX {
            for start_pn in PACKET_NUMBERS {
                let mut conn = for_space(space);
                conn.peer_cid = ConnectionId::new(&[2; ConnectionId::MAX][..cid_len]).unwrap();
                let st = &mut conn.spaces[space as usize];
                st.next_pn = start_pn;
                st.largest_acked = None;
                let offset = if start_pn == 0 { 0 } else { 1 << 40 };
                st.crypto_offset = offset;
                let expected: Vec<_> = (0..2500).map(|i| i as u8).collect();
                st.crypto_out = expected.clone();
                let mut received = Vec::new();
                let mut pn = start_pn;
                while !conn.spaces[space as usize].crypto_out.is_empty() {
                    assert!(pn - start_pn < 8, "CRYPTO did not drain");
                    let mut out = vec![0xa5; 31];
                    conn.write_packet(&mut out, space, 31).unwrap();
                    assert_eq!(&out[..31], &[0xa5; 31]);
                    assert!(
                        out.len() - 31 <= MAX_DATAGRAM,
                        "{space:?} cid={cid_len} pn={pn}: {} bytes",
                        out.len() - 31
                    );
                    let (end, plain) = decrypt(&conn, &out, 31, space, pn);
                    assert_eq!(end, out.len());
                    let frames = frame::Frames::new(&plain)
                        .collect::<Result<Vec<_>>>()
                        .unwrap();
                    let [frame::Frame::Crypto { offset: at, data }] = frames.as_slice() else {
                        panic!("unexpected frames: {frames:?}");
                    };
                    assert_eq!(*at, offset + received.len() as u64);
                    received.extend_from_slice(data);
                    let flight = conn.spaces[space as usize].crypto_flight.last().unwrap();
                    assert_eq!(flight.offset, *at);
                    assert_eq!(flight.data, *data);
                    assert_eq!(flight.sent_in, [pn]);
                    assert!(!flight.pending);
                    pn += 1;
                    assert_eq!(conn.spaces[space as usize].next_pn, pn);
                }
                assert_eq!(received, expected);
                acknowledge(&mut conn, space, &[(start_pn, pn - 1)]);
                assert!(conn.spaces[space as usize].crypto_flight.is_empty());
                assert!(conn.timeout().is_none());
                let mut empty = Vec::new();
                conn.write_packet(&mut empty, space, 0).unwrap();
                assert!(empty.is_empty());
                assert_eq!(conn.spaces[space as usize].next_pn, pn);
            }
        }
    }
}

#[test]
fn ack_room_boundaries_keep_all_ranges_owed_until_they_fit() {
    for ranges in [vec![(0, 0)], sparse_ranges()] {
        let mut encoded = Vec::new();
        frame::put_ack(&mut encoded, &ranges, 0);
        for space in SPACES {
            for cid_len in [0, 8, ConnectionId::MAX] {
                for pn in PACKET_NUMBERS {
                    let mut conn = for_space(space);
                    conn.peer_cid = ConnectionId::new(&[2; ConnectionId::MAX][..cid_len]).unwrap();
                    for room in 0..=PACKET_OVERHEAD + encoded.len() + 1 {
                        let st = &mut conn.spaces[space as usize];
                        st.next_pn = pn;
                        st.largest_acked = None;
                        st.ack.ranges = ranges.clone();
                        st.ack.owed = true;
                        let prefix = MAX_DATAGRAM - room;
                        let mut out = vec![0xa5; prefix];
                        conn.write_packet(&mut out, space, 0).unwrap();
                        assert_eq!(&out[..prefix], vec![0xa5; prefix]);
                        assert!(
                            out.len() <= MAX_DATAGRAM,
                            "ACK exceeded room={room}, {space:?}, cid={cid_len}, pn={pn}"
                        );
                        if out.len() == prefix {
                            let st = &conn.spaces[space as usize];
                            assert!(st.ack.owed);
                            assert_eq!(st.ack.ranges, ranges);
                            assert_eq!(st.next_pn, pn);
                            // A later fresh datagram must send the complete ACK.
                            out.clear();
                            conn.write_packet(&mut out, space, 0).unwrap();
                            assert!(!out.is_empty());
                            assert!(out.len() <= MAX_DATAGRAM);
                            assert_ack(&decrypt(&conn, &out, 0, space, pn).1, &ranges);
                        } else {
                            assert_ack(&decrypt(&conn, &out, prefix, space, pn).1, &ranges);
                        }
                        assert!(!conn.spaces[space as usize].ack.owed);
                        assert_eq!(conn.spaces[space as usize].next_pn, pn + 1);
                        assert!(conn.timeout().is_none(), "ACK-only packet armed recovery");
                        assert!(conn.rtt_probe.is_none());
                    }
                }
            }
        }
    }
}

#[test]
fn deferred_ack_does_not_block_crypto_or_misclassify_its_timer() {
    let mut conn = connection();
    conn.spaces[0].ack.ranges = sparse_ranges();
    conn.spaces[0].ack.owed = true;
    conn.spaces[0].crypto_out = b"tls".to_vec();
    let prefix = MAX_DATAGRAM - (PACKET_OVERHEAD + 8);
    let mut out = vec![0xa5; prefix];
    conn.write_packet(&mut out, Space::Initial, 0).unwrap();
    assert!(out.len() > prefix && out.len() <= MAX_DATAGRAM);
    assert!(conn.spaces[0].ack.owed);
    assert!(conn.spaces[0].crypto_out.is_empty());
    let plain = decrypt(&conn, &out, prefix, Space::Initial, 0).1;
    assert_eq!(
        frame::Frames::new(&plain).next().unwrap().unwrap(),
        frame::Frame::Crypto {
            offset: 0,
            data: b"tls"
        }
    );
    assert_eq!(conn.spaces[0].crypto_flight[0].sent_in, [0]);
    let deadline = conn.timeout();
    let probe = conn.rtt_probe;
    assert!(deadline.is_some());
    assert!(matches!(probe, Some((Space::Initial, 0, _))));
    out.clear();
    assert!(conn.poll_transmit(&mut out).unwrap());
    assert_ack(
        &decrypt(&conn, &out, 0, Space::Initial, 1).1,
        &sparse_ranges(),
    );
    assert_eq!(conn.timeout(), deadline);
    assert_eq!(conn.rtt_probe, probe);
    acknowledge(&mut conn, Space::Initial, &[(0, 0)]);
    assert!(conn.timeout().is_none());
    assert!(!conn.wants_send());
}

#[test]
fn path_response_waits_for_all_nine_bytes_of_room() {
    for spare in 0..=10 {
        let mut conn = credit_connection();
        let pn = conn.spaces[2].next_pn;
        conn.spaces[2].ack.record(0, true); // five-byte ACK
        conn.path_response = Some(*b"response");
        let prefix = MAX_DATAGRAM - (PACKET_OVERHEAD + 5 + spare);
        let mut out = vec![0xa5; prefix];
        conn.write_packet(&mut out, Space::Data, 0).unwrap();
        assert!(out.len() > prefix && out.len() <= MAX_DATAGRAM);
        let plain = decrypt(&conn, &out, prefix, Space::Data, pn).1;
        if spare < 9 {
            assert_ack(&plain, &[(0, 0)]);
            assert_eq!(conn.path_response, Some(*b"response"));
            assert!(conn.wants_send());
            assert!(conn.timeout().is_none());
            assert!(conn.rtt_probe.is_none());
            out.clear();
            assert!(conn.poll_transmit(&mut out).unwrap());
            let plain = decrypt(&conn, &out, 0, Space::Data, pn + 1).1;
            assert_eq!(plain, b"\x1bresponse");
        } else {
            assert_eq!(&plain[5..], b"\x1bresponse");
        }
        assert!(conn.path_response.is_none());
        assert!(conn.timeout().is_some());
        assert!(!conn.wants_send());
    }
}

#[test]
fn full_crypto_leaves_path_response_pending() {
    let mut conn = credit_connection();
    conn.spaces[2].crypto_out = vec![0x42; 2500];
    conn.path_response = Some(*b"response");
    for round in 0..4 {
        let pn = conn.spaces[2].next_pn;
        let mut out = Vec::new();
        assert!(conn.poll_transmit(&mut out).unwrap());
        assert!(out.len() <= MAX_DATAGRAM);
        let plain = decrypt(&conn, &out, 0, Space::Data, pn).1;
        if round < 2 {
            assert_eq!(conn.path_response, Some(*b"response"));
            assert!(matches!(
                frame::Frames::new(&plain)
                    .collect::<Result<Vec<_>>>()
                    .unwrap()
                    .as_slice(),
                [frame::Frame::Crypto { .. }]
            ));
        } else {
            assert_eq!(&plain[plain.len() - 9..], b"\x1bresponse");
            assert!(conn.path_response.is_none());
        }
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        if !conn.wants_send() {
            assert_eq!(round, 2);
            assert!(conn.timeout().is_none());
            return;
        }
    }
    panic!("pending path response did not drain");
}

#[test]
fn smaller_retransmission_keeps_original_ack_for_both_crypto_pieces() {
    let mut conn = connection();
    conn.peer_cid = ConnectionId::new(&[2; ConnectionId::MAX]).unwrap();
    conn.spaces[0].next_pn = 8388607;
    conn.spaces[0].crypto_out = vec![0x42; 2500];
    let mut out = Vec::new();
    assert!(conn.poll_transmit(&mut out).unwrap());
    assert!(out.len() <= MAX_DATAGRAM);
    let original = conn.spaces[0].crypto_flight[0].data.clone();
    let unsent = conn.spaces[0].crypto_out.clone();
    conn.on_timeout(conn.timeout().unwrap());
    conn.spaces[0].ack.ranges = sparse_ranges();
    conn.spaces[0].ack.owed = true;
    out.clear();
    assert!(conn.poll_transmit(&mut out).unwrap());
    assert!(out.len() <= MAX_DATAGRAM);
    let plain = decrypt(&conn, &out, 0, Space::Initial, 8388608).1;
    assert!(matches!(
        frame::Frames::new(&plain)
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .as_slice(),
        [frame::Frame::Ack { .. }, frame::Frame::Crypto { .. }]
    ));
    let flights = &conn.spaces[0].crypto_flight;
    assert_eq!(flights.len(), 2);
    assert_eq!(flights[0].sent_in, [8388607, 8388608]);
    assert_eq!(flights[1].sent_in, [8388607]);
    assert!(!flights[0].pending && flights[1].pending);
    assert_eq!(flights[1].offset, flights[0].data.len() as u64);
    assert_eq!(
        [flights[0].data.as_slice(), flights[1].data.as_slice()].concat(),
        original
    );
    acknowledge(&mut conn, Space::Initial, &[(8388607, 8388607)]);
    assert!(conn.spaces[0].crypto_flight.is_empty());
    assert_eq!(conn.spaces[0].crypto_out, unsent);
    assert!(conn.timeout().is_none());
}

#[test]
fn coalesced_packets_drain_all_spaces_with_exact_recovery_accounting() {
    let mut conn = data_connection();
    // Reinstall test keys for all three spaces to exercise coalescing after
    // the TLS helper has completed and discarded the handshake spaces.
    conn.initial = connection().initial;
    conn.handshake = connection().initial;
    conn.peer_cid = ConnectionId::new(&[2; ConnectionId::MAX]).unwrap();
    let expected = [vec![1; 1030], vec![2; 2000], vec![3; 2000]];
    let mut received = [Vec::new(), Vec::new(), Vec::new()];
    let mut next_pn = [0, 127, 8388607];
    let mut ack_count = [0; 3];
    let mut responses = 0;
    let mut paths = 0;
    for (i, st) in conn.spaces.iter_mut().enumerate() {
        st.next_pn = next_pn[i];
        st.largest_acked = None;
        st.crypto_out = expected[i].clone();
        st.ack.ranges = sparse_ranges();
        st.ack.owed = true;
    }
    conn.path_response = Some(*b"response");
    conn.on_stream(0, 0, b"request", true).unwrap();
    let mut coalesced = false;
    for _ in 0..20 {
        let mut out = vec![0xa5; 17];
        if !conn.poll_transmit(&mut out).unwrap() {
            assert!(!conn.wants_send());
            assert_eq!(received, expected);
            assert_eq!(ack_count, [1; 3]);
            assert_eq!((responses, paths), (1, 1));
            assert_eq!(conn.finished, 1);
            assert!(conn.unacked.is_empty());
            assert!(conn.timeout().is_none());
            assert!(coalesced, "fixture did not coalesce packets");
            return;
        }
        assert_eq!(&out[..17], &[0xa5; 17]);
        assert!(out.len() - 17 <= MAX_DATAGRAM);
        let mut at = 17;
        let mut packets = 0;
        while at < out.len() {
            let space = packet::parse(&out, at).unwrap().kind.space().unwrap();
            let i = space as usize;
            let (end, plain) = decrypt(&conn, &out, at, space, next_pn[i]);
            for frame in frame::Frames::new(&plain) {
                match frame.unwrap() {
                    frame::Frame::Crypto { offset, data } => {
                        assert_eq!(offset, received[i].len() as u64);
                        received[i].extend_from_slice(data);
                    }
                    frame::Frame::Ack {
                        largest,
                        first_range,
                        rest,
                        ..
                    } => {
                        assert_eq!(
                            frame::AckRanges::new(largest, first_range, rest).collect::<Vec<_>>(),
                            sparse_ranges()
                        );
                        ack_count[i] += 1;
                    }
                    frame::Frame::Stream {
                        id: 0,
                        offset: 0,
                        data,
                        fin: true,
                    } => {
                        assert_eq!(data, RESPONSE);
                        responses += 1;
                    }
                    frame::Frame::Stream {
                        id: CONTROL_STREAM,
                        data,
                        ..
                    } => assert_eq!(data, CONTROL_PRELUDE),
                    frame::Frame::Ignored | frame::Frame::Padding => {}
                    other => panic!("unexpected frame {other:?}"),
                }
            }
            paths += usize::from(plain.windows(9).any(|w| w == b"\x1bresponse"));
            acknowledge(&mut conn, space, &[(next_pn[i], next_pn[i])]);
            next_pn[i] += 1;
            assert_eq!(conn.spaces[i].next_pn, next_pn[i]);
            assert!(conn.spaces[i].crypto_flight.is_empty());
            at = end;
            packets += 1;
        }
        coalesced |= packets > 1;
    }
    panic!("coalesced transmit did not drain");
}
