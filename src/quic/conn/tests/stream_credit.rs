use super::*;

fn small_window() -> Connection {
    let mut conn = credit_connection();
    conn.stream_max_data = 64;
    conn
}

fn limits(plain: &[u8]) -> Vec<(u64, u64)> {
    frame::Frames::new(plain)
        .filter_map(|f| match f.unwrap() {
            frame::Frame::MaxStreamData { id, limit } => Some((id, limit)),
            _ => None,
        })
        .collect()
}

#[test]
fn stream_credit_body_crosses_initial_window() {
    let mut conn = small_window();
    for offset in (0..320).step_by(32) {
        conn.on_stream(0, offset, &[0; 32], false).unwrap();
        let (pn, plain) = send_data(&mut conn);
        assert_eq!(limits(&plain), [(0, offset + 96)]);
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        assert!(!conn.wants_send());
        assert!(conn.timeout().is_none());
    }
    conn.on_stream(0, 320, b"tail", true).unwrap();
    let (pn, plain) = send_data(&mut conn);
    assert!(limits(&plain).is_empty());
    assert!(frame::Frames::new(&plain).any(|f| matches!(
        f.unwrap(),
        frame::Frame::Stream {
            id: 0,
            data: RESPONSE,
            fin: true,
            ..
        }
    )));
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!((conn.finished, conn.data_seen), (1, 324));
}

#[test]
fn stream_credit_repeated_pto_and_late_ack() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let (original, _) = send_data(&mut conn);
    for _ in 0..3 {
        conn.on_timeout(conn.timeout().unwrap());
        let (_, plain) = send_data(&mut conn);
        assert_eq!(limits(&plain), [(0, 96)]);
    }
    conn.on_timeout(conn.timeout().unwrap());
    acknowledge(&mut conn, Space::Data, &[(original, original)]);
    assert!(!conn.wants_send());
    assert!(conn.timeout().is_none());
}

#[test]
fn stream_credit_sparse_ack_never_covers_a_hole() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let (original, _) = send_data(&mut conn);
    let mut later = original;
    for _ in 0..4 {
        conn.path_response = Some([0; 8]);
        later = send_data(&mut conn).0;
    }
    acknowledge(
        &mut conn,
        Space::Data,
        &[(later, later), (original - 1, original - 1)],
    );
    assert!(conn.wants_send());
    let (copy, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 96)]);
    acknowledge(&mut conn, Space::Data, &[(later, later)]);
    assert!(!conn.wants_send(), "old ACK cannot lose the newer copy");
    acknowledge(&mut conn, Space::Data, &[(copy, copy)]);
    assert!(conn.timeout().is_none());
}

#[test]
fn stream_credit_old_ack_cannot_deliver_new_limit() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let (old, _) = send_data(&mut conn);
    conn.on_stream(0, 32, &[0; 32], false).unwrap();
    let (new, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 128)]);
    acknowledge(&mut conn, Space::Data, &[(old, old)]);
    assert!(conn.timeout().is_some());
    conn.on_timeout(conn.timeout().unwrap());
    assert_eq!(limits(&send_data(&mut conn).1), [(0, 128)]);
    acknowledge(&mut conn, Space::Data, &[(new, new)]);
    assert!(conn.timeout().is_none());
}

#[test]
fn stream_credit_full_packet_does_not_advertise_or_forget_unsent_increase() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let mut body = vec![0; 16];
    conn.write_data(&mut body, 16, 100);
    assert_eq!(body, [0; 16]);
    assert_eq!(conn.on_stream(0, 64, b"x", false), Err(Error));
    let (old, _) = send_data(&mut conn);
    conn.on_stream(0, 32, &[0; 32], false).unwrap();
    conn.write_data(&mut body, 16, 101);
    acknowledge(&mut conn, Space::Data, &[(old, old)]);
    assert!(conn.wants_send());
    assert_eq!(conn.on_reset(0, 1, 97), Err(Error));
    let (_, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 128)]);
    assert_eq!(conn.data_seen, 64);
}

#[test]
fn stream_credit_probe_refreshes_below_threshold() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let (old, _) = send_data(&mut conn);
    conn.on_stream(0, 32, b"x", false).unwrap();
    assert!(!conn.wants_send());
    conn.on_timeout(conn.timeout().unwrap());
    let (new, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 97)]);
    acknowledge(&mut conn, Space::Data, &[(old, old)]);
    assert!(conn.timeout().is_some());
    acknowledge(&mut conn, Space::Data, &[(new, new)]);
    assert!(conn.timeout().is_none());
}

#[test]
fn stream_credit_many_streams_drain_within_packet_budget() {
    let mut conn = small_window();
    conn.initial_max_data = 4096;
    conn.data_credit.told = 4096;
    for id in [0, 4, 8, 12] {
        conn.on_stream(id, 0, &[0; 32], false).unwrap();
    }
    let mut seen = Vec::new();
    for pn in 100..104 {
        let mut body = Vec::new();
        conn.write_data(&mut body, 4, pn);
        assert_eq!(body.len(), 4);
        seen.extend(limits(&body));
    }
    assert_eq!(seen, [(0, 96), (4, 96), (8, 96), (12, 96)]);
    assert!(!conn.wants_send());
    for pn in 100..104 {
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    }
    assert!(conn.timeout().is_none());
}

#[test]
fn stream_credit_fin_reset_cancel_and_validate_final_size() {
    for reset in [false, true] {
        for sent in [false, true] {
            let mut conn = small_window();
            conn.on_stream(0, 0, &[0; 32], false).unwrap();
            let end = if sent {
                send_data(&mut conn);
                80
            } else {
                64
            };
            if reset {
                conn.on_reset(0, 0x10c, end).unwrap();
            } else {
                conn.on_stream(0, end, b"", true).unwrap();
            }
            assert!(conn.receive_credit.is_none());
            assert_eq!(conn.on_stream(0, end, b"x", false), Err(Error));
            assert_eq!(conn.on_reset(0, 0x10c, end - 1), Err(Error));
            conn.on_stream(0, end - 1, b"x", false).unwrap();
            let (pn, plain) = send_data(&mut conn);
            assert!(limits(&plain).is_empty());
            acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
            // Late large duplicates of retired requests do not reopen credit.
            conn.on_stream(0, end, b"", true).unwrap();
            conn.on_reset(0, 0x10c, end).unwrap();
            assert_eq!((conn.finished, conn.data_seen), (1, end));
            assert!(conn.receive_credit.is_none());
        }
    }
}

#[test]
fn stream_credit_stop_sending_keeps_receive_direction_live() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    conn.stop_sending(0, 0x10c);
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 96)]);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.finished, 0);
    conn.on_stream(0, 32, &[0; 32], false).unwrap();
    let (_, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 128)]);
    conn.on_stream(0, 100, b"", true).unwrap();
    assert_eq!((conn.finished, conn.data_seen), (1, 100));
    assert!(conn.receive_credit.is_none());
}

#[test]
fn stream_credit_uni_duplicate_reordering_and_reset() {
    let mut conn = small_window();
    conn.on_stream(2, 16, &[0; 16], false).unwrap();
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(2, 96)]);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.on_stream(2, 0, &[0; 32], false).unwrap();
    assert!(!conn.wants_send());
    conn.on_reset(2, 1, 80).unwrap();
    assert_eq!(conn.data_seen, 80);
    assert!(conn.receive_credit.is_none());
    conn.on_stream(2, 64, &[0; 16], false).unwrap();
    assert_eq!(conn.on_reset(2, 1, 81), Err(Error));
    assert_eq!(conn.data_seen, 80);
}

#[test]
fn stream_credit_encrypted_duplicate_packets_do_not_grant_twice() {
    let mut conn = small_window();
    let mut body = Vec::new();
    frame::put_stream(&mut body, 0, 16, false, &[0; 16]);
    let packet = peer_data_packet(&conn, 10, &body);
    conn.recv(&mut packet.clone()).unwrap();
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, 96)]);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.recv(&mut packet.clone()).unwrap();
    conn.recv(&mut peer_data_packet(&conn, 11, &body)).unwrap();
    assert_eq!(conn.data_seen, 32);
    assert!(limits(&send_data(&mut conn).1).is_empty());
    body.clear();
    frame::put_stream(&mut body, 0, 96, false, b"x");
    assert_eq!(
        conn.recv(&mut peer_data_packet(&conn, 12, &body)),
        Err(Error)
    );
    assert_eq!(conn.data_seen, 32);
}

#[test]
fn stream_credit_connection_limit_still_applies() {
    let mut conn = small_window();
    conn.on_stream(0, 0, &[0; 32], false).unwrap();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    conn.on_stream(4, 0, &[0; 32], false).unwrap();
    conn.on_stream(8, 0, &[0; 64], false).unwrap();
    assert_eq!(conn.on_stream(0, 32, b"x", false), Err(Error));
    assert_eq!(conn.on_reset(0, 1, 33), Err(Error));
    assert_eq!(conn.data_seen, 128);
    send_data(&mut conn); // MAX_DATA is now actually advertised.
    conn.on_stream(0, 32, b"x", false).unwrap();
}

#[test]
fn stream_credit_varint_saturation_and_offset_overflow() {
    let mut conn = small_window();
    let max = (1 << 62) - 1;
    conn.stream_max_data = max - 3;
    conn.initial_max_data = max - 3;
    conn.data_credit.told = max - 3;
    conn.on_stream(0, max - 4, b"x", false).unwrap();
    let (pn, plain) = send_data(&mut conn);
    assert_eq!(limits(&plain), [(0, max)]);
    assert!(frame::Frames::new(&plain).any(|f| f.unwrap() == frame::Frame::MaxData(max)));
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.on_stream(0, max, b"x", false), Err(Error));
    assert_eq!(conn.on_stream(0, u64::MAX, b"x", false), Err(Error));
    assert_eq!(conn.on_reset(0, 1, max + 1), Err(Error));
    conn.on_stream(0, max - 3, &[0; 3], true).unwrap();
    assert_eq!(conn.data_seen, max);
    assert!(conn.receive_credit.is_none());
}

#[test]
fn stream_credit_small_requests_do_not_allocate_delivery_state() {
    let mut conn = small_window();
    conn.on_stream(0, 0, b"small", false).unwrap();
    assert!(conn.receive_credit.is_none());
    conn.on_stream(0, 5, &[0; 59], true).unwrap();
    assert!(conn.receive_credit.is_none());
    for id in [1, 3, 16, 34] {
        conn.on_stream(id, 32, b"", false).unwrap();
    }
    assert!(conn.receive_credit.is_none());
    println!(
        "Connection={} Request={} StreamSlot={}",
        size_of::<Connection>(),
        size_of::<Request>(),
        size_of::<StreamSlot>()
    );
}
