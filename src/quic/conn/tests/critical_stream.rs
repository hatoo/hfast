use super::*;

fn prefix(kind: u8, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    bytes[0] = match len {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
    bytes[len - 1] |= kind;
    bytes
}

fn assert_close(conn: &mut Connection) {
    assert!(conn.is_closing());
    // Closing replays a protected packet built when the error was detected.
    let pn = conn.spaces[Space::Data as usize].next_pn - 1;
    let mut packet = Vec::new();
    assert!(conn.poll_transmit(&mut packet).unwrap());
    let keys = conn.local_keys(Space::Data).unwrap();
    let pn_offset = 1 + conn.peer_cid.as_slice().len();
    let (_, pn_len) = unprotect_header(keys.header.as_ref(), &mut packet, pn_offset).unwrap();
    let (header, body) = packet.split_at_mut(pn_offset + pn_len);
    let plain = keys.packet.decrypt_in_place(pn, header, body).unwrap();
    assert_eq!(plain, [0x1d, 0x41, 0x04, 0]);
    assert!(!conn.wants_send());
    assert!(!conn.closed);
    let deadline = conn.timeout().unwrap();
    conn.on_timeout(deadline - Duration::from_nanos(1));
    assert!(!conn.closed);
    conn.on_timeout(deadline);
    assert!(conn.closed);
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
}

#[test]
fn critical_fin_and_reset_use_all_varint_widths_and_granted_stream_ids() {
    for kind in [0, 2, 3] {
        for len in [1, 2, 4, 8] {
            for id in [2, 30] {
                for reset in [false, true] {
                    let mut conn = credit_connection();
                    let data = prefix(kind, len);
                    conn.on_stream(id, 0, &data, false).unwrap();
                    assert!(!conn.is_closing());
                    let result = if reset {
                        conn.on_reset(id, 0x100, len as u64)
                    } else {
                        conn.on_stream(id, len as u64, &[], true)
                    };
                    assert_eq!(result, Err(Error));
                    assert_eq!(conn.data_seen, len as u64);
                    assert_eq!(conn.finished, 0);
                    assert_close(&mut conn);
                }
            }
        }
    }
}

#[test]
fn critical_type_is_retained_across_gaps_overlaps_and_terminal_before_type() {
    for kind in [0, 2, 3] {
        for reset in [false, true] {
            let mut conn = credit_connection();
            let data = prefix(kind, 8);
            if reset {
                conn.on_reset(2, 0x100, 64).unwrap();
            } else {
                conn.on_stream(2, 64, &[], true).unwrap();
            }
            conn.on_stream(2, 4, &data[4..], false).unwrap();
            conn.on_stream(2, 0, &data[..2], false).unwrap();
            conn.on_stream(2, 4, &data[4..], false).unwrap();
            assert!(!conn.is_closing());
            assert_eq!(conn.on_stream(2, 1, &data[1..5], false), Err(Error));
            assert_eq!(conn.data_seen, 64);
            assert_close(&mut conn);
        }
    }
}

#[test]
fn unknown_empty_partial_and_ungranted_critical_types_do_not_close() {
    for data in [&b""[..], &[0x40], &[0xc0, 0, 0, 0], &[0x21], &[0x40, 0x21]] {
        for reset in [false, true] {
            let mut conn = credit_connection();
            conn.on_stream(2, 0, data, !reset).unwrap();
            if reset {
                conn.on_reset(2, 0x100, data.len() as u64).unwrap();
            }
            conn.on_stream(2, 0, data, true).unwrap();
            conn.on_stream(34, 0, &[0], true).unwrap();
            conn.on_reset(38, 0x100, 1).unwrap();
            assert!(!conn.is_closing());
            assert_eq!(conn.data_seen, data.len() as u64);
            conn.on_stream(0, 0, b"request", true).unwrap();
            let (_, plain) = send_data(&mut conn);
            assert!(frame::Frames::new(&plain).any(|f| matches!(
                f,
                Ok(frame::Frame::Stream {
                    id: 0,
                    fin: true,
                    ..
                })
            )));
        }
    }
}

#[test]
fn critical_final_size_and_credit_errors_precede_close_and_prefix_mutation() {
    for reset in [false, true] {
        let mut conn = credit_connection();
        conn.on_stream(2, 0, &[0, 4, 0], false).unwrap();
        let result = if reset {
            conn.on_reset(2, 0x100, 2)
        } else {
            conn.on_stream(2, 2, &[], true)
        };
        assert_eq!(result, Err(Error));
        assert!(!conn.is_closing());
        assert_eq!(conn.uni_final, 0);
        assert_eq!(conn.data_seen, 3);
        assert_eq!(conn.on_reset(2, 0x100, 129), Err(Error));
        assert_eq!(
            conn.on_stream(2, conn.stream_max_data, &[0], true),
            Err(Error)
        );
        assert_eq!(conn.data_seen, 3);
        assert!(!conn.is_closing());
    }
    let mut conn = credit_connection();
    conn.on_reset(2, 0x100, 0).unwrap();
    assert_eq!(conn.on_stream(2, 0, &[0], false), Err(Error));
    assert!(!conn.is_closing());
    assert_eq!(conn.data_seen, 0);
}

#[test]
fn encrypted_critical_close_stops_same_packet_responses_and_duplicate_reentry() {
    for critical_first in [false, true] {
        let mut conn = credit_connection();
        // A previously completed request remains retired and counted.
        conn.on_stream(0, 0, b"before", true).unwrap();
        let (pn, _) = send_data(&mut conn);
        acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
        assert_eq!(conn.finished, 1);
        let mut body = Vec::new();
        if !critical_first {
            frame::put_stream(&mut body, 4, 0, true, b"same packet");
        }
        frame::put_stream(&mut body, 2, 0, true, &[0, 4, 0]);
        frame::put_stream(&mut body, 8, 0, true, b"after closure");
        let original = peer_data_packet(&conn, 100, &body);
        assert_eq!(conn.recv(&mut original.clone()), Err(Error));
        assert_eq!(conn.finished, 1);
        let seen = conn.data_seen;
        let deadline = conn.timeout();
        conn.recv(&mut original.clone()).unwrap();
        assert_eq!(conn.data_seen, seen);
        assert_eq!(conn.timeout(), deadline);
        assert_close(&mut conn);
        assert_eq!(conn.finished, 1);
    }
}

#[test]
fn uni_type_storage_is_bounded_by_the_advertised_limit() {
    assert_eq!(std::mem::size_of::<UniType>(), 9);
    assert_eq!(
        std::mem::size_of::<[UniType; transport::MAX_STREAMS_UNI]>(),
        72
    );
}
