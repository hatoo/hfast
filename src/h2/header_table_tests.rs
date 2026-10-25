use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut wire = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn settings(sizes: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    for size in sizes {
        payload.extend_from_slice(&[0, 1]);
        payload.extend_from_slice(&size.to_be_bytes());
    }
    frame(4, 0, 0, &payload)
}

fn request(stream: u32) -> Vec<u8> {
    frame(1, 5, stream, b"\x82\x86\x84")
}

fn deliver(conn: &mut Conn, wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    assert_eq!(conn.drive(wire, &mut out), Some(wire.len()));
    out
}

fn response(stream: u32, shrink: bool, body: bool) -> Vec<u8> {
    // Keep this independent of the production template and frame lengths.
    let mut block = Vec::new();
    if shrink {
        block.push(0x20);
    }
    block.extend_from_slice(b"\x88\x0f\x10\x0atext/plain\x0f\x0d\x02\x31\x33");
    let mut expected = frame(1, 4, stream, &block);
    if body {
        expected.extend(frame(0, 1, stream, b"Hello, World!"));
    }
    expected
}

#[test]
fn every_reduced_limit_is_acknowledged_before_one_size_update() {
    for size in 0..4096 {
        let mut conn = Conn::new(&mut Vec::new());
        let input = [settings(&[size]), request(1), request(3)].concat();
        assert_eq!(
            deliver(&mut conn, &input),
            [
                frame(4, 1, 0, b""),
                response(1, true, true),
                response(3, false, true)
            ]
            .concat(),
            "limit {size}"
        );
        assert_eq!(conn.send_window, 65535 - 26);
        assert!(conn.pending.is_empty());
    }
}

#[test]
fn default_capacity_and_increases_keep_the_original_response() {
    // Deliberately allow a response before any client SETTINGS.
    let mut conn = Conn::new(&mut Vec::new());
    assert_eq!(deliver(&mut conn, &request(1)), response(1, false, true));
    for (stream, size) in [(3, 4096), (5, 8192), (7, u32::MAX), (9, 4096)] {
        assert_eq!(deliver(&mut conn, &settings(&[size])), frame(4, 1, 0, b""));
        assert_eq!(
            deliver(&mut conn, &request(stream)),
            response(stream, false, true)
        );
    }
}

#[test]
fn lowered_capacity_is_retained_across_later_increases_and_duplicate_settings() {
    for sizes in [
        vec![0, 4096],
        vec![8192, 128, u32::MAX],
        vec![31, 0, 1, 4096],
    ] {
        for separate in [false, true] {
            let mut conn = Conn::new(&mut Vec::new());
            assert_eq!(deliver(&mut conn, &request(1)), response(1, false, true));
            if separate {
                for size in &sizes {
                    assert_eq!(deliver(&mut conn, &settings(&[*size])), frame(4, 1, 0, b""));
                }
            } else {
                assert_eq!(deliver(&mut conn, &settings(&sizes)), frame(4, 1, 0, b""));
            }
            assert_eq!(deliver(&mut conn, &request(3)), response(3, true, true));
            for (i, size) in [u32::MAX, 0, 4096, 1, 0].into_iter().enumerate() {
                assert_eq!(deliver(&mut conn, &settings(&[size])), frame(4, 1, 0, b""));
                let stream = 5 + i as u32 * 2;
                assert_eq!(
                    deliver(&mut conn, &request(stream)),
                    response(stream, false, true)
                );
            }
        }
    }
}

#[test]
fn incomplete_settings_do_not_change_encoder_state() {
    let wire = settings(&[4096, 128, 4096]);
    for split in 0..wire.len() {
        let mut conn = Conn::new(&mut Vec::new());
        let mut out = Vec::new();
        assert_eq!(conn.drive(&wire[..split], &mut out), Some(0));
        assert!(out.is_empty());
        assert_eq!(deliver(&mut conn, &request(1)), response(1, false, true));
        assert_eq!(deliver(&mut conn, &wire), frame(4, 1, 0, b""));
        assert_eq!(deliver(&mut conn, &request(3)), response(3, true, true));
    }
}

#[test]
fn only_a_response_header_consumes_the_pending_update() {
    let mut conn = Conn::new(&mut Vec::new());
    deliver(&mut conn, &request(1));
    deliver(&mut conn, &settings(&[0]));
    assert!(deliver(&mut conn, &frame(4, 1, 0, b"")).is_empty());
    assert_eq!(
        deliver(&mut conn, &frame(6, 0, 0, b"barrier!")),
        frame(6, 1, 0, b"barrier!")
    );
    // Trailers, including split trailers, cannot consume the update.
    assert!(deliver(&mut conn, &request(1)).is_empty());
    assert!(deliver(&mut conn, &frame(1, 1, 1, b"")).is_empty());
    assert!(deliver(&mut conn, &frame(9, 4, 1, b"")).is_empty());
    assert!(deliver(&mut conn, &frame(1, 1, 3, b"\x82")).is_empty());
    assert!(deliver(&mut conn, &frame(9, 0, 3, b"\x86\x84")).is_empty());
    assert_eq!(
        deliver(&mut conn, &frame(9, 4, 3, b"")),
        response(3, true, true)
    );
    assert_eq!(deliver(&mut conn, &request(5)), response(5, false, true));
}

#[test]
fn pending_data_and_both_credit_limits_preserve_header_update_order() {
    for connection_blocked in [false, true] {
        let mut conn = Conn::new(&mut Vec::new());
        if connection_blocked {
            conn.send_window = 0;
        } else {
            deliver(&mut conn, &frame(4, 0, 0, &[0, 4, 0, 0, 0, 0]));
        }
        assert_eq!(deliver(&mut conn, &request(1)), response(1, false, false));
        assert_eq!(deliver(&mut conn, &settings(&[0])), frame(4, 1, 0, b""));
        let credit_stream = if connection_blocked { 0 } else { 1 };
        assert_eq!(
            deliver(&mut conn, &frame(8, 0, credit_stream, &1u32.to_be_bytes())),
            frame(0, 0, 1, b"H")
        );
        assert_eq!(deliver(&mut conn, &request(3)), response(3, true, false));
        assert_eq!(
            deliver(&mut conn, &frame(8, 0, credit_stream, &12u32.to_be_bytes())),
            frame(0, 1, 1, b"ello, World!")
        );
        let credit_stream = if connection_blocked { 0 } else { 3 };
        assert_eq!(
            deliver(&mut conn, &frame(8, 0, credit_stream, &13u32.to_be_bytes())),
            frame(0, 1, 3, b"Hello, World!")
        );
        assert!(conn.pending.is_empty());
        assert_eq!(deliver(&mut conn, &request(5)), response(5, false, false));
    }
}

#[test]
fn capacity_updates_are_local_to_the_connection() {
    let mut first = Conn::new(&mut Vec::new());
    deliver(&mut first, &settings(&[0]));
    let mut second = Conn::new(&mut Vec::new());
    assert_eq!(deliver(&mut second, &request(1)), response(1, false, true));
    assert_eq!(deliver(&mut first, &request(1)), response(1, true, true));
    deliver(&mut second, &settings(&[1]));
    assert_eq!(deliver(&mut second, &request(3)), response(3, true, true));
    assert_eq!(deliver(&mut first, &request(3)), response(3, false, true));
}
