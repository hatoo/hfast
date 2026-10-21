use super::*;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut wire = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    wire.extend_from_slice(&stream.to_be_bytes());
    wire.extend_from_slice(payload);
    wire
}

fn deliver(conn: &mut Conn, wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    assert_eq!(conn.drive(wire, &mut out), Some(wire.len()));
    out
}

fn fresh() -> Conn {
    let mut conn = Conn::new(&mut Vec::new());
    deliver(
        &mut conn,
        &frame(HEADERS, FLAG_END_HEADERS, 1, b"\x83\x86\x84"),
    );
    conn
}

fn grant(n: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, 0, &n.to_be_bytes())
}

#[test]
fn connection_credit_is_batched_across_exact_initial_window_boundary() {
    let mut conn = fresh();
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_384])).is_empty());
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_383])).is_empty());
    assert_eq!(conn.receive_uncredited, 32_767);
    assert_eq!(deliver(&mut conn, &frame(DATA, 0, 1, &[0])), grant(32_768));
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_384])).is_empty());
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_383])).is_empty());
    // The old implementation exhausted the peer's connection credit here.
    assert_eq!(deliver(&mut conn, &frame(DATA, 1, 1, &[0])), grant(32_768));
    assert_eq!(conn.receive_uncredited, 0);
    assert_eq!(conn.send_window, INITIAL_WINDOW - BODY.len() as u32);
    assert_eq!(conn.pending.capacity(), 0);
}

#[test]
fn one_mib_of_single_byte_frames_returns_only_consumed_payload() {
    let mut conn = fresh();
    let wire = frame(DATA, 0, 1, &[42]);
    let mut out = Vec::new();
    for _ in 0..1_048_576 {
        assert_eq!(conn.drive(&wire, &mut out), Some(wire.len()));
    }
    assert_eq!(out, grant(32_768).repeat(32));
    assert_eq!(conn.receive_uncredited, 0);
}

#[test]
fn padding_counts_but_empty_data_and_other_frames_do_not() {
    let mut conn = fresh();
    let mut out = Vec::new();
    // 128 frames contain only a pad-length byte and 255 padding bytes.
    let mut payload = [0; 256];
    payload[0] = 255;
    for _ in 0..128 {
        conn.drive(&frame(DATA, 8, 1, &payload), &mut out).unwrap();
        assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[])).is_empty());
        assert!(deliver(&mut conn, &frame(0xff, 0, 0, &[0; 16_384])).is_empty());
    }
    assert_eq!(out, grant(32_768));
    assert_eq!(conn.receive_uncredited, 0);
}

#[test]
fn every_split_waits_for_complete_payload_before_returning_credit() {
    let wire = frame(DATA, 8, 1, &[3, 42, 0, 0, 0]);
    for split in 0..wire.len() {
        let mut conn = fresh();
        conn.receive_uncredited = 32_767;
        let mut out = Vec::new();
        assert_eq!(conn.drive(&wire[..split], &mut out), Some(0));
        assert!(out.is_empty());
        assert_eq!(conn.receive_uncredited, 32_767);
        // TCP retains the partial frame and retries it with the remaining bytes.
        assert_eq!(conn.drive(&wire, &mut out), Some(wire.len()));
        assert_eq!(out, grant(32_772));
        assert_eq!(conn.receive_uncredited, 0);
    }
}

#[test]
fn complete_overrun_queues_goaway_and_preserves_prior_output() {
    let mut conn = fresh();
    conn.receive_uncredited = 32_767;
    let wire = frame(DATA, 0, 1, &[0; 32_769]);
    let mut out = vec![42];
    assert_eq!(conn.drive(&wire[..wire.len() - 1], &mut out), Some(0));
    assert_eq!(out, [42]);
    assert!(!conn.is_closing());
    assert_eq!(conn.drive(&wire, &mut out), Some(wire.len()));
    assert_eq!(
        out,
        [&[42][..], &frame(GOAWAY, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 3])].concat()
    );
    assert!(conn.is_closing());
    assert_eq!(conn.receive_uncredited, 32_767);
    // Once closing, no subsequent input can generate more credit or responses.
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_384])).is_empty());
}

#[test]
fn exact_remaining_receive_window_is_allowed() {
    let mut conn = fresh();
    conn.receive_uncredited = 32_767;
    // Larger frames retain the parser's existing size tolerance. The receive
    // ledger still distinguishes an exact window from a one-byte overrun.
    assert_eq!(
        deliver(&mut conn, &frame(DATA, 0, 1, &[0; 32_768])),
        grant(65_535)
    );
    assert!(!conn.is_closing());
}

#[test]
fn invalid_data_never_grants_credit() {
    for (stream, flags, payload, error) in [
        (0, 0, vec![0; 16_384], PROTOCOL_ERROR),
        (2, 0, vec![0; 16_384], PROTOCOL_ERROR),
        (3, 0, vec![0; 16_384], PROTOCOL_ERROR),
        (1, 8, vec![], FRAME_SIZE_ERROR),
        (1, 8, vec![1], PROTOCOL_ERROR),
        (1, 8, vec![2, 0], PROTOCOL_ERROR),
    ] {
        let mut conn = fresh();
        conn.receive_uncredited = 32_767;
        let wire = frame(DATA, flags, stream, &payload);
        assert_eq!(
            deliver(&mut conn, &wire),
            frame(
                GOAWAY,
                0,
                0,
                &[1_u32.to_be_bytes(), error.to_be_bytes()].concat()
            )
        );
        assert!(conn.is_closing());
        assert_eq!(conn.receive_uncredited, 32_767);
    }
}

#[test]
fn incomplete_header_block_still_rejects_data_before_accounting() {
    let mut conn = fresh();
    conn.receive_uncredited = 32_767;
    assert!(deliver(&mut conn, &frame(HEADERS, 0, 3, b"\x83")).is_empty());
    let wire = frame(DATA, 0, 1, &[0; 2]);
    let mut out = Vec::new();
    assert_eq!(conn.drive(&wire[..wire.len() - 1], &mut out), Some(0));
    assert_eq!(conn.drive(&wire, &mut out), None);
    assert!(out.is_empty());
    assert_eq!(conn.receive_uncredited, 32_767);
}

#[test]
fn request_credit_is_independent_of_blocked_responses_settings_and_resets() {
    let mut conn = fresh();
    conn.send_window = 0;
    let settings = frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]);
    deliver(&mut conn, &settings);
    deliver(&mut conn, &frame(HEADERS, 4, 3, b"\x83\x86\x84"));
    assert_eq!(conn.pending.len(), 1);
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_384])).is_empty());
    deliver(&mut conn, &frame(RST_STREAM, 0, 3, &[0; 4]));
    // DATA in flight on a reset stream still consumes connection credit.
    assert_eq!(
        deliver(&mut conn, &frame(DATA, 0, 3, &[0; 16_384])),
        grant(32_768)
    );
    assert_eq!(conn.send_window, 0);
    assert_eq!(conn.initial_window, 0);
    assert!(conn.pending.is_empty());
    assert!(deliver(&mut conn, &frame(DATA, 0, 1, &[0; 16_384])).is_empty());
    deliver(&mut conn, &settings);
    deliver(
        &mut conn,
        &frame(WINDOW_UPDATE, 0, 0, &13_u32.to_be_bytes()),
    );
    assert_eq!(conn.receive_uncredited, 16_384);
    assert_eq!(conn.send_window, 13);
}

#[test]
fn receive_accounting_fits_existing_connection_padding() {
    #[cfg(target_pointer_width = "64")]
    assert_eq!(std::mem::size_of::<Conn>(), 72);
}
