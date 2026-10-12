use super::*;

fn settled() -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    wire_ack(&mut conn, &[(pn, pn)]);
    assert!(conn.timeout().is_none());
    conn
}

fn receive(conn: &mut Connection, body: &[u8]) {
    let pn = conn.spaces[Space::Data as usize]
        .ack
        .ranges
        .first()
        .map_or(0, |r| r.1 + 1);
    let mut packet = peer_data_packet(conn, pn as u32, body);
    conn.recv(&mut packet).unwrap();
}

fn wire_ack(conn: &mut Connection, ranges: &[(u64, u64)]) {
    let mut body = Vec::new();
    let mut ordered = ranges.to_vec();
    ordered.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in ordered {
        assert!(lo <= hi);
        if let Some(last) = merged.last_mut()
            && lo <= last.1 + 1
        {
            last.1 = last.1.max(hi);
        } else {
            merged.push((lo, hi));
        }
    }
    merged.reverse();
    frame::put_ack(&mut body, &merged, 0);
    receive(conn, &body);
}

fn request(conn: &mut Connection, id: u64, fin: bool) -> u64 {
    let mut body = Vec::new();
    frame::put_stream(&mut body, id, 0, fin, b"request");
    receive(conn, &body);
    let (pn, plain) = send_data(conn);
    assert_eq!(responses(&plain), [id]);
    pn
}

fn responses(plain: &[u8]) -> Vec<u64> {
    frame::Frames::new(plain)
        .filter_map(|f| match f.unwrap() {
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } if id & 3 == 0 => {
                assert_eq!(offset, 0);
                assert_eq!(data, RESPONSE);
                assert!(fin);
                Some(id)
            }
            _ => None,
        })
        .collect()
}

fn idle(conn: &mut Connection) {
    assert!(
        conn.ready.is_empty(),
        "acknowledged response is still queued"
    );
    assert!(!conn.wants_send());
    assert!(conn.timeout().is_none());
    assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
}

#[test]
fn late_original_ack_cancels_response_queued_by_pto() {
    let mut conn = settled();
    let original = request(&mut conn, 0, true);
    let charged = conn.send_credit.sent;
    conn.on_timeout(conn.timeout().unwrap());
    assert_eq!(conn.ready, [0]);
    wire_ack(&mut conn, &[(original, original)]);
    assert_eq!(conn.finished, 1);
    assert!(conn.streams.is_empty());
    assert_eq!(conn.send_credit.sent, charged);
    idle(&mut conn);
}

#[test]
fn late_original_ack_cancels_response_queued_by_packet_loss() {
    let mut conn = settled();
    let original = request(&mut conn, 0, true);
    let mut later = original;
    for _ in 0..4 {
        conn.path_response = Some([7; 8]);
        later = send_data(&mut conn).0;
    }
    wire_ack(&mut conn, &[(later, later)]);
    assert_eq!(conn.ready, [0]);
    wire_ack(&mut conn, &[(original, original)]);
    assert_eq!(conn.finished, 1);
    idle(&mut conn);
}

#[test]
fn original_or_retry_ack_retires_response_once_after_repeated_pto() {
    for ack_original in [true, false] {
        let mut conn = settled();
        let original = request(&mut conn, 0, true);
        let charged = conn.send_credit.sent;
        conn.peer.initial_max_data = charged;
        conn.send_credit.initialize(&conn.peer);
        assert_eq!(conn.send_credit.available(), 0);
        let mut retry = original;
        for _ in 0..3 {
            conn.on_timeout(conn.timeout().unwrap());
            let (pn, plain) = send_data(&mut conn);
            retry = pn;
            assert_eq!(responses(&plain), [0]);
            assert_eq!(conn.send_credit.sent, charged);
        }
        conn.on_timeout(conn.timeout().unwrap());
        let acked = if ack_original { original } else { retry };
        wire_ack(&mut conn, &[(acked, acked)]);
        assert_eq!(conn.finished, 1);
        idle(&mut conn);
        for _ in 0..2 {
            wire_ack(&mut conn, &[(retry, retry), (original, original)]);
            assert_eq!(conn.finished, 1);
            assert_eq!(conn.send_credit.sent, charged);
            idle(&mut conn);
        }
    }
}

#[test]
fn response_ack_preserves_unfinished_request_and_sibling_timer() {
    let mut conn = settled();
    let mut body = Vec::new();
    frame::put_stream(&mut body, 0, 0, false, b"request");
    receive(&mut conn, &body);
    assert!(responses(&send_data(&mut conn).1).is_empty());
    let original = request(&mut conn, 4, true);
    let sibling = request(&mut conn, 8, true);
    conn.on_timeout(conn.timeout().unwrap());
    send_data(&mut conn);
    wire_ack(&mut conn, &[(original, original)]);
    assert_eq!(conn.finished, 1);
    assert!(!conn.stream_mut(0).unwrap().answered);
    assert!(conn.timeout().is_some(), "sibling still needs recovery");
    conn.on_timeout(conn.timeout().unwrap());
    let (_, plain) = send_data(&mut conn);
    assert_eq!(responses(&plain), [8]);
    wire_ack(&mut conn, &[(sibling, sibling)]);
    assert_eq!(conn.finished, 2);
    assert_eq!(conn.base_stream, 0);
    body.clear();
    frame::put_stream(&mut body, 0, 7, true, b"tail");
    receive(&mut conn, &body);
    let (last, plain) = send_data(&mut conn);
    assert_eq!(responses(&plain), [0]);
    wire_ack(&mut conn, &[(last, last)]);
    assert_eq!(conn.finished, 3);
    assert_eq!(conn.base_stream, 3);
    assert_eq!(conn.data_seen, 25);
    assert_eq!(
        conn.send_credit.sent,
        (CONTROL_PRELUDE.len() + 3 * RESPONSE.len()) as u64
    );
    idle(&mut conn);
}

#[test]
fn sparse_old_acks_retire_only_delivered_responses_without_duplicate_credit() {
    let mut conn = settled();
    conn.max_streams_bidi = 4;
    conn.streams_credit.told = 4;
    let first = request(&mut conn, 0, true);
    let middle = request(&mut conn, 4, true);
    let last = request(&mut conn, 8, true);
    conn.on_timeout(conn.timeout().unwrap());
    send_data(&mut conn);
    wire_ack(&mut conn, &[(last, last), (first, first)]);
    assert_eq!(conn.finished, 2);
    assert_eq!(conn.base_stream, 1);
    conn.on_timeout(conn.timeout().unwrap());
    let (credit, plain) = send_data(&mut conn);
    assert_eq!(responses(&plain), [4]);
    assert!(frame::Frames::new(&plain).any(|f| matches!(
        f.unwrap(),
        frame::Frame::MaxStreams {
            bidi: true,
            limit: 6
        }
    )));
    wire_ack(&mut conn, &[(middle, middle)]);
    assert_eq!(conn.finished, 3);
    wire_ack(&mut conn, &[(credit, credit), (first, last)]);
    assert_eq!(conn.finished, 3);
    assert_eq!(conn.streams_credit.told, 6);
    idle(&mut conn);
}

#[test]
fn stop_after_loss_keeps_reset_recovery_separate_from_response_aliases() {
    let mut conn = settled();
    let original = request(&mut conn, 0, true);
    conn.on_timeout(conn.timeout().unwrap());
    let retry = send_data(&mut conn).0;
    let mut stop = Vec::new();
    for n in [0x05, 0, 0x10c] {
        // STOP_SENDING
        put_varint(&mut stop, n);
    }
    receive(&mut conn, &stop);
    wire_ack(&mut conn, &[(retry, retry), (original, original)]);
    assert_eq!(conn.finished, 0, "RESET_STREAM is not acknowledged yet");
    let (reset, plain) = send_data(&mut conn);
    assert!(responses(&plain).is_empty());
    assert_reset(&plain, 0, RESPONSE.len() as u64);
    wire_ack(&mut conn, &[(reset, reset)]);
    assert_eq!(conn.finished, 1);
    idle(&mut conn);
}

#[test]
fn stale_loss_ack_does_not_requeue_new_response_copy_or_extend_timer() {
    let mut conn = settled();
    let original = request(&mut conn, 0, true);
    let mut later = original;
    for _ in 0..4 {
        conn.path_response = Some([7; 8]);
        later = send_data(&mut conn).0;
    }
    wire_ack(&mut conn, &[(later, later)]);
    let (retry, plain) = send_data(&mut conn);
    assert_eq!(responses(&plain), [0]);
    let deadline = conn.timeout();
    wire_ack(&mut conn, &[(later, later)]);
    assert_eq!(conn.timeout(), deadline);
    assert!(conn.ready.is_empty());
    wire_ack(&mut conn, &[(retry, retry)]);
    assert_eq!(conn.finished, 1);
    idle(&mut conn);
}

#[test]
fn ordinary_response_keeps_compact_flight_and_never_allocates_range_recovery() {
    let mut conn = settled();
    for n in 0..32 {
        let pn = request(&mut conn, n * 4, true);
        assert_eq!(conn.unacked, [(pn, n * 4)]);
        assert!(conn.send_credit.responses.is_empty());
        assert!(!conn.stream_mut(n * 4).unwrap().partial);
        wire_ack(&mut conn, &[(pn, pn)]);
        assert!(conn.send_credit.responses.is_empty());
    }
    assert_eq!(conn.finished, 32);
    assert_eq!(std::mem::size_of::<Request>(), 16);
    assert_eq!(std::mem::size_of::<(u64, u64)>(), 16);
}

#[test]
fn batched_original_acks_release_all_response_slots_and_cancel_wire_work() {
    let mut conn = settled();
    conn.max_streams_bidi = 1024;
    conn.streams_credit.told = 1024;
    for id in (0..512).map(|n| n * 4) {
        conn.on_stream(id, 0, b"request", true).unwrap();
    }
    let first = conn.spaces[Space::Data as usize].next_pn;
    let mut sent = 0;
    while conn.wants_send() {
        sent += responses(&send_data(&mut conn).1).len();
    }
    let last = conn.spaces[Space::Data as usize].next_pn - 1;
    assert_eq!(sent, 512);
    conn.on_timeout(conn.timeout().unwrap());
    let mut copies = 0;
    while conn.wants_send() {
        copies += responses(&send_data(&mut conn).1).len();
    }
    assert_eq!(copies, 512);
    wire_ack(&mut conn, &[(first, last)]);
    let retained = conn
        .streams
        .iter()
        .filter(|s| matches!(s, StreamSlot::Active(_)))
        .count();
    if let Some(deadline) = conn.timeout() {
        conn.on_timeout(deadline);
    }
    let mut redundant = 0;
    while conn.wants_send() {
        let (pn, plain) = send_data(&mut conn);
        redundant += responses(&plain).len();
        wire_ack(&mut conn, &[(pn, pn)]);
    }
    println!(
        "RESPONSE_REPLAY {{\"original_responses\":{sent},\"required_copies\":{copies},\"retained_after_original_ack\":{retained},\"redundant_responses\":{redundant}}}"
    );
    assert_eq!(retained, 0);
    assert_eq!(redundant, 0);
    assert_eq!(conn.finished, 512);
    assert_eq!(
        conn.send_credit.sent,
        (CONTROL_PRELUDE.len() + 512 * RESPONSE.len()) as u64
    );
}

#[test]
fn promoted_full_response_and_credit_fragment_share_ack_without_losing_tail() {
    let mut conn = settled();
    conn.peer.initial_max_stream_data_bidi_local = 4;
    conn.on_stream(0, 0, b"partial", true).unwrap();
    let (prefix, _) = send_data(&mut conn);
    conn.peer.initial_max_stream_data_bidi_local = RESPONSE.len() as u64;
    let full = request(&mut conn, 4, true);
    conn.on_timeout(conn.timeout().unwrap());
    send_data(&mut conn);
    wire_ack(&mut conn, &[(prefix, full)]);
    assert_eq!(conn.finished, 1);
    assert_eq!(conn.base_stream, 0);
    assert!(!conn.stream_mut(0).unwrap().send_done);
    assert_eq!(conn.stream_mut(0).unwrap().sent, 4);
    let mut grant = Vec::new();
    for n in [0x11, 0, RESPONSE.len() as u64] {
        // MAX_STREAM_DATA
        put_varint(&mut grant, n);
    }
    receive(&mut conn, &grant);
    let (pn, plain) = send_data(&mut conn);
    let parts: Vec<_> = frame::Frames::new(&plain)
        .filter_map(|f| match f.unwrap() {
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => Some((id, offset, data, fin)),
            _ => None,
        })
        .collect();
    assert_eq!(parts, [(0, 4, &RESPONSE[4..], true)]);
    wire_ack(&mut conn, &[(pn, pn)]);
    assert_eq!(conn.finished, 2);
    assert_eq!(
        conn.send_credit.sent,
        (CONTROL_PRELUDE.len() + 2 * RESPONSE.len()) as u64
    );
    idle(&mut conn);
}
