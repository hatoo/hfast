use super::*;
use std::collections::BTreeMap;

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = ((payload.len() as u32) << 8 | u32::from(kind))
        .to_be_bytes()
        .to_vec();
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn peer() -> (Conn, Vec<u8>) {
    let mut out = Vec::new();
    let mut c = Conn::new(&mut out);
    c.gate = Some(DrainGate::new());
    (c, out)
}

fn feed(c: &mut Conn, out: &mut Vec<u8>, bytes: &[u8]) {
    assert_eq!(c.drive(bytes, out), Some(bytes.len()));
    assert!(!c.is_closing());
}

fn split_feed(c: &mut Conn, out: &mut Vec<u8>, bytes: &[u8], chunk: usize) {
    let mut carry = Vec::new();
    for part in bytes.chunks(chunk) {
        carry.extend_from_slice(part);
        let n = c.drive(&carry, out).unwrap();
        carry.drain(..n);
        assert!(!c.is_closing());
    }
    assert!(carry.is_empty());
}

fn phase(c: &Conn) -> DrainPhase {
    c.gate.as_ref().unwrap().phase
}

fn requests(count: u32) -> Vec<u8> {
    (0..count)
        .flat_map(|i| frame(HEADERS, 5, 2 * i + 1, b"\x82\x86\x84"))
        .collect()
}

fn decoded(out: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < out.len() {
        assert!(out.len() - at >= 9);
        let len = u32::from_be_bytes([0, out[at], out[at + 1], out[at + 2]]) as usize;
        let end = at + 9 + len;
        frames.push((
            out[at + 3],
            out[at + 4],
            u32::from_be_bytes(out[at + 5..at + 9].try_into().unwrap()),
            out[at + 9..end].to_vec(),
        ));
        at = end;
    }
    frames
}

fn bodies(out: &[u8], expected: &[u32]) {
    let mut ledger: BTreeMap<u32, (usize, Vec<u8>, usize)> = BTreeMap::new();
    for (kind, flags, id, payload) in decoded(out) {
        match kind {
            HEADERS => {
                assert!(payload == HEADER_BLOCK || payload == ZERO_TABLE_HEADER_BLOCK);
                ledger.entry(id).or_default().0 += 1;
            }
            DATA => {
                let row = ledger.get_mut(&id).expect("DATA before HEADERS");
                assert_eq!(row.2, 0, "DATA after completion");
                row.1.extend_from_slice(&payload);
                row.2 += usize::from(flags & 1 != 0);
            }
            _ => {}
        }
    }
    assert_eq!(ledger.keys().copied().collect::<Vec<_>>(), expected);
    for (_, (headers, body, ends)) in ledger {
        assert_eq!(headers, 1);
        assert_eq!(body, BODY);
        assert_eq!(ends, 1);
    }
}

fn ping_ack(c: &Conn) -> Vec<u8> {
    frame(PING, 1, 0, &c.gate.as_ref().unwrap().nonce)
}

#[test]
fn fragmented_and_coalesced_gate_preserves_every_body_and_control_order() {
    for chunk in [1, 2, 7, 9, 19, 128, 4096] {
        let (mut c, mut out) = peer();
        let mut prelude = frame(SETTINGS, 0, 0, &[0, 1, 0, 0, 0, 0]);
        prelude.extend_from_slice(SETTINGS_ACK);
        prelude.extend_from_slice(&requests(DRAIN_REQUESTS));
        split_feed(&mut c, &mut out, &prelude, chunk);
        assert_eq!(phase(&c), DrainPhase::Settings);
        assert!(
            !decoded(&out)
                .iter()
                .any(|(kind, _, id, _)| *kind == DATA && *id == 1)
        );
        split_feed(&mut c, &mut out, SETTINGS_ACK, chunk);
        assert_eq!(phase(&c), DrainPhase::Ping);
        let frames = decoded(&out);
        let pause = frames
            .iter()
            .position(|f| f.0 == SETTINGS && f.3 == [0, 3, 0, 0, 0, 0])
            .unwrap();
        let final_body = frames.iter().rposition(|f| f.0 == DATA).unwrap();
        let ping = frames.iter().position(|f| f.0 == PING).unwrap();
        assert!(pause < final_body && final_body < ping);
        assert_eq!(frames[final_body].2, 1);
        let ack = ping_ack(&c);
        split_feed(&mut c, &mut out, &ack, chunk);
        assert_eq!(phase(&c), DrainPhase::Done);
        split_feed(&mut c, &mut out, SETTINGS_ACK, chunk);
        let more = frame(HEADERS, 5, 2 * DRAIN_REQUESTS + 1, b"\x82");
        split_feed(&mut c, &mut out, &more, chunk);
        bodies(
            &out,
            &(0..=DRAIN_REQUESTS).map(|i| 2 * i + 1).collect::<Vec<_>>(),
        );
        assert!(c.pending.is_empty());
        assert!(c.gate.as_ref().unwrap().held.is_none());
        assert_eq!(c.gate.as_ref().unwrap().requests, DRAIN_REQUESTS);
        assert_eq!(decoded(&out).iter().filter(|f| f.0 == PING).count(), 1);
    }
}

#[test]
fn initial_ack_cannot_release_pause_and_duplicate_ack_fails_visibly() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), DrainPhase::Settings);
    assert_eq!(c.gate.as_ref().unwrap().held.as_ref().unwrap().sent, 0);
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), DrainPhase::Ping);
    assert_eq!(c.drive(SETTINGS_ACK, &mut out), Some(9));
    assert!(c.is_closing());
    assert_eq!(decoded(&out).last().unwrap().0, GOAWAY);
    assert!(c.gate.is_none());
}

#[test]
fn stale_wrong_and_duplicate_ping_acks_never_open_the_gate() {
    let (mut c, mut out) = peer();
    let ack = ping_ack(&c);
    feed(&mut c, &mut out, &ack);
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    feed(&mut c, &mut out, &ack);
    assert_eq!(phase(&c), DrainPhase::Settings);
    feed(&mut c, &mut out, SETTINGS_ACK);
    let before = out.len();
    feed(&mut c, &mut out, &frame(PING, 1, 0, b"unrelate"));
    assert_eq!(out.len(), before);
    feed(&mut c, &mut out, &frame(PING, 0, 0, b"unrelate"));
    assert_eq!(phase(&c), DrainPhase::Ping);
    feed(&mut c, &mut out, &ack);
    let after = out.len();
    feed(&mut c, &mut out, &ack);
    assert_eq!(out.len(), after);
    assert_eq!(phase(&c), DrainPhase::Done);
    let (other, _) = peer();
    assert_ne!(other.gate.unwrap().nonce, c.gate.unwrap().nonce);
}

#[test]
fn held_and_sorted_pending_bodies_keep_independent_reduced_credit() {
    let (mut c, mut out) = peer();
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 5]),
    );
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    assert_eq!(c.pending.len(), 96);
    assert_eq!(c.pending.front().unwrap().stream, 3);
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), DrainPhase::Bodies);
    assert_eq!(c.gate.as_ref().unwrap().held.as_ref().unwrap().sent, 5);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]),
    );
    assert_eq!(c.gate.as_ref().unwrap().held.as_ref().unwrap().window, -5);
    feed(
        &mut c,
        &mut out,
        &frame(WINDOW_UPDATE, 0, 1, &6_u32.to_be_bytes()),
    );
    assert_eq!(c.gate.as_ref().unwrap().held.as_ref().unwrap().sent, 6);
    assert_eq!(phase(&c), DrainPhase::Bodies);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 13]),
    );
    assert_eq!(phase(&c), DrainPhase::Ping);
    bodies(
        &out,
        &(0..DRAIN_REQUESTS).map(|i| 2 * i + 1).collect::<Vec<_>>(),
    );
    assert!(c.pending.is_empty());
}

#[test]
fn connection_credit_blocks_ping_until_the_last_data_byte() {
    let (mut c, mut out) = peer();
    c.send_window = 0;
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), DrainPhase::Bodies);
    feed(
        &mut c,
        &mut out,
        &frame(
            WINDOW_UPDATE,
            0,
            0,
            &(13 * DRAIN_REQUESTS - 1).to_be_bytes(),
        ),
    );
    assert_eq!(phase(&c), DrainPhase::Bodies);
    assert!(!decoded(&out).iter().any(|f| f.0 == PING));
    feed(
        &mut c,
        &mut out,
        &frame(WINDOW_UPDATE, 0, 0, &1_u32.to_be_bytes()),
    );
    assert_eq!(phase(&c), DrainPhase::Ping);
    bodies(
        &out,
        &(0..DRAIN_REQUESTS).map(|i| 2 * i + 1).collect::<Vec<_>>(),
    );
}

#[test]
fn reset_held_and_pending_responses_never_resurrects_body_or_credit() {
    let (mut c, mut out) = peer();
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]),
    );
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    for id in [1_u32, 3, 99, 193] {
        feed(
            &mut c,
            &mut out,
            &frame(RST_STREAM, 0, id, &8_u32.to_be_bytes()),
        );
        feed(
            &mut c,
            &mut out,
            &frame(WINDOW_UPDATE, 0, id, &13_u32.to_be_bytes()),
        );
    }
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), DrainPhase::Bodies);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 13]),
    );
    assert_eq!(phase(&c), DrainPhase::Ping);
    for (kind, _, id, _) in decoded(&out) {
        assert!(!(kind == DATA && [1, 3, 99, 193].contains(&id)));
    }
    assert!(c.pending.is_empty());
}

#[test]
fn zero_or_overflowing_credit_resets_held_without_leaking_a_response() {
    for increment in [0_u32, MAX_WINDOW] {
        let (mut c, mut out) = peer();
        feed(&mut c, &mut out, &requests(1));
        feed(
            &mut c,
            &mut out,
            &frame(WINDOW_UPDATE, 0, 1, &increment.to_be_bytes()),
        );
        assert!(c.gate.as_ref().unwrap().held.is_none());
        assert_eq!(decoded(&out).last().unwrap().0, RST_STREAM);
        assert!(!decoded(&out).iter().any(|f| f.0 == DATA));
    }
}

#[test]
fn continuations_and_trailers_do_not_count_as_new_requests() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, &frame(HEADERS, 1, 1, b"\x82"));
    assert_eq!(c.gate.as_ref().unwrap().requests, 0);
    feed(&mut c, &mut out, &frame(CONTINUATION, 4, 1, b"\x86"));
    feed(&mut c, &mut out, &frame(HEADERS, 0, 1, b"\x00"));
    feed(&mut c, &mut out, &frame(CONTINUATION, 4, 1, b"\x00"));
    assert_eq!(c.gate.as_ref().unwrap().requests, 1);
    assert_eq!(decoded(&out).iter().filter(|f| f.0 == HEADERS).count(), 1);
    assert!(c.drive(&frame(GOAWAY, 0, 0, &[0; 8]), &mut out).is_none());
    // Transport owns and drops this connection, including its one held body.
    drop(c);
}

#[test]
fn unacknowledged_pause_has_a_fixed_request_bound() {
    let (mut c, mut out) = peer();
    let input = requests(DRAIN_REQUEST_BOUND + 1);
    assert_eq!(c.drive(&input, &mut out), Some(input.len()));
    assert!(c.is_closing());
    assert!(c.pending.is_empty());
    assert!(c.gate.is_none());
    assert_eq!(decoded(&out).last().unwrap().0, GOAWAY);
}

#[test]
fn new_stream_after_zero_limit_ack_invalidates_the_barrier() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(DRAIN_REQUESTS));
    feed(&mut c, &mut out, SETTINGS_ACK);
    let input = frame(HEADERS, 5, 195, b"\x82");
    assert_eq!(c.drive(&input, &mut out), Some(input.len()));
    assert!(c.is_closing());
    assert_eq!(decoded(&out).last().unwrap().0, GOAWAY);
}
