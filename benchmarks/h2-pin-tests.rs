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
    c.gate = Some(PinGate::new());
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

fn phase(c: &Conn) -> PinPhase {
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

fn timer(c: &mut Conn, out: &mut Vec<u8>) {
    let deadline = c.gate.as_ref().unwrap().deadline.unwrap();
    let before = out.len();
    c.pin_tick(deadline - Duration::from_nanos(1), out);
    assert_eq!(before, out.len());
    c.pin_tick(deadline, out);
    assert_eq!(phase(c), PinPhase::Settings);
    let after = out.len();
    c.pin_tick(deadline + Duration::from_secs(60), out);
    assert_eq!(after, out.len(), "pause must be sent exactly once");
}

#[test]
fn timer_releases_one_or_two_pins_without_further_requests_after_fragmented_input() {
    for count in [1, 2, 128] {
        for chunk in [1, 2, 7, 9, 19, 128, 4096] {
            let (mut c, mut out) = peer();
            split_feed(&mut c, &mut out, SETTINGS_ACK, chunk);
            split_feed(&mut c, &mut out, &requests(count), chunk);
            assert_eq!(phase(&c), PinPhase::Holding);
            for id in (0..count.min(2)).map(|i| 2 * i + 1) {
                let data: Vec<_> = decoded(&out)
                    .into_iter()
                    .filter(|f| f.0 == DATA && f.2 == id)
                    .collect();
                assert_eq!(data.len(), 1);
                assert_eq!(data[0].1, 0);
                assert_eq!(data[0].3, BODY[..12]);
            }
            timer(&mut c, &mut out);
            split_feed(&mut c, &mut out, SETTINGS_ACK, chunk);
            assert_eq!(phase(&c), PinPhase::Ping);
            let frames = decoded(&out);
            let pause = frames
                .iter()
                .position(|f| f.0 == SETTINGS && f.3 == [0, 3, 0, 0, 0, 0])
                .unwrap();
            let last = frames.iter().rposition(|f| f.0 == DATA).unwrap();
            let ping = frames.iter().position(|f| f.0 == PING).unwrap();
            assert!(pause < last && last < ping);
            bodies(&out, &(0..count).map(|i| 2 * i + 1).collect::<Vec<_>>());
            let ack = ping_ack(&c);
            split_feed(&mut c, &mut out, &ack, chunk);
            split_feed(&mut c, &mut out, SETTINGS_ACK, chunk);
            assert_eq!(phase(&c), PinPhase::Armed);
            let before = out.len();
            c.pin_tick(Instant::now() + Duration::from_secs(60), &mut out);
            assert_eq!(out.len(), before, "idle peers must not start another cycle");
        }
    }
}

#[test]
fn a_hundred_cycles_reuse_fixed_storage_and_reject_stale_ping_acks() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, SETTINGS_ACK);
    let mut previous = frame(PING, 1, 0, &[0; 8]);
    for cycle in 0..100_u32 {
        out.clear();
        let ids: Vec<_> = (0..32).map(|i| (cycle * 32 + i) * 2 + 1).collect();
        for &id in &ids {
            feed(&mut c, &mut out, &frame(HEADERS, 5, id, b"\x82"));
        }
        timer(&mut c, &mut out);
        feed(&mut c, &mut out, SETTINGS_ACK);
        assert_eq!(phase(&c), PinPhase::Ping);
        let before = out.len();
        feed(&mut c, &mut out, &previous);
        assert_eq!(out.len(), before);
        bodies(&out, &ids);
        let ack = ping_ack(&c);
        assert_ne!(ack, previous);
        feed(&mut c, &mut out, &ack);
        feed(&mut c, &mut out, &ack);
        feed(&mut c, &mut out, SETTINGS_ACK);
        assert_eq!(phase(&c), PinPhase::Armed);
        assert!(c.gate.as_ref().unwrap().held.iter().all(Option::is_none));
        assert!(c.pending.is_empty());
        previous = ack;
    }
}

#[test]
fn partial_credit_reductions_and_replenishment_preserve_bodies_and_pin_order() {
    let (mut c, mut out) = peer();
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 5]),
    );
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(32));
    assert_eq!(c.pending.len(), 30);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]),
    );
    for p in c.gate.as_ref().unwrap().held.iter().flatten() {
        assert_eq!(p.window, -5);
        assert_eq!(p.sent, 5);
    }
    for id in [1, 3] {
        feed(
            &mut c,
            &mut out,
            &frame(WINDOW_UPDATE, 0, id, &6_u32.to_be_bytes()),
        );
    }
    for p in c.gate.as_ref().unwrap().held.iter().flatten() {
        assert_eq!(p.sent, 6);
    }
    timer(&mut c, &mut out);
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), PinPhase::Bodies);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 13]),
    );
    assert_eq!(phase(&c), PinPhase::Ping);
    bodies(&out, &(0..32).map(|i| 2 * i + 1).collect::<Vec<_>>());
}

#[test]
fn exhausted_connection_credit_cannot_emit_ping_before_the_last_byte() {
    let (mut c, mut out) = peer();
    c.send_window = 0;
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(32));
    timer(&mut c, &mut out);
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(
        &mut c,
        &mut out,
        &frame(WINDOW_UPDATE, 0, 0, &415_u32.to_be_bytes()),
    );
    assert_eq!(phase(&c), PinPhase::Bodies);
    assert!(!decoded(&out).iter().any(|f| f.0 == PING));
    feed(
        &mut c,
        &mut out,
        &frame(WINDOW_UPDATE, 0, 0, &1_u32.to_be_bytes()),
    );
    assert_eq!(phase(&c), PinPhase::Ping);
    bodies(&out, &(0..32).map(|i| 2 * i + 1).collect::<Vec<_>>());
}

#[test]
fn cancelled_pins_and_pending_streams_are_not_revived_by_late_credit() {
    let (mut c, mut out) = peer();
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]),
    );
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(32));
    for id in [1, 3, 17, 63] {
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
    timer(&mut c, &mut out);
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(
        &mut c,
        &mut out,
        &frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 13]),
    );
    assert_eq!(phase(&c), PinPhase::Ping);
    assert!(
        !decoded(&out)
            .iter()
            .any(|f| f.0 == DATA && [1, 3, 17, 63].contains(&f.2))
    );
}

#[test]
fn pause_waits_for_all_settings_acks_and_unsolicited_acks_fail_visibly() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, &requests(1));
    timer(&mut c, &mut out);
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), PinPhase::Settings);
    feed(&mut c, &mut out, SETTINGS_ACK);
    assert_eq!(phase(&c), PinPhase::Ping);
    assert_eq!(c.drive(SETTINGS_ACK, &mut out), Some(9));
    assert!(c.is_closing());
    assert!(c.gate.is_none());
}

#[test]
fn late_pre_ack_requests_complete_but_post_ack_new_requests_fail() {
    let (mut c, mut out) = peer();
    feed(&mut c, &mut out, SETTINGS_ACK);
    feed(&mut c, &mut out, &requests(2));
    timer(&mut c, &mut out);
    feed(&mut c, &mut out, &frame(HEADERS, 5, 5, b"\x82"));
    feed(&mut c, &mut out, SETTINGS_ACK);
    bodies(&out, &[1, 3, 5]);
    let input = frame(HEADERS, 5, 7, b"\x82");
    assert_eq!(c.drive(&input, &mut out), Some(input.len()));
    assert!(c.is_closing());
}

#[test]
fn invalid_credit_and_shutdown_retire_pins_without_duplicate_data() {
    for increment in [0_u32, MAX_WINDOW] {
        let (mut c, mut out) = peer();
        feed(&mut c, &mut out, &requests(2));
        out.clear();
        feed(
            &mut c,
            &mut out,
            &frame(WINDOW_UPDATE, 0, 1, &increment.to_be_bytes()),
        );
        assert!(c.gate.as_ref().unwrap().held[0].is_none());
        assert_eq!(decoded(&out).len(), 1);
        assert_eq!(decoded(&out)[0].0, RST_STREAM);
        assert!(c.drive(&frame(GOAWAY, 0, 0, &[0; 8]), &mut out).is_none());
    }
}

#[test]
fn continued_headers_trailers_and_idle_ticks_do_not_capture_extra_pins() {
    let (mut c, mut out) = peer();
    let before = out.len();
    c.pin_tick(Instant::now() + Duration::from_secs(60), &mut out);
    assert_eq!(out.len(), before);
    feed(&mut c, &mut out, &frame(HEADERS, 1, 1, b"\x82"));
    assert_eq!(c.gate.as_ref().unwrap().captured, 0);
    feed(&mut c, &mut out, &frame(CONTINUATION, 4, 1, &[0; 16384]));
    feed(&mut c, &mut out, &frame(HEADERS, 5, 1, b"\x00\x00"));
    assert_eq!(c.gate.as_ref().unwrap().captured, 1);
    assert_eq!(decoded(&out).iter().filter(|f| f.0 == HEADERS).count(), 1);
}

#[test]
fn withheld_credit_cannot_grow_fixture_pending_storage_without_bound() {
    let (mut c, mut out) = peer();
    c.send_window = 0;
    let input = requests(1027);
    assert_eq!(c.drive(&input, &mut out), Some(input.len()));
    assert!(c.is_closing());
    assert!(c.gate.is_none());
    assert!(c.pending.is_empty());
    assert!(c.pending.capacity() <= 1024);
}
