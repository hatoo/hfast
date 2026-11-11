//! Outgoing CRYPTO bytes, packet room and recovery ownership contracts. The
//! scalar encoder below does not use the production frame or varint encoders.
use super::*;

fn enqueue(space: &mut SpaceState, bytes: &[u8]) {
    space.crypto_out.extend_from_slice(bytes);
}

fn queued(space: &SpaceState) -> &[u8] {
    &space.crypto_out
}

// Deliberately independent of the production varint and frame encoders.
fn width(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 4,
        _ => 8,
    }
}

fn scalar_varint(out: &mut Vec<u8>, value: u64) {
    let n = width(value);
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - n..]);
    out[start] |= match n {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => unreachable!(),
    };
}

fn scalar_frame(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) {
    out.push(6);
    scalar_varint(out, offset);
    scalar_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn emit(space: &mut SpaceState, room: usize, prefix: usize, pn: u64) -> usize {
    let before = queued(space).to_vec();
    let offset = space.crypto_offset;
    let count = before
        .len()
        .min(room.saturating_sub(prefix + 1 + width(offset) + width(room as u64)));
    let mut expected = vec![0xa5; prefix];
    if count != 0 {
        scalar_frame(&mut expected, offset, &before[..count]);
    }
    let mut actual = vec![0xa5; prefix];
    let flights = space.crypto_flight.len();
    space.write_crypto(&mut actual, room, pn);
    assert_eq!(actual, expected, "room={room}, prefix={prefix}, pn={pn}");
    assert_eq!(queued(space), &before[count..]);
    assert_eq!(space.crypto_offset, offset + count as u64);
    assert_eq!(space.crypto_flight.len(), flights + usize::from(count != 0));
    if count != 0 {
        assert!(actual.len() <= room);
        let flight = space.crypto_flight.last().unwrap();
        assert_eq!(flight.offset, offset);
        assert_eq!(flight.data, before[..count]);
        assert_eq!(flight.sent_in, [pn]);
        assert!(!flight.pending);
    }
    count
}

#[test]
fn crypto_output_matches_scalar_wire_at_room_and_offset_boundaries() {
    for length in [0, 1, 63, 64, 1150, 2000, 65536] {
        let bytes: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        for offset in [0, 63, 64, 16383, 16384, 1 << 30] {
            for room in [0, 1, 3, 4, 5, 63, 64, 1200, 2048] {
                for prefix in [0, 5] {
                    let mut space = SpaceState {
                        crypto_offset: offset,
                        ..Default::default()
                    };
                    enqueue(&mut space, &bytes);
                    let mut sent = emit(&mut space, room, prefix, 0);
                    let mut pn = 1;
                    while !space.crypto_out.is_empty() {
                        sent += emit(&mut space, 1200, 0, pn);
                        pn += 1;
                    }
                    assert_eq!(sent, length);
                    assert_eq!(space.crypto_offset, offset + length as u64);
                    assert_eq!(
                        space
                            .crypto_flight
                            .iter()
                            .flat_map(|f| &f.data)
                            .copied()
                            .collect::<Vec<_>>(),
                        bytes
                    );
                }
            }
        }
    }
}

#[test]
fn crypto_output_partial_appends_reuse_capacity_and_preserve_owned_flights() {
    let mut space = SpaceState {
        crypto_out: Vec::with_capacity(2048),
        ..Default::default()
    };
    let mut reference = Vec::with_capacity(2048);
    let mut expected = Vec::new();
    let mut pn = 0;
    for round in 0..12 {
        for (append, room) in [(1500, 300), (100, 500), (700, 1200), (0, 0), (2400, 2048)] {
            let bytes: Vec<_> = (0..append).map(|i| ((i + round) % 251) as u8).collect();
            enqueue(&mut space, &bytes);
            reference.extend_from_slice(&bytes);
            expected.extend_from_slice(&bytes);
            assert_eq!(queued(&space), reference);
            assert_eq!(space.crypto_out.capacity(), reference.capacity());
            let count = emit(&mut space, room, 0, pn);
            reference.drain(..count);
            pn += 1;
        }
    }
    while !space.crypto_out.is_empty() {
        emit(&mut space, 1200, 0, pn);
        pn += 1;
    }
    assert_eq!(space.crypto_offset as usize, expected.len());
    assert_eq!(
        space
            .crypto_flight
            .iter()
            .flat_map(|f| &f.data)
            .copied()
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn crypto_output_drained_storage_reuses_capacity_without_replaying_bytes() {
    let mut space = SpaceState::default();
    let mut offset = 0;
    for length in [65536, 1, 2000, 0, 65536] {
        let bytes: Vec<_> = (0..length).map(|i| ((i + offset) % 251) as u8).collect();
        enqueue(&mut space, &bytes);
        let capacity = space.crypto_out.capacity();
        assert_eq!(queued(&space), bytes);
        let mut pn = 0;
        while !space.crypto_out.is_empty() {
            emit(&mut space, 1200, 0, pn);
            pn += 1;
        }
        offset += length;
        assert_eq!(space.crypto_offset, offset as u64);
        assert_eq!(space.crypto_out.capacity(), capacity);
        assert!(queued(&space).is_empty());
        emit(&mut space, 1200, 0, pn);
        space.crypto_flight.clear();
    }
}

#[test]
fn crypto_output_retries_leave_new_bytes_queued_and_obey_room() {
    let mut space = SpaceState::default();
    enqueue(&mut space, &[0x31; 2000]);
    emit(&mut space, 1200, 0, 10);
    space.crypto_flight[0].pending = true;
    enqueue(&mut space, b"appended after partial send");
    let unsent = queued(&space).to_vec();
    let offset = space.crypto_offset;
    let original = space.crypto_flight[0].data.clone();
    let mut body = Vec::new();
    space.write_crypto(&mut body, 0, 11);
    assert!(body.is_empty());
    assert!(space.crypto_flight[0].pending);
    assert_eq!(space.crypto_flight[0].sent_in, [10]);
    space.write_crypto(&mut body, 70, 12);
    let first = &space.crypto_flight[0];
    let split = first.data.len();
    let mut expected = Vec::new();
    scalar_frame(&mut expected, 0, &original[..split]);
    assert_eq!(body, expected);
    assert_eq!(first.sent_in, [10, 12]);
    assert!(!first.pending);
    let tail = &space.crypto_flight[1];
    assert_eq!(tail.offset, split as u64);
    assert_eq!(tail.data, original[split..]);
    assert_eq!(tail.sent_in, [10]);
    assert!(tail.pending);
    assert_eq!(queued(&space), unsent);
    assert_eq!(space.crypto_offset, offset);
}

#[test]
fn crypto_output_partial_append_survives_sparse_and_late_acknowledgments() {
    let mut conn = connection();
    let mut bytes: Vec<_> = (0..4000).map(|i| (i % 251) as u8).collect();
    enqueue(&mut conn.spaces[0], &bytes);
    let first = send_crypto(&mut conn);
    let second = send_crypto(&mut conn);
    let sent = first[0].1.len() + second[0].1.len();
    let appended: Vec<_> = (0..3000).map(|i| (i % 239) as u8).collect();
    enqueue(&mut conn.spaces[0], &appended);
    bytes.extend_from_slice(&appended);
    acknowledge(&mut conn, Space::Initial, &[(1, 1)]);
    conn.on_timeout(conn.timeout().unwrap());
    for pn in (100..116).step_by(2) {
        conn.spaces[0].ack.record(pn, true);
    }
    let retry = send_crypto(&mut conn);
    assert_eq!(retry[0].0, 0);
    assert!(retry[0].1.len() < first[0].1.len());
    assert_eq!(retry[0].1, bytes[..retry[0].1.len()]);
    assert_eq!(queued(&conn.spaces[0]), &bytes[sent..]);
    acknowledge(&mut conn, Space::Initial, &[(0, 0)]);
    assert!(conn.spaces[0].crypto_flight.is_empty());
    let mut emitted = sent;
    while !conn.spaces[0].crypto_out.is_empty() {
        let pn = conn.spaces[0].next_pn;
        let frame = send_crypto(&mut conn);
        assert_eq!(frame[0].0, emitted as u64);
        let end = emitted + frame[0].1.len();
        assert_eq!(frame[0].1, bytes[emitted..end]);
        emitted = end;
        acknowledge(&mut conn, Space::Initial, &[(pn, pn)]);
    }
    assert_eq!(emitted, bytes.len());
    assert!(conn.spaces[0].crypto_flight.is_empty());
    assert!(!conn.wants_send());
    assert!(conn.timeout().is_none());
}

#[test]
fn crypto_output_discard_resets_partial_storage_and_pending_gate() {
    let mut conn = connection();
    enqueue(&mut conn.spaces[0], &[0x42; 4000]);
    send_crypto(&mut conn);
    assert!(!queued(&conn.spaces[0]).is_empty());
    conn.on_timeout(conn.timeout().unwrap());
    conn.discard(Space::Initial);
    assert!(queued(&conn.spaces[0]).is_empty());
    assert!(!conn.wants_send());
    assert!(conn.timeout().is_none());
    assert!(conn.spaces[0].crypto_flight.is_empty());
    // Exercise buffer reuse directly: real discarded spaces no longer have keys.
    let offset = conn.spaces[0].crypto_offset;
    enqueue(&mut conn.spaces[0], b"new");
    assert!(conn.wants_send());
    assert_eq!(emit(&mut conn.spaces[0], 1200, 0, 100), 3);
    assert_eq!(conn.spaces[0].crypto_offset, offset + 3);
    assert!(!conn.wants_send());
}
