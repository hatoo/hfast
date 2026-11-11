use super::*;
use std::collections::BTreeMap;

// Deliberately independent of put_stream/stream_overhead: packet admission
// must include the type, stream ID, explicit zero offset, length, and body.
fn complete_wire(id: u64) -> Vec<u8> {
    let (width, tag) = match id {
        0..64 => (1, 0),
        64..16384 => (2, 0x40),
        16384..1073741824 => (4, 0x80),
        _ => (8, 0xc0),
    };
    let mut bytes = vec![0x0f];
    bytes.extend_from_slice(&id.to_be_bytes()[8 - width..]);
    bytes[1] |= tag;
    assert!(RESPONSE.len() < 64);
    bytes.extend_from_slice(&[0, RESPONSE.len() as u8]);
    bytes.extend_from_slice(RESPONSE);
    bytes
}

fn settled() -> Connection {
    let mut conn = data_connection();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert!(!conn.wants_send());
    conn
}

#[test]
fn complete_response_packet_boundary_preserves_queued_state_and_credit() {
    // Cover each stream-ID width without allocating all preceding slots.
    for id in [
        0,
        60,
        64,
        16380,
        16384,
        (1 << 30) - 4,
        1 << 30,
        (1 << 62) - 4,
    ] {
        let mut conn = settled();
        conn.base_stream = id >> 2;
        conn.finished = conn.base_stream;
        conn.streams_credit.told = conn.streams_limit();
        conn.on_stream(id, 0, b"request", true).unwrap();
        let sent = conn.send_credit.sent;
        let mut expected = vec![frame::PING as u8];
        expected.extend_from_slice(&complete_wire(id));
        let mut body = vec![frame::PING as u8];

        for room in [1, expected.len() - 1, expected.len() - 1] {
            conn.write_data(&mut body, room, 100);
            assert_eq!(body, [frame::PING as u8]);
            assert_eq!(conn.ready, [id]);
            assert_eq!(conn.send_credit.sent, sent, "packet admission credit");
            assert!(conn.unacked.is_empty());
            let req = conn.stream_mut(id).unwrap();
            assert!(req.queued);
            assert_eq!(req.sent, 0);
            assert!(!req.partial);
        }
        conn.write_data(&mut body, expected.len(), 101);
        assert_eq!(body, expected);
        assert!(conn.ready.is_empty());
        assert_eq!(conn.unacked, [(101, id)]);
        assert_eq!(conn.send_credit.sent, sent + RESPONSE.len() as u64);
        let req = conn.stream_mut(id).unwrap();
        assert_eq!(req.sent, RESPONSE.len() as u8);
        assert!(!req.queued);
        assert!(!req.send_done, "only an ACK completes delivery");
    }
}

#[test]
fn wrapped_sparse_queue_matches_newest_first_packet_model() {
    let mut conn = settled();
    conn.streams = VecDeque::with_capacity(8);
    conn.max_streams_bidi = 256;
    conn.streams_credit.told = 256;
    for n in 0..8 {
        conn.on_stream(n * 4, 0, b"x", n < 5).unwrap();
    }
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!((conn.base_stream, conn.finished), (5, 5));
    // Leave stream 9 unseen, with active slots on both sides of the wrap.
    for n in [8, 10, 11, 12] {
        conn.on_stream(n * 4, 0, b"x", false).unwrap();
    }
    assert_eq!(conn.streams.capacity(), 8);
    assert!(!conn.streams.as_slices().1.is_empty());
    let queued = [5, 12, 7, 10];
    for n in queued {
        conn.on_stream(n * 4, 1, b"", true).unwrap();
    }
    let sent = conn.send_credit.sent;
    let mut model: Vec<_> = queued.into_iter().map(|n| n * 4).collect();
    let mut flights = VecDeque::new();
    for packet in 0..4 {
        let id = model.pop().unwrap();
        let mut expected = vec![frame::PING as u8];
        expected.extend_from_slice(&complete_wire(id));
        let mut body = vec![frame::PING as u8];
        conn.write_data(&mut body, expected.len(), 100 + packet);
        assert_eq!(body, expected, "newest-first packet order");
        assert_eq!(conn.ready, model);
        flights.push_back((100 + packet, id));
        assert_eq!(conn.unacked, flights);
        assert_eq!(
            conn.send_credit.sent,
            sent + (packet + 1) * RESPONSE.len() as u64
        );
        for n in queued {
            let req = conn.stream_mut(n * 4).unwrap();
            let pending = model.contains(&(n * 4));
            assert_eq!(req.queued, pending);
            assert_eq!(req.sent, if pending { 0 } else { RESPONSE.len() as u8 });
        }
        assert!(matches!(conn.streams[4], StreamSlot::Unseen));
    }
    acknowledge(&mut conn, Space::Data, &[(100, 103)]);
    assert_eq!((conn.base_stream, conn.finished), (6, 9));
    assert!(conn.unacked.is_empty());
    assert!(conn.ready.is_empty());
}

#[test]
fn stale_completed_and_stopped_ready_entries_do_not_charge_credit() {
    let mut conn = settled();
    conn.on_stream(0, 0, b"x", true).unwrap();
    let (pn, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(pn, pn)]);
    assert_eq!(conn.base_stream, 1);
    for id in [4, 8, 12, 16] {
        conn.on_stream(id, 0, b"x", id != 12).unwrap();
    }
    conn.stop_sending(8, 0x10c);
    // A delivered send direction with an open receive direction stays Active.
    let req = conn.stream_mut(12).unwrap();
    req.send_done = true;
    req.queued = true;
    *conn.stream_slot_mut(16).unwrap() = StreamSlot::Complete;
    conn.ready = vec![4, 0, 8, 12, 16, 2, 256];
    let sent = conn.send_credit.sent;
    let mut body = Vec::new();
    conn.write_data(&mut body, 1200, 100);
    let frames: Vec<_> = frame::Frames::new(&body).map(Result::unwrap).collect();
    assert_eq!(
        frames,
        [
            frame::Frame::ResetStream {
                id: 8,
                error_code: 0x10c,
                final_size: 0
            },
            frame::Frame::Stream {
                id: 4,
                offset: 0,
                data: RESPONSE,
                fin: true
            },
        ],
        "stale/stopped entries must not emit response bytes"
    );
    assert_eq!(conn.send_credit.sent, sent + RESPONSE.len() as u64);
    assert_eq!(conn.unacked, [(100, 4)]);
    assert!(conn.ready.is_empty());
    assert!(!conn.stream_mut(8).unwrap().queued);
    assert!(!conn.stream_mut(12).unwrap().queued);
    assert!(matches!(conn.streams[3], StreamSlot::Complete));
    assert_eq!(conn.base_stream, 1);
}

#[test]
fn mixed_complete_and_partial_responses_keep_exact_credit_after_late_ack() {
    let mut conn = settled();
    let before = conn.send_credit.sent;
    conn.peer.initial_max_data = before + RESPONSE.len() as u64 + 4;
    conn.send_credit.initialize(&conn.peer);
    for id in [0, 8, 12] {
        conn.on_stream(id, 0, b"request", true).unwrap();
    }
    let (original, plain) = send_data(&mut conn);
    let answers: Vec<_> = frame::Frames::new(&plain)
        .map(Result::unwrap)
        .filter(|f| matches!(f, frame::Frame::Stream { id, .. } if id & 3 == 0))
        .collect();
    assert_eq!(
        answers,
        [
            frame::Frame::Stream {
                id: 12,
                offset: 0,
                data: RESPONSE,
                fin: true
            },
            frame::Frame::Stream {
                id: 8,
                offset: 0,
                data: &RESPONSE[..4],
                fin: false
            },
        ]
    );
    assert_eq!(conn.send_credit.available(), 0);
    assert_eq!(conn.send_credit.sent, before + RESPONSE.len() as u64 + 4);
    assert_eq!(conn.unacked, [(original, 12)]);
    assert_eq!(
        conn.send_credit.blocked.iter().copied().collect::<Vec<_>>(),
        [0, 8]
    );
    conn.on_timeout(conn.timeout().unwrap());
    let (retry, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(original, original)]);
    assert_eq!(conn.finished, 1);
    conn.on_frame(
        &frame::Frame::MaxData(before + 3 * RESPONSE.len() as u64),
        Space::Data,
    )
    .unwrap();
    let (tail, _) = send_data(&mut conn);
    acknowledge(&mut conn, Space::Data, &[(tail, tail)]);
    let charged = conn.send_credit.sent;
    acknowledge(&mut conn, Space::Data, &[(retry, retry)]);
    assert_eq!(conn.finished, 3);
    assert_eq!(charged, before + 3 * RESPONSE.len() as u64);
    assert_eq!(conn.send_credit.sent, charged);
    assert!(conn.ready.is_empty());
    assert!(conn.unacked.is_empty());
    assert!(conn.send_credit.responses.is_empty());
    assert!(!conn.wants_send());
    assert!(conn.timeout().is_none());
}

fn receive(conn: &mut Connection, body: &[u8]) {
    let pn = conn.spaces[Space::Data as usize]
        .ack
        .ranges
        .first()
        .map_or(0, |r| r.1 + 1);
    conn.recv(&mut peer_data_packet(conn, pn as u32, body))
        .unwrap();
}

fn wire_ack(conn: &mut Connection, packets: &[u64]) {
    let mut packets = packets.to_vec();
    packets.sort_unstable();
    packets.dedup();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for pn in packets {
        if let Some(last) = ranges.last_mut()
            && pn == last.1 + 1
        {
            last.1 = pn;
        } else {
            ranges.push((pn, pn));
        }
    }
    ranges.reverse();
    let mut body = Vec::new();
    frame::put_ack(&mut body, &ranges, 0);
    receive(conn, &body);
}

type Part = (u64, u64, &'static [u8], bool);

#[derive(Default)]
struct Delivery {
    sent: [bool; RESPONSE.len()],
    acked: [bool; RESPONSE.len()],
    fin_acked: bool,
}

// A byte bitmap and an immutable packet ledger model unique bytes and delivery
// independently of the production queue, fragment ranges and compact flights.
struct Ledger {
    initial_credit: u64,
    initial_finished: u64,
    streams: BTreeMap<u64, Delivery>,
    packets: BTreeMap<u64, Vec<Part>>,
}

impl Ledger {
    fn new(conn: &Connection, ids: &[u64]) -> Self {
        Self {
            initial_credit: conn.send_credit.sent,
            initial_finished: conn.finished,
            streams: ids.iter().map(|&id| (id, Delivery::default())).collect(),
            packets: BTreeMap::new(),
        }
    }

    fn check(&self, conn: &Connection) {
        let bytes: usize = self
            .streams
            .values()
            .map(|s| s.sent.iter().filter(|&&b| b).count())
            .sum();
        assert_eq!(
            conn.send_credit.sent,
            self.initial_credit + bytes as u64,
            "unique response credit ledger"
        );
        let delivered = self
            .streams
            .values()
            .filter(|s| s.fin_acked && s.acked.iter().all(|&b| b))
            .count();
        assert_eq!(
            conn.finished,
            self.initial_finished + delivered as u64,
            "acknowledged delivery ledger"
        );
    }

    fn send(&mut self, conn: &mut Connection, expected: &[Part]) -> u64 {
        let (pn, plain) = send_data(conn);
        let actual: Vec<_> = frame::Frames::new(&plain)
            .map(Result::unwrap)
            .filter_map(|f| match f {
                frame::Frame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                } => Some((id, offset, data, fin)),
                _ => None,
            })
            .collect();
        assert_eq!(actual, expected, "response bytes/offset/FIN/order ledger");
        for &(id, offset, data, _) in expected {
            let start = offset as usize;
            assert_eq!(data, &RESPONSE[start..start + data.len()]);
            self.streams.get_mut(&id).unwrap().sent[start..start + data.len()].fill(true);
        }
        assert!(self.packets.insert(pn, expected.to_vec()).is_none());
        self.check(conn);
        pn
    }

    fn ack(&mut self, conn: &mut Connection, packets: &[u64]) {
        for pn in packets {
            for &(id, offset, data, fin) in &self.packets[pn] {
                let stream = self.streams.get_mut(&id).unwrap();
                let start = offset as usize;
                stream.acked[start..start + data.len()].fill(true);
                stream.fin_acked |= fin;
            }
        }
        wire_ack(conn, packets);
        self.check(conn);
    }
}

#[test]
fn encrypted_mixed_queue_matches_byte_ledger_through_sparse_ack_and_pto() {
    // Cross ID widths with a missing slot, three partial sizes and both a
    // transmitted retry and a retry cancelled by the original packet's ACK.
    for base in [0, 60, 16380, (1 << 30) - 4] {
        for prefix in [1, 4, RESPONSE.len() - 1] {
            for ack_original in [false, true] {
                let mut conn = settled();
                conn.base_stream = base >> 2;
                conn.finished = conn.base_stream;
                conn.streams_credit.told = conn.streams_limit();
                let ids = [base, base + 8, base + 12];
                let mut ledger = Ledger::new(&conn, &ids);
                let before = conn.send_credit.sent;
                conn.peer.initial_max_data = before + (RESPONSE.len() + prefix) as u64;
                conn.send_credit.initialize(&conn.peer);
                let mut requests = Vec::new();
                for id in ids {
                    frame::put_stream(&mut requests, id, 0, true, b"request");
                }
                receive(&mut conn, &requests);
                let parts = [
                    (ids[2], 0, RESPONSE, true),
                    (ids[1], 0, &RESPONSE[..prefix], false),
                ];
                let original = ledger.send(&mut conn, &parts);
                assert_eq!(conn.send_credit.available(), 0);
                assert_eq!(
                    conn.send_credit.blocked.iter().copied().collect::<Vec<_>>(),
                    [ids[0], ids[1]]
                );

                conn.on_timeout(conn.timeout().unwrap());
                ledger.check(&conn);
                let retry = ledger.send(&mut conn, &parts);
                conn.on_timeout(conn.timeout().unwrap());
                ledger.ack(&mut conn, &[if ack_original { original } else { retry }]);
                assert!(conn.ready.is_empty(), "late ACK cancels queued copies");
                assert!(
                    !conn.stream_mut(ids[1]).unwrap().send_done,
                    "ACKed prefix is not a delivered response"
                );

                let mut grant = Vec::new();
                put_varint(&mut grant, frame::MAX_DATA);
                put_varint(&mut grant, before + 2 * RESPONSE.len() as u64);
                receive(&mut conn, &grant);
                let tail = ledger.send(
                    &mut conn,
                    &[(ids[1], prefix as u64, &RESPONSE[prefix..], true)],
                );
                grant.clear();
                put_varint(&mut grant, frame::MAX_DATA);
                put_varint(&mut grant, before + 3 * RESPONSE.len() as u64);
                receive(&mut conn, &grant);
                let sibling = ledger.send(&mut conn, &[(ids[0], 0, RESPONSE, true)]);
                // A sparse ACK acknowledges the first packet and the final
                // sibling, but excludes the distinct tail bytes in between.
                assert!(original < tail && tail < sibling);
                ledger.ack(&mut conn, &[original, sibling]);
                assert_eq!(conn.finished, ledger.initial_finished + 2);
                assert!(
                    conn.timeout().is_some(),
                    "unacknowledged tail needs recovery"
                );
                let deadline = conn.timeout();
                ledger.ack(&mut conn, &[original, sibling]);
                ledger.ack(&mut conn, &[retry]);
                assert_eq!(
                    conn.timeout(),
                    deadline,
                    "duplicate ACK must not rearm recovery"
                );
                conn.on_timeout(conn.timeout().unwrap());
                ledger.check(&conn);
                ledger.ack(&mut conn, &[tail]);
                ledger.ack(&mut conn, &[tail]);
                assert!(
                    conn.ready.is_empty(),
                    "late tail ACK cancels its queued retry"
                );
                assert_eq!(conn.base_stream, (base >> 2) + 1, "unseen slot stays open");
                assert!(matches!(conn.streams.front(), Some(StreamSlot::Unseen)));
                assert_eq!(conn.finished, ledger.initial_finished + 3);
                assert!(conn.ready.is_empty());
                assert!(conn.unacked.is_empty());
                assert!(conn.send_credit.responses.is_empty());
                assert!(conn.send_credit.blocked.is_empty());
                assert!(conn.timeout().is_none());
                // Receiving an encrypted request/credit frame may leave an
                // ACK-only packet owed. It must not contain another response.
                if conn.wants_send() {
                    ledger.send(&mut conn, &[]);
                }
                assert!(!conn.poll_transmit(&mut Vec::new()).unwrap());
            }
        }
    }
}

#[test]
fn encrypted_stop_after_partial_send_keeps_reset_separate_from_sibling_response() {
    let mut conn = settled();
    let before = conn.send_credit.sent;
    conn.peer.initial_max_data = before + 4;
    conn.send_credit.initialize(&conn.peer);
    let mut requests = Vec::new();
    for id in [0, 8] {
        frame::put_stream(&mut requests, id, 0, true, b"request");
    }
    receive(&mut conn, &requests);
    let mut ledger = Ledger::new(&conn, &[0, 8]);
    let original = ledger.send(&mut conn, &[(8, 0, &RESPONSE[..4], false)]);
    conn.on_timeout(conn.timeout().unwrap());

    let mut stop = Vec::new();
    for n in [0x05, 8, 0x10c] {
        // STOP_SENDING
        put_varint(&mut stop, n);
    }
    receive(&mut conn, &stop);
    receive(&mut conn, &stop); // duplicate in a new packet
    wire_ack(&mut conn, &[original]);
    assert_eq!(
        conn.finished, 0,
        "response ACK does not deliver RESET_STREAM"
    );
    let mut grant = Vec::new();
    put_varint(&mut grant, frame::MAX_DATA);
    put_varint(&mut grant, before + 4 + RESPONSE.len() as u64);
    receive(&mut conn, &grant);
    let (reset, plain) = send_data(&mut conn);
    let relevant: Vec<_> = frame::Frames::new(&plain)
        .map(Result::unwrap)
        .filter(|f| {
            matches!(
                f,
                frame::Frame::Stream { .. } | frame::Frame::ResetStream { .. }
            )
        })
        .collect();
    assert_eq!(
        relevant,
        [
            frame::Frame::ResetStream {
                id: 8,
                error_code: 0x10c,
                final_size: 4
            },
            frame::Frame::Stream {
                id: 0,
                offset: 0,
                data: RESPONSE,
                fin: true
            },
        ],
        "stopped response stays cancelled while sibling progresses"
    );
    assert_eq!(conn.send_credit.sent, before + 4 + RESPONSE.len() as u64);
    wire_ack(&mut conn, &[original]);
    assert_eq!(
        conn.finished, 0,
        "old partial ACK cannot retire reset or sibling"
    );
    wire_ack(&mut conn, &[reset]);
    wire_ack(&mut conn, &[reset, original]);
    assert_eq!(conn.finished, 2);
    assert_eq!(conn.base_stream, 1);
    assert!(conn.resets.is_empty());
    assert!(conn.ready.is_empty());
    assert!(conn.unacked.is_empty());
    assert!(conn.send_credit.responses.is_empty());
    assert!(conn.send_credit.blocked.is_empty());
    assert!(conn.timeout().is_none());
    assert!(!conn.wants_send());
}
