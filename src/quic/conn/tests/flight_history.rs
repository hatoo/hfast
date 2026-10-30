use super::*;

#[test]
fn every_original_or_retried_control_packet_can_complete_delivery() {
    for copies in [1, 2, 3, 8, 9, 65] {
        for acknowledged in 0..copies {
            let mut flight = ControlFlight::new();
            for copy in 0..copies {
                flight.sent(10 + 3 * copy);
                flight.on_timeout();
                assert!(flight.pending);
            }
            let pn = 10 + 3 * acknowledged;
            // A high unrelated range plus a sparse singleton for this copy.
            let largest = 1000;
            let mut rest = Vec::new();
            put_varint(&mut rest, largest - pn - 2);
            put_varint(&mut rest, 0);
            assert!(flight.on_ack(largest, 0, &rest));
            assert!(!flight.pending);
            assert!(flight.sent_in.is_empty());
            flight.on_timeout();
            assert!(!flight.pending);
            assert!(!flight.on_ack(largest, 0, &rest));
        }
    }
}

#[test]
fn cleared_credit_history_cannot_acknowledge_a_new_generation() {
    for copies in [1, 2, 8, 65] {
        let mut credit = Credit::new(0);
        let mut out = Vec::new();
        credit.write(&mut out, 4096, 10, frame::MAX_DATA, 100);
        for copy in 1..copies {
            credit.flight.on_timeout();
            credit.write(&mut out, 4096, 10 + copy, frame::MAX_DATA, 100);
        }
        credit.write(&mut out, 4096, 1000, frame::MAX_DATA, 200);
        assert_eq!(credit.told, 200);
        assert!(!credit.flight.on_ack(10 + copies - 1, copies - 1, &[]));
        assert_eq!(credit.flight.sent_in.as_slice(), [1000]);
        assert!(!credit.flight.pending);
        assert!(credit.flight.on_ack(1000, 0, &[]));
        assert!(!credit.owed(200, 100));
    }
}

#[test]
fn crypto_split_after_many_retries_keeps_all_original_delivery_identities() {
    let data: Vec<_> = (0..2000).map(|i| (i % 251) as u8).collect();
    for acknowledged in 0..=8 {
        let mut conn = connection();
        conn.spaces[0].crypto_out.extend_from_slice(&data);
        let original_len = send_crypto(&mut conn)[0].1.len();
        for _ in 0..8 {
            conn.on_timeout(conn.timeout().unwrap());
            assert_eq!(send_crypto(&mut conn), [(0, data[..original_len].to_vec())]);
        }
        conn.on_timeout(conn.timeout().unwrap());
        for pn in (100..116).step_by(2) {
            conn.spaces[0].ack.record(pn, true);
        }
        let prefix = send_crypto(&mut conn);
        let split = prefix[0].1.len();
        assert!(split < original_len);
        assert_eq!(prefix, [(0, data[..split].to_vec())]);
        assert_eq!(conn.spaces[0].crypto_flight.len(), 2);
        // Either the original or any pre-split retry covered both split ranges.
        acknowledge(&mut conn, Space::Initial, &[(acknowledged, acknowledged)]);
        assert!(conn.spaces[0].crypto_flight.is_empty());
        assert_eq!(
            send_crypto(&mut conn),
            [(original_len as u64, data[original_len..].to_vec())]
        );
    }
}
