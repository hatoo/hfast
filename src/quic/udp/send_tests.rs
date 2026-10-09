//! Exercise the initialized descriptor prefix and every referenced allocation.
use super::tests::{batch, decode};
use super::*;

fn check_fields(messages: &[libc::mmsghdr]) {
    for message in messages {
        let msg = &message.msg_hdr;
        assert_eq!(message.msg_len, 0);
        assert_eq!(msg.msg_flags, 0);
        if msg.msg_controllen == 0 {
            assert!(msg.msg_control.is_null());
        } else {
            // The kernel may read the padded control area, not only its u16.
            let bytes = unsafe {
                std::slice::from_raw_parts(msg.msg_control.cast::<u8>(), msg.msg_controllen)
            };
            let used = unsafe { libc::CMSG_LEN(2) as usize };
            assert!(bytes[used..].iter().all(|&byte| byte == 0));
        }
    }
}

#[test]
fn active_prefix_survives_moves_reallocation_and_shrinking_batches() {
    let mut tx = batch(&[(1, 1); SEND_BATCH]);
    // Small initial capacities keep this pointer-lifetime test cheap under
    // Miri while still forcing every active buffer to grow on every round.
    for buffer in &mut tx.buffers {
        buffer.shrink_to_fit();
    }
    for (round, count) in [8, 2, 7, 1, 0, 3, 8, 2].into_iter().enumerate() {
        tx = *std::hint::black_box(Box::new(tx));
        let mut expected = Vec::new();
        for i in 0..count {
            // Force growth beyond the current capacity on every used slot.
            let size = tx.buffers[i].capacity() + 1;
            tx.buffers[i].resize(size, 0);
            tx.buffers[i].fill((round * SEND_BATCH + i) as u8);
            tx.addresses[i].sin_port = (1 + i as u16 / 2).to_be();
            expected.push((1 + i as u16 / 2, tx.buffers[i].clone()));
        }
        tx.len = count;
        let mut calls = 0;
        tx.flush_with(|messages| {
            calls += 1;
            check_fields(messages);
            assert_eq!(decode(messages), expected);
            // Simulate sendmmsg's output writes before the storage is reused.
            for message in messages.iter_mut() {
                message.msg_len = 1234;
            }
            Ok(messages.len())
        })
        .unwrap();
        assert_eq!(calls, usize::from(count != 0));
        assert_eq!(tx.len, 0);
    }
}

#[test]
fn every_active_prefix_and_peer_partition_decodes_exactly() {
    // Cover every partition of each possible active prefix, with empty and
    // shorter datagrams interspersed. Check wire semantics independently of
    // the number of groups selected by the implementation.
    for count in 1..=SEND_BATCH {
        for partition in 0..1usize << (count - 1) {
            let mut port = 1;
            let spec: Vec<_> = (0..count)
                .map(|i| {
                    if i > 0 && partition & (1 << (i - 1)) != 0 {
                        port += 1;
                    }
                    let len = match (partition + i) % 5 {
                        0 => 0,
                        1 => 3,
                        _ => 4,
                    };
                    (len, port)
                })
                .collect();
            let expected: Vec<_> = spec
                .iter()
                .enumerate()
                .map(|(i, &(len, port))| (port, vec![i as u8; len]))
                .collect();
            let mut tx = batch(&spec);
            for segmentation in [true, false] {
                tx.segmentation = segmentation;
                tx.len = count;
                tx.flush_with(|messages| {
                    check_fields(messages);
                    assert_eq!(decode(messages), expected);
                    Ok(messages.len())
                })
                .unwrap();
            }
        }
    }
}

#[test]
fn fallback_reinitializes_output_fields_and_controls_without_replay() {
    // First group was accepted; the second GSO group fails. Fallback expands
    // the suffix into the same message slots, including the accepted slot.
    let spec = [(4, 1), (4, 1), (4, 2), (3, 2), (0, 3), (2, 4)];
    let mut tx = batch(&spec);
    let mut delivered = Vec::new();
    let mut calls = 0;
    tx.flush_with(|messages| {
        calls += 1;
        match calls {
            1 => {
                check_fields(messages);
                delivered.extend(decode(&messages[..1]));
                messages[0].msg_len = 8;
                Ok(1)
            }
            2 => Err(io::ErrorKind::Interrupted.into()),
            3 => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
            4..=7 => {
                check_fields(messages);
                assert!(messages.iter().all(|m| m.msg_hdr.msg_control.is_null()));
                delivered.extend(decode(&messages[..1]));
                messages[0].msg_len = 999;
                Ok(1)
            }
            _ => panic!("unexpected send"),
        }
    })
    .unwrap();
    assert_eq!(calls, 7);
    assert!(!tx.segmentation);
    assert_eq!(
        delivered,
        spec.iter()
            .enumerate()
            .map(|(i, &(len, port))| (port, vec![i as u8; len]))
            .collect::<Vec<_>>()
    );
}

#[test]
fn errors_after_partial_send_leave_next_prefix_clean() {
    for errno in [None, Some(libc::ENOBUFS), Some(libc::EAGAIN)] {
        let mut tx = batch(&[(3, 1), (3, 2), (3, 2)]);
        let mut calls = 0;
        let error = tx
            .flush_with(|messages| {
                calls += 1;
                check_fields(messages);
                if calls == 1 {
                    assert_eq!(decode(&messages[..1]), vec![(1, vec![0; 3])]);
                    messages[0].msg_len = 3;
                    Ok(1)
                } else if let Some(errno) = errno {
                    Err(io::Error::from_raw_os_error(errno))
                } else {
                    Ok(0)
                }
            })
            .unwrap_err();
        assert_eq!(calls, 2);
        assert_eq!(tx.len, 0);
        if let Some(errno) = errno {
            assert_eq!(error.raw_os_error(), Some(errno));
        } else {
            assert_eq!(error.kind(), io::ErrorKind::WriteZero);
        }
        tx.flush_with(|_| panic!("failed suffix must not be replayed"))
            .unwrap();
        tx.len = 2;
        tx.buffers[0] = vec![9; MAX_DATAGRAM * 2];
        tx.buffers[1] = vec![8; MAX_DATAGRAM * 2];
        tx.flush_with(|messages| {
            check_fields(messages);
            assert_eq!(
                decode(messages),
                vec![
                    (1, vec![9; MAX_DATAGRAM * 2]),
                    (2, vec![8; MAX_DATAGRAM * 2])
                ]
            );
            Ok(messages.len())
        })
        .unwrap();
    }
}
