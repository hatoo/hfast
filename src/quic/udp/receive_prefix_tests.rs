use super::*;

fn check_inputs(messages: &[libc::mmsghdr]) {
    for message in messages {
        let msg = &message.msg_hdr;
        assert_eq!(message.msg_len, 0);
        assert_eq!(msg.msg_flags, 0);
        assert_eq!(msg.msg_namelen as usize, size_of::<libc::sockaddr_in>());
        assert_eq!(msg.msg_iovlen, 1);
        assert_eq!(msg.msg_controllen, RECEIVE_CONTROL_SIZE);
        // Model the kernel's access to all inputs, including the control bytes
        // it may leave untouched. Miri checks initialization and pointer lifetime.
        unsafe {
            let _address = msg.msg_name.cast::<libc::sockaddr_in>().read();
            let iov = &*msg.msg_iov;
            assert_eq!(iov.iov_len, RECEIVE_SIZE);
            assert_eq!(iov.iov_base.cast::<u8>().add(RECEIVE_SIZE - 1).read(), 0);
            assert_eq!(
                std::slice::from_raw_parts(msg.msg_control.cast::<u8>(), msg.msg_controllen),
                &[0; RECEIVE_CONTROL_SIZE]
            );
        }
    }
}

fn complete(message: &mut libc::mmsghdr, peer: u8, gro: bool) {
    let msg = &mut message.msg_hdr;
    unsafe {
        msg.msg_name
            .cast::<libc::sockaddr_in>()
            .write(libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: (12000 + peer as u16).to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, peer + 1]),
                },
                sin_zero: [0; 8],
            });
        let data = std::slice::from_raw_parts_mut((*msg.msg_iov).iov_base.cast::<u8>(), 7);
        data.copy_from_slice(&[peer, 1, 2, peer, 3, 4, peer]);
        if gro {
            let control = &mut *msg.msg_control.cast::<ReceiveControl>();
            control._alignment = libc::cmsghdr {
                cmsg_level: libc::IPPROTO_UDP,
                cmsg_type: libc::UDP_GRO,
                cmsg_len: libc::CMSG_LEN(4) as _,
            };
            let offset = libc::CMSG_LEN(0) as usize;
            control.bytes[offset..offset + 4].copy_from_slice(&3i32.to_ne_bytes());
        } else {
            msg.msg_controllen = 0;
        }
    }
    message.msg_len = 7;
}

#[test]
fn receive_prefix_model_partial_zero_and_full_batches() {
    let mut rx = ReceiveBatch::new();
    for limit in [2, 4, 8, 16, BATCH, 2] {
        for count in [0, 1, limit / 2, limit] {
            rx.limit = limit;
            rx.lengths.fill(123);
            rx.segment_sizes.fill(None);
            let actual = rx
                .receive_with::<BATCH>(|messages| {
                    check_inputs(messages);
                    assert_eq!(messages.len(), limit);
                    for (i, message) in messages[..count].iter_mut().enumerate() {
                        complete(message, i as u8, i % 2 == 0);
                    }
                    Ok(count)
                })
                .unwrap();
            assert_eq!(actual, count);
            assert_eq!(rx.limit, (count * 2).clamp(2, BATCH));
            assert!(rx.lengths[count..].iter().all(|&n| n == 123));
            assert!(rx.segment_sizes[count..].iter().all(Option::is_none));
            for i in 0..count {
                let (datagrams, from) = rx.datagrams(i);
                assert_eq!(
                    from,
                    format!("127.0.0.{}:{}", i + 1, 12000 + i).parse().unwrap()
                );
                let parts: Vec<Vec<u8>> = datagrams.map(|part| part.to_vec()).collect();
                assert_eq!(parts.concat(), [i as u8, 1, 2, i as u8, 3, 4, i as u8]);
                assert_eq!(parts.len(), if i % 2 == 0 { 3 } else { 1 });
            }
        }
    }
}

#[test]
fn receive_prefix_model_singleton_does_not_change_batch_limit() {
    let mut rx = ReceiveBatch::new();
    for limit in [2, 4, 8, 16, BATCH] {
        rx.limit = limit;
        for count in [0, 1] {
            assert_eq!(
                rx.receive_with::<1>(|messages| {
                    check_inputs(messages);
                    assert_eq!(messages.len(), 1);
                    if count == 1 {
                        complete(&mut messages[0], 0, true);
                    }
                    Ok(count)
                })
                .unwrap(),
                count
            );
            assert_eq!(rx.limit, limit);
        }
    }
}

#[test]
fn receive_prefix_model_errors_leave_accounting_and_reinitialize_inputs() {
    let mut rx = ReceiveBatch::new();
    for errno in [libc::EINTR, libc::EAGAIN, libc::EBADF, libc::ENOBUFS] {
        rx.limit = 2;
        rx.lengths.fill(123);
        rx.segment_sizes.fill(None);
        let mut calls = 0;
        let err = rx
            .receive_with::<BATCH>(|messages| {
                calls += 1;
                check_inputs(messages);
                complete(&mut messages[0], 0, true);
                messages[0].msg_len = u32::MAX;
                Err(io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(err.raw_os_error(), Some(errno));
        assert_eq!(rx.limit, 2);
        assert_eq!(rx.lengths, [123; BATCH]);
        assert_eq!(rx.segment_sizes, [None; BATCH]);
        rx.receive_with::<BATCH>(|messages| {
            check_inputs(messages);
            complete(&mut messages[0], 1, false);
            Ok(1)
        })
        .unwrap();
        assert_eq!(rx.datagrams(0).0.count(), 1);
    }
}

#[test]
fn receive_prefix_model_rejects_truncated_output_and_clears_controls_on_reuse() {
    let mut rx = ReceiveBatch::new();
    rx.limit = 2;
    for flags in [libc::MSG_TRUNC, libc::MSG_CTRUNC] {
        rx.receive_with::<BATCH>(|messages| {
            check_inputs(messages);
            complete(&mut messages[0], 0, true);
            messages[0].msg_hdr.msg_flags = flags;
            Ok(1)
        })
        .unwrap();
        assert_eq!(rx.datagrams(0).0.count(), 0);
        rx.receive_with::<BATCH>(|messages| {
            check_inputs(messages);
            complete(&mut messages[0], 1, false);
            messages[0].msg_len = 0;
            Ok(1)
        })
        .unwrap();
        assert_eq!(rx.datagrams(0).0.map(|d| d.len()).collect::<Vec<_>>(), [0]);
    }
}

#[test]
#[should_panic(expected = "out of range")]
fn receive_prefix_model_rejects_output_beyond_initialized_prefix() {
    let mut rx = ReceiveBatch::new();
    rx.limit = 2;
    let _ = rx.receive_with::<BATCH>(|messages| {
        check_inputs(messages);
        Ok(messages.len() + 1)
    });
}

#[test]
fn receive_prefix_kernel_grows_shrinks_and_switches_singleton_with_multiple_peers() {
    use std::time::Duration;
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let to = receiver.local_addr().unwrap();
    let senders = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    let mut rx = ReceiveBatch::new();
    // Start at 32, shrink to 2, grow through every power of two, then shrink.
    for (single, count) in [
        (false, 1),
        (true, 1),
        (false, 2),
        (false, 4),
        (false, 8),
        (false, 16),
        (false, 32),
        (true, 1),
        (false, 1),
    ] {
        let old_limit = rx.limit;
        for i in 0..count {
            senders[i % 2].send_to(&[i as u8], to).unwrap();
        }
        assert_eq!(rx.receive(&receiver, single).unwrap(), count);
        for i in 0..count {
            let (datagrams, from) = rx.datagrams(i);
            assert_eq!(from, senders[i % 2].local_addr().unwrap());
            assert_eq!(datagrams.collect::<Vec<_>>(), [vec![i as u8]]);
        }
        assert_eq!(
            rx.limit,
            if single {
                old_limit
            } else {
                (count * 2).clamp(2, BATCH)
            }
        );
    }
    for single in [false, true] {
        let limit = rx.limit;
        assert_eq!(
            rx.receive(&receiver, single).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(rx.limit, limit);
    }
}
