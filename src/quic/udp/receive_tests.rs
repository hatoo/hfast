use super::*;

// Model the kernel's value-result fields and writes through the actual stored
// pointers. These tests also run under Miri without invoking socket syscalls.
fn fill(messages: &mut [libc::mmsghdr], count: usize, round: u8) {
    assert!(count <= messages.len());
    for (i, message) in messages.iter_mut().enumerate() {
        let msg = &mut message.msg_hdr;
        assert_eq!(
            msg.msg_namelen as usize,
            std::mem::size_of::<libc::sockaddr_in>()
        );
        assert_eq!(msg.msg_controllen, 0);
        assert_eq!(msg.msg_flags, 0);
        assert_eq!(message.msg_len, 0);
        assert!(msg.msg_control.is_null());
        assert_eq!(msg.msg_iovlen, 1);
        unsafe {
            let iov = &*msg.msg_iov;
            assert_eq!(iov.iov_len, RECEIVE_SIZE);
            if i < count {
                msg.msg_name
                    .cast::<libc::sockaddr_in>()
                    .write(libc::sockaddr_in {
                        sin_family: libc::AF_INET as _,
                        sin_port: (10000 + i as u16).to_be(),
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes([127, 0, 0, round]),
                        },
                        sin_zero: [0; 8],
                    });
                std::slice::from_raw_parts_mut(iov.iov_base.cast::<u8>(), i + 1).fill(round);
                message.msg_len = (i + 1) as _;
            }
        }
    }
}

fn check(rx: &mut ReceiveBatch, count: usize, round: u8) {
    for i in 0..count {
        let (data, from) = rx.datagram(i);
        assert_eq!(data, vec![round; i + 1]);
        assert_eq!(
            from,
            SocketAddrV4::new([127, 0, 0, round].into(), 10000 + i as u16).into()
        );
        // Real packet parsing/decryption also mutates the delivered buffer.
        data.fill(255);
    }
}

#[test]
fn storage_survives_moves_and_alternating_payload_borrows() {
    let mut rx = ReceiveBatch::new();
    let pointers = rx
        .messages
        .map(|msg| (msg.msg_hdr.msg_name, msg.msg_hdr.msg_iov));
    rx.receive_with(|messages| {
        fill(messages, BATCH, 1);
        Ok(BATCH)
    })
    .unwrap();
    check(&mut rx, BATCH, 1);
    rx.single_buffer()[..3].copy_from_slice(b"one");
    assert_eq!(&rx.datagram(0).0[..1], b"o");

    // Move between stack/heap owners and reallocate the container, including
    // a move after descriptors have already been used and payloads borrowed.
    let mut owners = Vec::with_capacity(1);
    owners.push(std::hint::black_box(rx));
    owners.reserve_exact(4);
    let mut moved = Box::new(owners.pop().unwrap());
    assert_eq!(
        moved
            .messages
            .map(|msg| (msg.msg_hdr.msg_name, msg.msg_hdr.msg_iov)),
        pointers
    );
    moved
        .receive_with(|messages| {
            fill(messages, BATCH, 2);
            Ok(BATCH)
        })
        .unwrap();
    check(&mut moved, BATCH, 2);
    let mut rx = std::hint::black_box(*moved);
    rx.single_buffer().fill(123);
    rx.receive_with(|messages| {
        fill(messages, 1, 3);
        Ok(1)
    })
    .unwrap();
    check(&mut rx, 1, 3);
    assert_eq!(
        rx.single_buffer()[1],
        123,
        "receive overwrites only the payload"
    );
}

#[test]
fn storage_resets_active_prefix_after_limit_growth_and_shrink() {
    let mut rx = ReceiveBatch::new();
    for (round, (limit, count)) in [
        (32, 1),
        (2, 2),
        (4, 4),
        (8, 8),
        (16, 16),
        (32, 32),
        (32, 3),
        (6, 1),
        (2, 0),
        (2, 2),
        (4, 4),
        (8, 8),
        (16, 16),
        (32, 32),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(rx.limit, limit);
        rx.receive_with(|messages| {
            assert_eq!(messages.len(), limit);
            fill(messages, count, round as u8);
            Ok(count)
        })
        .unwrap();
        check(&mut rx, count, round as u8);
        // Poison all value-result fields, including descriptors outside the
        // current limit, so later growth cannot rely on untouched entries.
        for message in &mut rx.messages {
            message.msg_hdr.msg_namelen = 0;
            message.msg_hdr.msg_controllen = 1;
            message.msg_hdr.msg_flags = libc::MSG_TRUNC;
            message.msg_len = u32::MAX;
        }
    }
}

#[test]
fn storage_discards_invalid_results_and_reuses_their_descriptors() {
    let mut rx = ReceiveBatch::new();
    rx.receive_with(|messages| {
        fill(messages, 7, 4);
        messages[0].msg_hdr.msg_flags = libc::MSG_TRUNC;
        messages[0].msg_len = RECEIVE_SIZE as u32 + 1;
        messages[1].msg_hdr.msg_namelen = 0;
        messages[2].msg_hdr.msg_namelen -= 1;
        messages[3].msg_hdr.msg_namelen += 1;
        unsafe {
            (*messages[4].msg_hdr.msg_name.cast::<libc::sockaddr_in>()).sin_family =
                libc::AF_INET6 as _;
            (*messages[5].msg_hdr.msg_name.cast::<libc::sockaddr_in>()).sin_family =
                libc::AF_UNSPEC as _;
        }
        messages[6].msg_len = 0; // A valid empty UDP datagram still counts.
        Ok(7)
    })
    .unwrap();
    for i in 0..7 {
        assert!(rx.datagram(i).0.is_empty());
    }
    assert_eq!(rx.limit, 14);
    rx.receive_with(|messages| {
        fill(messages, 7, 5);
        Ok(7)
    })
    .unwrap();
    check(&mut rx, 7, 5);
}

#[test]
fn storage_recovers_from_errors_after_output_fields_were_changed() {
    let mut rx = ReceiveBatch::new();
    for errno in [libc::EINTR, libc::EAGAIN, libc::ENOBUFS, libc::EBADF] {
        let old_limit = rx.limit;
        let err = rx
            .receive_with(|messages| {
                fill(messages, 1, 6);
                // A failing system call must not leave stale input capacities or
                // flags for its successor, even if it touched the attempted entry.
                messages[0].msg_hdr.msg_namelen = 0;
                messages[0].msg_hdr.msg_controllen = 99;
                messages[0].msg_hdr.msg_flags = libc::MSG_TRUNC;
                Err(io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(errno));
        assert_eq!(rx.limit, old_limit);
        rx.receive_with(|messages| {
            fill(messages, 1, 7);
            Ok(1)
        })
        .unwrap();
        check(&mut rx, 1, 7);
    }
}

#[test]
fn kernel_receive_recovers_from_truncation_and_nonblocking_errors() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = receiver.local_addr().unwrap();
    let mut rx = ReceiveBatch::new();
    assert_eq!(
        rx.receive(&receiver).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // Force real kernel payload truncation; the normal buffer fits all IPv4 UDP.
    unsafe {
        (*rx.messages[0].msg_hdr.msg_iov).iov_len = 8;
    }
    sender.send_to(&[9; 64], to).unwrap();
    assert_eq!(rx.receive(&receiver).unwrap(), 1);
    assert_ne!(rx.messages[0].msg_hdr.msg_flags & libc::MSG_TRUNC, 0);
    assert!(rx.datagram(0).0.is_empty());
    unsafe {
        (*rx.messages[0].msg_hdr.msg_iov).iov_len = RECEIVE_SIZE;
    }
    assert_eq!(
        rx.receive(&receiver).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    sender.send_to(b"whole", to).unwrap();
    assert_eq!(rx.receive(&receiver).unwrap(), 1);
    let (data, from) = rx.datagram(0);
    assert_eq!(data, b"whole");
    assert_eq!(from, sender.local_addr().unwrap());
}

#[test]
fn kernel_receive_preserves_packets_across_adaptive_limits_and_owner_moves() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_millis(20)))
        .unwrap();
    let senders = std::array::from_fn::<_, 2, _>(|_| UdpSocket::bind("127.0.0.1:0").unwrap());
    let to = receiver.local_addr().unwrap();
    let mut rx = ReceiveBatch::new();
    senders[0].send_to(b"single", to).unwrap();
    assert_eq!(receiver.recv(rx.single_buffer()).unwrap(), 6);
    senders[0].send_to(b"batch", to).unwrap();
    assert_eq!(rx.receive(&receiver).unwrap(), 1);
    assert_eq!(rx.limit, 2);
    let mut moved = Box::new(std::hint::black_box(rx));
    for i in 0..63 {
        senders[i % 2].send_to(&[i as u8; 3], to).unwrap();
    }
    let mut delivered = 0;
    for count in [2, 4, 8, 16, 32, 1] {
        assert_eq!(moved.receive(&receiver).unwrap(), count);
        for i in 0..count {
            let (data, from) = moved.datagram(i);
            assert_eq!(data, &[delivered as u8; 3]);
            assert_eq!(from, senders[delivered % 2].local_addr().unwrap());
            delivered += 1;
        }
    }
    assert_eq!(delivered, 63);
    assert_eq!(moved.limit, 2);
    senders[1].send_to(b"single again", to).unwrap();
    assert_eq!(receiver.recv(moved.single_buffer()).unwrap(), 12);
    assert_eq!(&moved.single_buffer()[..12], b"single again");
    assert!(moved.receive(&receiver).is_err(), "no replayed datagrams");
}
