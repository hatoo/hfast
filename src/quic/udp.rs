//! Reusable datagram batches for the endpoint's IPv4 socket.

use std::io;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use super::MAX_DATAGRAM;

const BATCH: usize = 32;
const SEND_BATCH: usize = 8;
const RECEIVE_SIZE: usize = 65536;

// The union provides cmsghdr alignment and space for its padded u16 payload.
const SEGMENT_CONTROL_SIZE: usize = unsafe { libc::CMSG_SPACE(2) as usize };
union SegmentControl {
    _alignment: libc::cmsghdr,
    bytes: [u8; SEGMENT_CONTROL_SIZE],
}

pub(super) struct ReceiveBatch {
    buffers: [Box<[u8]>; BATCH],
    addresses: [libc::sockaddr_in; BATCH],
    lengths: [usize; BATCH],
    limit: usize,
}

impl ReceiveBatch {
    pub fn new() -> Self {
        Self {
            buffers: std::array::from_fn(|_| vec![0; RECEIVE_SIZE].into_boxed_slice()),
            // All-zero sockaddr_in is valid storage for an output address.
            addresses: unsafe { std::mem::zeroed() },
            lengths: [0; BATCH],
            limit: BATCH,
        }
    }

    pub fn single_buffer(&mut self) -> &mut [u8] {
        &mut self.buffers[0]
    }

    pub fn receive(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        let mut iovecs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
        let mut messages: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };
        for i in 0..self.limit {
            iovecs[i].iov_base = self.buffers[i].as_mut_ptr().cast();
            iovecs[i].iov_len = RECEIVE_SIZE;
            messages[i].msg_hdr.msg_name =
                (&mut self.addresses[i] as *mut libc::sockaddr_in).cast();
            messages[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as _;
            messages[i].msg_hdr.msg_iov = &mut iovecs[i];
            messages[i].msg_hdr.msg_iovlen = 1;
        }
        // WAITFORONE blocks only for the first datagram (subject to SO_RCVTIMEO).
        // After that it drains what is available without waiting to fill a batch.
        // All buffers, addresses and iovecs remain live and exclusive for this call.
        let count = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                messages.as_mut_ptr(),
                self.limit as _,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        for (i, msg) in messages[..count as usize].iter().enumerate() {
            // The endpoint only binds IPv4 sockets. Discard unexpected or truncated
            // addresses/payloads rather than handing partial data to QUIC.
            self.lengths[i] = if msg.msg_hdr.msg_flags & libc::MSG_TRUNC == 0
                && msg.msg_hdr.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_in>()
                && self.addresses[i].sin_family == libc::AF_INET as _
            {
                msg.msg_len as usize
            } else {
                0
            };
        }
        // Grow quickly when there is a backlog, but prepare only a small
        // prefix when the socket is keeping up with the clients.
        self.limit = (count as usize * 2).clamp(2, BATCH);
        Ok(count as usize)
    }

    pub fn datagram(&mut self, index: usize) -> (&mut [u8], SocketAddr) {
        let addr = self.addresses[index];
        let from = SocketAddrV4::new(
            addr.sin_addr.s_addr.to_ne_bytes().into(),
            u16::from_be(addr.sin_port),
        );
        (&mut self.buffers[index][..self.lengths[index]], from.into())
    }
}

pub(super) struct SendBatch {
    buffers: [Vec<u8>; SEND_BATCH],
    addresses: [libc::sockaddr_in; SEND_BATCH],
    len: usize,
    segmentation: bool,
}

impl SendBatch {
    pub fn new() -> Self {
        Self {
            buffers: std::array::from_fn(|_| Vec::with_capacity(MAX_DATAGRAM)),
            addresses: unsafe { std::mem::zeroed() },
            len: 0,
            segmentation: true,
        }
    }

    pub fn buffer(&mut self) -> &mut Vec<u8> {
        let buf = &mut self.buffers[self.len];
        buf.clear();
        buf
    }

    pub fn push(&mut self, to: SocketAddr, socket: &UdpSocket) -> io::Result<()> {
        let SocketAddr::V4(to) = to else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "IPv4 endpoint"));
        };
        self.addresses[self.len] = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_port: to.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(to.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        self.len += 1;
        if self.len == SEND_BATCH {
            self.flush(socket)
        } else {
            Ok(())
        }
    }

    pub fn flush(&mut self, socket: &UdpSocket) -> io::Result<()> {
        if self.len == 1 {
            self.len = 0;
            let addr = self.addresses[0];
            let to = SocketAddrV4::new(
                addr.sin_addr.s_addr.to_ne_bytes().into(),
                u16::from_be(addr.sin_port),
            );
            return socket.send_to(&self.buffers[0], to).map(|_| ());
        }
        self.flush_with(|messages| {
            // All referenced storage remains live until the synchronous call returns.
            let n = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    messages.as_mut_ptr(),
                    messages.len() as _,
                    0,
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        })
    }

    // Group only consecutive datagrams with identical destinations. Linux splits
    // the concatenated iovecs at segment_size boundaries, so only the last
    // datagram may be shorter. Empty datagrams must remain separate messages.
    fn group_end(&self, start: usize, count: usize) -> usize {
        let size = self.buffers[start].len();
        let mut end = start + 1;
        if !self.segmentation || size == 0 || size > u16::MAX as usize {
            return end;
        }
        let addr = &self.addresses[start];
        let mut total = size;
        while end < count {
            let next_size = self.buffers[end].len();
            let next_addr = &self.addresses[end];
            if next_addr.sin_addr.s_addr != addr.sin_addr.s_addr
                || next_addr.sin_port != addr.sin_port
                || next_size == 0
                || next_size > size
                // Stay within the IPv4 UDP payload limit, even on older kernels.
                || total + next_size > 65507
            {
                break;
            }
            total += next_size;
            end += 1;
            if next_size < size {
                break;
            }
        }
        end
    }

    fn flush_with(
        &mut self,
        mut send: impl FnMut(&mut [libc::mmsghdr]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let count = std::mem::take(&mut self.len);
        if count == 0 {
            return Ok(());
        }
        // Only the active datagrams and their GSO groups need descriptors. Keep
        // this storage local: payload Vecs may reallocate and SendBatch may move
        // between flushes, so none of these pointers can outlive this call.
        let mut iovecs = [MaybeUninit::<libc::iovec>::uninit(); SEND_BATCH];
        let mut messages = [MaybeUninit::<libc::mmsghdr>::uninit(); SEND_BATCH];
        let mut controls = [const { MaybeUninit::<SegmentControl>::uninit() }; SEND_BATCH];
        for (iov, buf) in iovecs.iter_mut().zip(&mut self.buffers).take(count) {
            iov.write(libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            });
        }
        let iovec_ptr = iovecs.as_mut_ptr().cast::<libc::iovec>();

        let mut first = 0;
        while first < count {
            // Map kernel message boundaries back to original datagram offsets.
            let mut starts = [0; SEND_BATCH + 1];
            let mut groups = 0;
            let mut start = first;
            while start < count {
                let end = self.group_end(start, count);
                starts[groups] = start;
                let msg = &mut messages[groups]
                    .write(libc::mmsghdr {
                        msg_hdr: libc::msghdr {
                            msg_name: (&mut self.addresses[start] as *mut libc::sockaddr_in).cast(),
                            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as _,
                            // Derive from the whole initialized iovec prefix:
                            // this group references start..end, within count.
                            msg_iov: unsafe { iovec_ptr.add(start) },
                            msg_iovlen: end - start,
                            msg_control: std::ptr::null_mut(),
                            msg_controllen: 0,
                            msg_flags: 0,
                        },
                        msg_len: 0,
                    })
                    .msg_hdr;
                if end - start > 1 {
                    let control = controls[groups].write(SegmentControl {
                        bytes: [0; SEGMENT_CONTROL_SIZE],
                    });
                    msg.msg_control = (control as *mut SegmentControl).cast();
                    msg.msg_controllen = SEGMENT_CONTROL_SIZE;
                    // Storage has cmsghdr alignment and CMSG_SPACE(u16) bytes.
                    // Both the header and native-endian payload live through send.
                    unsafe {
                        let cmsg = libc::CMSG_FIRSTHDR(msg);
                        (*cmsg).cmsg_level = libc::IPPROTO_UDP;
                        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                        (*cmsg).cmsg_len = libc::CMSG_LEN(2) as _;
                        libc::CMSG_DATA(cmsg)
                            .cast::<u16>()
                            .write(self.buffers[start].len() as u16);
                    }
                }
                groups += 1;
                start = end;
            }
            starts[groups] = count;

            // Each message in this prefix was fully initialized above. Its
            // address, iovec range, optional padded control and payload buffers
            // remain live until all synchronous sends finish. The unused suffix
            // is never exposed, including when fallback rebuilds fewer groups.
            let messages = unsafe {
                std::slice::from_raw_parts_mut(
                    messages.as_mut_ptr().cast::<libc::mmsghdr>(),
                    groups,
                )
            };

            let mut sent = 0;
            while sent < groups {
                match send(&mut messages[sent..groups]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => sent += n,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error)
                        if messages[sent].msg_hdr.msg_controllen != 0
                            && matches!(
                                error.raw_os_error(),
                                Some(
                                    libc::EINVAL | libc::EIO | libc::ENOPROTOOPT | libc::EOPNOTSUPP
                                )
                            ) =>
                    {
                        // Unsupported cmsg, checksumming or route offload. Rebuild
                        // only the unsent suffix as ordinary datagrams. Cache the
                        // fallback for this endpoint rather than retry every batch.
                        self.segmentation = false;
                        break;
                    }
                    // As with a failed send_to, QUIC loss recovery owns these packets.
                    Err(error) => return Err(error),
                }
            }
            first = starts[sent];
        }
        Ok(())
    }
}

#[cfg(test)]
mod send_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn socket() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        socket
    }

    pub(super) fn batch(spec: &[(usize, u16)]) -> SendBatch {
        assert!(spec.len() <= SEND_BATCH);
        let mut tx = SendBatch::new();
        for (i, &(len, port)) in spec.iter().enumerate() {
            tx.buffers[i].resize(len, i as u8);
            tx.addresses[i] = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                },
                sin_zero: [0; 8],
            };
        }
        tx.len = spec.len();
        tx
    }

    // Decode the actual scatter/gather descriptors like a UDP receiver would.
    // This checks control layout, datagram boundaries and every payload byte.
    pub(super) fn decode(messages: &[libc::mmsghdr]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        for message in messages {
            let msg = &message.msg_hdr;
            unsafe {
                assert_eq!(
                    msg.msg_namelen as usize,
                    std::mem::size_of::<libc::sockaddr_in>()
                );
                let addr = &*msg.msg_name.cast::<libc::sockaddr_in>();
                let port = u16::from_be(addr.sin_port);
                let iovecs = std::slice::from_raw_parts(msg.msg_iov, msg.msg_iovlen);
                let data: Vec<u8> = iovecs
                    .iter()
                    .flat_map(|iov| {
                        std::slice::from_raw_parts(iov.iov_base.cast::<u8>(), iov.iov_len)
                    })
                    .copied()
                    .collect();
                if msg.msg_controllen == 0 {
                    assert_eq!(msg.msg_iovlen, 1);
                    out.push((port, data));
                } else {
                    assert_eq!(msg.msg_controllen, SEGMENT_CONTROL_SIZE);
                    let cmsg = libc::CMSG_FIRSTHDR(msg);
                    assert_eq!((*cmsg).cmsg_level, libc::IPPROTO_UDP);
                    assert_eq!((*cmsg).cmsg_type, libc::UDP_SEGMENT);
                    assert_eq!((*cmsg).cmsg_len, libc::CMSG_LEN(2) as usize);
                    let size = libc::CMSG_DATA(cmsg).cast::<u16>().read() as usize;
                    assert!(msg.msg_iovlen > 1);
                    assert_eq!(data.len().div_ceil(size), msg.msg_iovlen);
                    out.extend(data.chunks(size).map(|chunk| (port, chunk.to_vec())));
                }
            }
        }
        out
    }

    #[test]
    fn segmentation_respects_lengths_peers_and_udp_limit() {
        type GroupCase<'a> = (&'a [(usize, u16)], &'a [usize]);
        let cases: &[GroupCase<'_>] = &[
            (&[(3, 1), (3, 1), (2, 1), (1, 1)], &[3, 1]),
            (&[(2, 1), (3, 1), (3, 1), (1, 1)], &[1, 3]),
            (&[(3, 1), (0, 1), (3, 1), (2, 1)], &[1, 1, 2]),
            (&[(0, 1), (0, 1)], &[1, 1]),
            (&[(3, 1), (3, 2), (2, 2), (1, 1)], &[1, 2, 1]),
            (&[(32754, 1), (32754, 1)], &[1, 1]),
            (&[(32754, 1), (32753, 1)], &[2]),
            (&[(3, 1); SEND_BATCH], &[SEND_BATCH]),
        ];
        for &(spec, groups) in cases {
            let mut tx = batch(spec);
            tx.flush_with(|messages| {
                assert_eq!(
                    messages
                        .iter()
                        .map(|m| m.msg_hdr.msg_iovlen)
                        .collect::<Vec<_>>(),
                    groups
                );
                assert_eq!(
                    decode(messages),
                    spec.iter()
                        .enumerate()
                        .map(|(i, &(n, p))| (p, vec![i as u8; n]))
                        .collect::<Vec<_>>()
                );
                Ok(messages.len())
            })
            .unwrap();
        }
        let mut tx = batch(&[(3, 1), (3, 1)]);
        tx.addresses[1].sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 2]);
        tx.flush_with(|messages| {
            assert_eq!(messages.len(), 2);
            assert!(messages.iter().all(|m| m.msg_hdr.msg_controllen == 0));
            Ok(2)
        })
        .unwrap();
    }

    #[test]
    fn fallback_after_partial_group_send_retries_only_unsent_datagrams() {
        let spec = [(3, 1), (2, 1), (4, 2), (4, 2), (2, 2), (5, 1), (2, 1)];
        for errno in [libc::EINVAL, libc::EIO, libc::ENOPROTOOPT, libc::EOPNOTSUPP] {
            let mut tx = batch(&spec);
            let mut delivered = Vec::new();
            let mut calls = 0;
            tx.flush_with(|messages| {
                calls += 1;
                match calls {
                    1 => {
                        assert_eq!(messages.len(), 3);
                        delivered.extend(decode(&messages[..1]));
                        Ok(1)
                    }
                    2 => Err(io::ErrorKind::Interrupted.into()),
                    3 => Err(io::Error::from_raw_os_error(errno)),
                    4 => {
                        assert_eq!(messages.len(), 5);
                        assert!(messages.iter().all(|m| m.msg_hdr.msg_controllen == 0));
                        delivered.extend(decode(&messages[..2]));
                        Ok(2)
                    }
                    5 => {
                        delivered.extend(decode(messages));
                        Ok(messages.len())
                    }
                    _ => panic!("unexpected retry"),
                }
            })
            .unwrap();
            assert_eq!(calls, 5);
            assert_eq!(
                delivered,
                spec.iter()
                    .enumerate()
                    .map(|(i, &(n, p))| (p, vec![i as u8; n]))
                    .collect::<Vec<_>>()
            );
            assert!(!tx.segmentation);
            assert_eq!(tx.len, 0);
            tx.len = spec.len();
            tx.flush_with(|messages| {
                assert_eq!(messages.len(), spec.len());
                assert!(messages.iter().all(|m| m.msg_hdr.msg_controllen == 0));
                Ok(messages.len())
            })
            .unwrap();
        }
    }

    #[test]
    fn other_errors_and_failed_fallback_are_propagated() {
        for errno in [libc::EAGAIN, libc::ENOBUFS, libc::EMSGSIZE, libc::EPERM] {
            let mut tx = batch(&[(3, 1), (2, 1)]);
            let err = tx
                .flush_with(|_| Err(io::Error::from_raw_os_error(errno)))
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(errno));
            assert!(tx.segmentation);
            assert_eq!(tx.len, 0);
        }
        let mut tx = batch(&[(3, 1), (2, 1)]);
        let mut calls = 0;
        let err = tx
            .flush_with(|_| {
                calls += 1;
                Err(io::Error::from_raw_os_error(libc::EINVAL))
            })
            .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        assert_eq!(calls, 2);
        assert!(!tx.segmentation);

        let mut tx = batch(&[(3, 1), (3, 2), (2, 2)]);
        let mut calls = 0;
        tx.flush_with(|_| {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        })
        .unwrap_err();
        assert_eq!(
            calls, 1,
            "ordinary-send errors must not trigger GSO fallback"
        );
        assert!(tx.segmentation);

        let mut tx = batch(&[(3, 1), (2, 1)]);
        assert_eq!(
            tx.flush_with(|_| Ok(0)).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }

    #[test]
    fn segmented_batches_preserve_wire_payloads_across_flush_and_reuse() {
        let sender = socket();
        let receivers = [socket(), socket()];
        let sizes = [1200, 1200, 954, 954, 1200, 0, 0, 600, 600, 1, 1200];
        let mut tx = SendBatch::new();
        for round in 0..2 {
            let mut expected = [Vec::new(), Vec::new()];
            for (i, &len) in sizes.iter().enumerate() {
                let peer = (i / 3) % 2;
                let data = vec![(i + round * sizes.len()) as u8; len];
                tx.buffer().extend_from_slice(&data);
                tx.push(receivers[peer].local_addr().unwrap(), &sender)
                    .unwrap();
                expected[peer].push(data);
            }
            tx.flush(&sender).unwrap();
            for (receiver, packets) in receivers.iter().zip(expected) {
                let mut buf = [0; 1500];
                for data in packets {
                    let (n, from) = receiver.recv_from(&mut buf).unwrap();
                    assert_eq!(from, sender.local_addr().unwrap());
                    assert_eq!(&buf[..n], data);
                }
                assert!(receiver.recv(&mut buf).is_err(), "unexpected duplicate");
            }
        }
    }

    #[test]
    fn disabled_checksums_trigger_real_kernel_fallback_after_sent_prefix() {
        let sender = socket();
        let receivers = [socket(), socket()];
        let value: libc::c_int = 1;
        // UDP_SEGMENT requires checksums; ordinary IPv4 sends permit SO_NO_CHECK.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NO_CHECK,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as _,
                )
            },
            0
        );
        let mut tx = SendBatch::new();
        for (data, peer) in [
            (b"prefix".as_slice(), 0),
            (b"full segment", 1),
            (b"short", 1),
        ] {
            tx.buffer().extend_from_slice(data);
            tx.push(receivers[peer].local_addr().unwrap(), &sender)
                .unwrap();
        }
        tx.flush(&sender).unwrap();
        assert!(!tx.segmentation);
        let mut buf = [0; 64];
        for (data, peer) in [
            (b"prefix".as_slice(), 0),
            (b"full segment", 1),
            (b"short", 1),
        ] {
            let n = receivers[peer].recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], data);
        }
        for receiver in &receivers {
            assert!(receiver.recv(&mut buf).is_err());
        }
    }

    #[test]
    fn failure_after_sent_segment_group_does_not_replay_it() {
        let sender = socket();
        let receiver = socket();
        let to = receiver.local_addr().unwrap();
        let mut tx = SendBatch::new();
        for (data, to) in [
            (b"first".as_slice(), to),
            (b"two", to),
            (b"bad", "127.0.0.1:0".parse().unwrap()),
        ] {
            tx.buffer().extend_from_slice(data);
            tx.push(to, &sender).unwrap();
        }
        assert!(tx.flush(&sender).is_err());
        tx.buffer().extend_from_slice(b"next");
        tx.push(to, &sender).unwrap();
        tx.flush(&sender).unwrap();
        let mut buf = [0; 64];
        for data in [b"first".as_slice(), b"two", b"next"] {
            let n = receiver.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], data);
        }
        assert!(receiver.recv(&mut buf).is_err());
    }

    #[test]
    fn batches_preserve_payloads_addresses_and_reuse() {
        let sender = socket();
        let receivers = [socket(), socket()];
        let mut tx = SendBatch::new();
        let mut rx = ReceiveBatch::new();
        for round in 0..2 {
            // Cross the capacity boundary and explicitly flush a partial batch.
            for i in 0..BATCH + 3 {
                tx.buffer().extend_from_slice(&[round, i as u8]);
                tx.push(receivers[i % 2].local_addr().unwrap(), &sender)
                    .unwrap();
            }
            tx.flush(&sender).unwrap();
            tx.flush(&sender).unwrap();
            for (which, receiver) in receivers.iter().enumerate() {
                let mut expected = which;
                while expected < BATCH + 3 {
                    let count = rx.receive(receiver).unwrap();
                    for i in 0..count {
                        let (data, from) = rx.datagram(i);
                        assert_eq!(data, &[round, expected as u8]);
                        assert_eq!(from, sender.local_addr().unwrap());
                        expected += 2;
                    }
                }
            }
        }
    }

    #[test]
    fn partial_send_error_does_not_resend_prefix_or_poison_next_batch() {
        let sender = socket();
        let receiver = socket();
        let mut tx = SendBatch::new();
        tx.buffer().extend_from_slice(b"first");
        tx.push(receiver.local_addr().unwrap(), &sender).unwrap();
        tx.buffer().extend_from_slice(b"invalid destination");
        tx.push("127.0.0.1:0".parse().unwrap(), &sender).unwrap();
        // Linux sends the first message and returns a short count. Retrying
        // the suffix exposes the invalid destination's error.
        assert!(tx.flush(&sender).is_err());
        tx.buffer().extend_from_slice(b"next batch");
        tx.push(receiver.local_addr().unwrap(), &sender).unwrap();
        tx.flush(&sender).unwrap();
        let mut buf = [0; 64];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"next batch");
        assert!(receiver.recv(&mut buf).is_err());
    }

    #[test]
    fn receive_handles_full_batches_large_and_empty_datagrams() {
        let sender = socket();
        let receiver = socket();
        let to = receiver.local_addr().unwrap();
        let mut rx = ReceiveBatch::new();
        for i in 0..BATCH {
            sender.send_to(&[i as u8], to).unwrap();
        }
        assert_eq!(rx.receive(&receiver).unwrap(), BATCH);
        for i in 0..BATCH {
            assert_eq!(rx.datagram(i).0, &[i as u8]);
        }
        sender.send_to(&[], to).unwrap();
        sender.send_to(&vec![7; 65000], to).unwrap();
        assert_eq!(rx.receive(&receiver).unwrap(), 2);
        assert!(rx.datagram(0).0.is_empty());
        assert_eq!(rx.datagram(1).0, &[7; 65000]);
    }

    #[test]
    fn receive_returns_partial_batch_and_idle_timeout() {
        let sender = socket();
        let receiver = socket();
        let mut rx = ReceiveBatch::new();
        sender
            .send_to(b"one", receiver.local_addr().unwrap())
            .unwrap();
        assert_eq!(rx.receive(&receiver).unwrap(), 1);
        assert_eq!(rx.datagram(0).0, b"one");
        let start = Instant::now();
        let err = rx.receive(&receiver).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
