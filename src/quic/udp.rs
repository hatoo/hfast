//! Reusable datagram batches for the endpoint's IPv4 socket.

use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use super::MAX_DATAGRAM;

const BATCH: usize = 32;
const SEND_BATCH: usize = 8;
const RECEIVE_SIZE: usize = 65536;

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
}

impl SendBatch {
    pub fn new() -> Self {
        Self {
            buffers: std::array::from_fn(|_| Vec::with_capacity(MAX_DATAGRAM)),
            addresses: unsafe { std::mem::zeroed() },
            len: 0,
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
        let count = std::mem::take(&mut self.len);
        if count == 0 {
            return Ok(());
        }
        if count == 1 {
            let addr = self.addresses[0];
            let to = SocketAddrV4::new(
                addr.sin_addr.s_addr.to_ne_bytes().into(),
                u16::from_be(addr.sin_port),
            );
            return socket.send_to(&self.buffers[0], to).map(|_| ());
        }
        let mut iovecs: [libc::iovec; SEND_BATCH] = unsafe { std::mem::zeroed() };
        let mut messages: [libc::mmsghdr; SEND_BATCH] = unsafe { std::mem::zeroed() };
        for i in 0..count {
            iovecs[i].iov_base = self.buffers[i].as_mut_ptr().cast();
            iovecs[i].iov_len = self.buffers[i].len();
            messages[i].msg_hdr.msg_name =
                (&mut self.addresses[i] as *mut libc::sockaddr_in).cast();
            messages[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as _;
            messages[i].msg_hdr.msg_iov = &mut iovecs[i];
            messages[i].msg_hdr.msg_iovlen = 1;
        }
        let mut sent = 0;
        while sent < count {
            // All referenced storage remains live until the synchronous call returns.
            let n = unsafe {
                libc::sendmmsg(
                    socket.as_raw_fd(),
                    messages[sent..count].as_mut_ptr(),
                    (count - sent) as _,
                    0,
                )
            };
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // As with a failed send_to, QUIC loss recovery owns these packets.
                return Err(error);
            }
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            // sendmmsg may send only a prefix; retry the remaining datagrams.
            sent += n as usize;
        }
        Ok(())
    }
}

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
