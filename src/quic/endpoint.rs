//! The socket loop: one thread, one socket, the connections it is routing for
//!
//! Connections are found by the address they came from rather than by their
//! connection id. The transport parameters say active migration is not
//! allowed, and the kernel hands a client's datagrams to the same
//! `SO_REUSEPORT` socket for as long as its address holds, so the two agree.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::conn::Connection;
use super::packet::{self, Kind, LOCAL_CID_LEN};
use super::wire::ConnectionId;
use super::{
    packet::VERSION_1,
    udp::{ReceiveBatch, SendBatch, enable_gro},
};
use crate::sys;

/// How much of a client's first packet has to be there before it is worth
/// making a connection for (RFC 9000 Section 14.1)
const MIN_INITIAL: usize = 1200;

/// How many datagrams may go by before the timers are looked at
const TICK_EVERY: u32 = 2048;

/// A client that has said nothing for this long is forgotten. It matches the
/// idle timeout the transport parameters promise.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Endpoint {
    socket: UdpSocket,
    config: Arc<rustls::ServerConfig>,
    conns: HashMap<SocketAddr, (Connection, Instant, bool)>,
    /// Peers awaiting output; the boolean in `conns` prevents duplicate entries.
    ready: Vec<SocketAddr>,
    max_streams: u32,
    next_cid: u64,
    out: SendBatch,
}

impl Endpoint {
    pub fn new(socket: UdpSocket, config: Arc<rustls::ServerConfig>, max_streams: u32) -> Self {
        let _ = enable_gro(&socket);
        Endpoint {
            socket,
            config,
            conns: HashMap::new(),
            ready: Vec::new(),
            max_streams,
            next_cid: 1,
            out: SendBatch::new(),
        }
    }

    pub fn run(&mut self) {
        let mut batch = ReceiveBatch::new();
        // Short enough that a connection waiting on a lost packet does not
        // wait on the socket as well, long enough that a quiet server is not
        // spinning
        let _ = self.socket.set_read_timeout(Some(Duration::from_millis(5)));
        let mut since_tick = 0u32;
        loop {
            let received = self.receive(&mut batch, &mut since_tick);
            // Do not wait for another receive to finish a connection's output.
            self.flush_ready();
            if received.is_err() {
                since_tick = 0;
                self.tick();
            }
            // Never wait for another receive to complete a partial send batch.
            let _ = self.out.flush(&self.socket);
        }
    }

    fn receive(&mut self, batch: &mut ReceiveBatch, since_tick: &mut u32) -> std::io::Result<()> {
        // A lone client still uses one receive message per round trip. Both
        // paths split aggregates before QUIC parsing or in-place decryption.
        let messages = batch.receive(&self.socket, self.conns.len() <= 1)?;
        for i in 0..messages {
            let (datagrams, from) = batch.datagrams(i);
            let mut processed = false;
            for datagram in datagrams {
                self.datagram(datagram, from);
                self.received_one(since_tick);
                processed = true;
            }
            if !processed {
                // Invalid/truncated input cannot indefinitely starve timers.
                self.received_one(since_tick);
            }
        }
        Ok(())
    }

    fn received_one(&mut self, since_tick: &mut u32) {
        *since_tick += 1;
        if *since_tick >= TICK_EVERY {
            *since_tick = 0;
            self.flush_ready();
            self.tick();
        }
    }

    /// Give every connection that is waiting on something a chance to send it
    /// again, and forget the ones that have gone away
    fn tick(&mut self) {
        let now = Instant::now();
        let due: Vec<SocketAddr> = self
            .conns
            .iter()
            .filter(|(_, (c, last, _))| {
                now.duration_since(*last) > IDLE_TIMEOUT || c.timeout().is_some_and(|t| now >= t)
            })
            .map(|(a, _)| *a)
            .collect();
        for addr in due {
            let Some((conn, last, _)) = self.conns.get_mut(&addr) else {
                continue;
            };
            if now.duration_since(*last) > IDLE_TIMEOUT {
                self.conns.remove(&addr);
                continue;
            }
            conn.on_timeout(now);
            self.flush(addr);
        }
    }

    fn flush_ready(&mut self) {
        // Consume all available input before building response packets. This
        // combines ACKs and fills packets even when peers interleave a burst.
        for i in 0..self.ready.len() {
            self.flush(self.ready[i]);
        }
        self.ready.clear();
    }

    fn datagram(&mut self, datagram: &mut [u8], from: SocketAddr) {
        let Some((conn, last, queued)) = self.conns.get_mut(&from) else {
            if self.accept(datagram, from) {
                self.datagram(datagram, from);
            }
            return;
        };
        *last = Instant::now();
        if conn.recv(datagram).is_err() || conn.closed {
            self.conns.remove(&from);
            return;
        }
        if !*queued {
            *queued = true;
            self.ready.push(from);
        }
    }

    /// A datagram from an address with no connection: it has to be an Initial
    /// big enough to prove the path carries one
    fn accept(&mut self, datagram: &[u8], from: SocketAddr) -> bool {
        if datagram.len() < MIN_INITIAL {
            return false;
        }
        let Ok(h) = packet::parse(datagram, 0) else {
            return false;
        };
        if h.kind != Kind::Initial || h.version != VERSION_1 {
            return false;
        }
        let mut cid = [0u8; LOCAL_CID_LEN];
        cid.copy_from_slice(&self.next_cid.to_be_bytes()[..LOCAL_CID_LEN]);
        self.next_cid += 1;
        let Ok(local_cid) = ConnectionId::new(&cid) else {
            return false;
        };
        let Ok(conn) = Connection::accept(
            &self.config,
            h.dcid,
            h.scid,
            local_cid,
            self.max_streams as u64,
            1 << 30,
            1 << 24,
        ) else {
            return false;
        };
        self.conns.insert(from, (conn, Instant::now(), false));
        true
    }

    fn flush(&mut self, to: SocketAddr) {
        let Some((conn, _, queued)) = self.conns.get_mut(&to) else {
            return;
        };
        *queued = false;
        while conn.wants_send() {
            match conn.poll_transmit(self.out.buffer()) {
                Ok(true) => {}
                _ => break,
            }
            if self.out.push(to, &self.socket).is_err() {
                break;
            }
        }
    }
}

pub fn serve(port: u16, threads: usize, max_streams: u32) {
    let config = Arc::new(tls_config());
    let sockets: Vec<_> = (0..threads).map(|_| sys::udp_listener(port)).collect();
    let mut running = Vec::new();
    for (cpu, socket) in sockets.into_iter().enumerate() {
        let config = config.clone();
        running.push(std::thread::spawn(move || {
            sys::pin_to_cpu(cpu);
            Endpoint::new(socket, config, max_streams).run()
        }));
    }
    for t in running {
        let _ = t.join();
    }
}

/// A self-signed certificate, generated at startup, and ALPN naming HTTP/3
pub(super) fn tls_config() -> rustls::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("self-signed");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key)
    .expect("certificate");
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // This transport does not send post-handshake CRYPTO: pump_tls queues
    // tickets in Handshake, which recv retires immediately after Finished.
    // Avoid deriving and caching resumption state that no client can use.
    tls.send_tls13_tickets = 0;
    tls.max_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls
}

#[cfg(test)]
mod tests {
    use super::super::{TAG_LEN, frame, wire};
    use super::*;
    use rustls::quic::{Keys, Version};

    fn client_keys() -> Keys {
        let rustls::SupportedCipherSuite::Tls13(suite) =
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        Keys::initial(
            Version::V1,
            suite,
            suite.quic.unwrap(),
            &[1; 8],
            rustls::Side::Client,
        )
    }

    fn initial(pn: u8, payload: &[u8]) -> Vec<u8> {
        let keys = client_keys();
        let mut out = Vec::new();
        let length_at = packet::put_long_header(
            &mut out,
            Kind::Initial,
            &ConnectionId::new(&[1; 8]).unwrap(),
            &ConnectionId::new(&[2; 8]).unwrap(),
            1,
            MIN_INITIAL,
        );
        let pn_offset = out.len();
        out.push(pn);
        let header_end = out.len();
        out.extend_from_slice(payload);
        out.resize(MIN_INITIAL - TAG_LEN, 0);
        packet::patch_length(&mut out, length_at, (MIN_INITIAL - pn_offset) as u64).unwrap();
        let (head, body) = out.split_at_mut(header_end);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(pn as u64, head, body)
            .unwrap();
        out.extend_from_slice(tag.as_ref());
        wire::protect_header(keys.local.header.as_ref(), &mut out, pn_offset, 1).unwrap();
        out
    }

    fn endpoint() -> (Endpoint, UdpSocket) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_nonblocking(true).unwrap();
        (Endpoint::new(server, Arc::new(tls_config()), 64), client)
    }

    fn send_initials(client: &UdpSocket, to: SocketAddr, packets: &[(u8, &[u8])]) {
        let mut tx = SendBatch::new();
        for &(pn, payload) in packets {
            tx.buffer().extend_from_slice(&initial(pn, payload));
            tx.push(to, client).unwrap();
        }
        tx.flush(client).unwrap();
    }

    #[test]
    fn gro_receive_preserves_sparse_ack_ranges_duplicates_and_reordering() {
        for gro in [false, true] {
            let (mut ep, client) = endpoint();
            if !gro {
                use std::os::fd::AsRawFd;
                let zero: libc::c_int = 0;
                assert_eq!(
                    unsafe {
                        libc::setsockopt(
                            ep.socket.as_raw_fd(),
                            libc::IPPROTO_UDP,
                            libc::UDP_GRO,
                            (&zero as *const libc::c_int).cast(),
                            std::mem::size_of_val(&zero) as _,
                        )
                    },
                    0
                );
            }
            let ping = [frame::PING as u8];
            send_initials(
                &client,
                ep.socket.local_addr().unwrap(),
                &[(0, &ping), (4, &ping), (2, &ping), (4, &ping), (1, &ping)],
            );
            let mut batch = ReceiveBatch::new();
            let mut received = 0;
            while received < 5 {
                ep.receive(&mut batch, &mut received).unwrap();
            }
            assert_eq!(received, 5);
            assert_eq!(ep.conns.len(), 1);
            assert_eq!(ep.ready, [client.local_addr().unwrap()]);
            ep.flush_ready();
            ep.out.flush(&ep.socket).unwrap();
            let mut buf = [0; 2048];
            let n = client.recv(&mut buf).unwrap();
            let packet = &mut buf[..n];
            let header = packet::parse(packet, 0).unwrap();
            let keys = client_keys();
            let (_, pn_len) =
                wire::unprotect_header(keys.remote.header.as_ref(), packet, header.pn_offset)
                    .unwrap();
            let (head, body) = packet.split_at_mut(header.pn_offset + pn_len);
            let plain = keys.remote.packet.decrypt_in_place(0, head, body).unwrap();
            let frames = frame::Frames::new(plain)
                .collect::<wire::Result<Vec<_>>>()
                .unwrap();
            let [
                frame::Frame::Ack {
                    largest,
                    first_range,
                    rest,
                    ..
                },
            ] = frames.as_slice()
            else {
                panic!("expected one ACK");
            };
            assert_eq!(
                frame::AckRanges::new(*largest, *first_range, rest).collect::<Vec<_>>(),
                [(4, 4), (0, 2)]
            );
            assert_eq!(
                client.recv(&mut buf).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn gro_receive_switches_one_many_one_peers_and_counts_datagrams_for_timers() {
        let (mut ep, first) = endpoint();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = ep.socket.local_addr().unwrap();
        let ping = [frame::PING as u8];
        let mut batch = ReceiveBatch::new();
        let mut received = 0;
        send_initials(&first, to, &[(0, &ping), (2, &ping), (1, &ping)]);
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(received, 3);
        assert_eq!(ep.conns.len(), 1);
        send_initials(&second, to, &[(0, &ping), (1, &ping)]);
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(received, 5);
        assert_eq!(ep.conns.len(), 2);
        send_initials(&first, to, &[(3, &ping), (4, &ping)]);
        send_initials(
            &second,
            to,
            &[(2, &[frame::CONNECTION_CLOSE as u8, 0, 0, 0])],
        );
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(received, 8);
        assert_eq!(ep.conns.len(), 1);
        assert!(ep.conns.contains_key(&first.local_addr().unwrap()));
        assert!(!ep.conns.contains_key(&second.local_addr().unwrap()));
        // Crossing the timer budget within an aggregate retains the remainder.
        received = TICK_EVERY - 1;
        send_initials(&first, to, &[(5, &ping), (6, &ping)]);
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(received, 1);
        assert_eq!(ep.conns.len(), 1);
        ep.flush_ready();
        ep.out.flush(&ep.socket).unwrap();
    }

    #[test]
    fn invalid_quic_segments_still_run_timers_inside_a_gro_aggregate() {
        let (mut ep, idle) = endpoint();
        let idle_addr = idle.local_addr().unwrap();
        ep.datagram(&mut initial(0, &[frame::PING as u8]), idle_addr);
        ep.conns.get_mut(&idle_addr).unwrap().1 =
            Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1);
        let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut tx = SendBatch::new();
        for _ in 0..8 {
            tx.buffer().extend_from_slice(&[0; 13]);
            tx.push(ep.socket.local_addr().unwrap(), &attacker).unwrap();
        }
        tx.flush(&attacker).unwrap();
        let mut batch = ReceiveBatch::new();
        let mut received = TICK_EVERY - 3;
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(
            received, 5,
            "count original datagrams, including invalid QUIC"
        );
        assert!(ep.conns.is_empty(), "the timer must expire the idle peer");
        assert!(ep.ready.is_empty());
    }

    #[test]
    fn truncated_control_is_discarded_without_starving_timers() {
        use std::os::fd::AsRawFd;
        let (mut ep, idle) = endpoint();
        let idle_addr = idle.local_addr().unwrap();
        ep.datagram(&mut initial(0, &[frame::PING as u8]), idle_addr);
        ep.conns.get_mut(&idle_addr).unwrap().1 =
            Instant::now() - IDLE_TIMEOUT - Duration::from_secs(1);
        // A timestamp needs more ancillary storage than the GRO-only receiver.
        // The kernel must report MSG_CTRUNC; this otherwise valid Initial must
        // not create a connection, and the discarded message must tick timers.
        let one: libc::c_int = 1;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    ep.socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_TIMESTAMPNS,
                    (&one as *const libc::c_int).cast(),
                    std::mem::size_of_val(&one) as _,
                )
            },
            0
        );
        let newcomer = UdpSocket::bind("127.0.0.1:0").unwrap();
        send_initials(
            &newcomer,
            ep.socket.local_addr().unwrap(),
            &[(0, &[frame::PING as u8])],
        );
        let mut batch = ReceiveBatch::new();
        let mut received = TICK_EVERY - 1;
        ep.receive(&mut batch, &mut received).unwrap();
        assert_eq!(received, 0);
        assert!(ep.conns.is_empty());
        assert!(ep.ready.is_empty());
    }

    #[test]
    fn received_packets_share_one_ack_and_the_next_batch_can_send_again() {
        let (mut ep, client) = endpoint();
        let from = client.local_addr().unwrap();
        let mut buf = [0; 2048];
        for round in 0..2u8 {
            for pn in round * 2..round * 2 + 2 {
                ep.datagram(&mut initial(pn, &[frame::PING as u8]), from);
            }
            assert_eq!(ep.ready, [from]);
            assert_eq!(
                client.recv(&mut buf).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            ep.flush_ready();
            ep.out.flush(&ep.socket).unwrap();
            let n = client.recv(&mut buf).unwrap();
            let packet = &mut buf[..n];
            let header = packet::parse(packet, 0).unwrap();
            let keys = client_keys();
            let (_, pn_len) =
                wire::unprotect_header(keys.remote.header.as_ref(), packet, header.pn_offset)
                    .unwrap();
            let (head, body) = packet.split_at_mut(header.pn_offset + pn_len);
            let plain = keys
                .remote
                .packet
                .decrypt_in_place(round as u64, head, body)
                .unwrap();
            let frames = frame::Frames::new(plain)
                .collect::<wire::Result<Vec<_>>>()
                .unwrap();
            assert!(
                matches!(frames.as_slice(), [frame::Frame::Ack { largest, first_range, .. }]
                if *largest == (round * 2 + 1) as u64 && *first_range == *largest)
            );
            assert_eq!(
                client.recv(&mut buf).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn interleaved_peers_each_get_one_response_packet() {
        let (mut ep, first) = endpoint();
        let second = UdpSocket::bind("127.0.0.1:0").unwrap();
        second.set_nonblocking(true).unwrap();
        for pn in 0..2 {
            for client in [&first, &second] {
                ep.datagram(
                    &mut initial(pn, &[frame::PING as u8]),
                    client.local_addr().unwrap(),
                );
            }
        }
        assert_eq!(ep.ready.len(), 2);
        ep.flush_ready();
        ep.out.flush(&ep.socket).unwrap();
        for client in [&first, &second] {
            assert!(client.recv(&mut [0; 2048]).unwrap() > 0);
            assert_eq!(
                client.recv(&mut [0; 2048]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn closing_during_a_receive_batch_discards_queued_output() {
        let (mut ep, client) = endpoint();
        let from = client.local_addr().unwrap();
        ep.datagram(&mut initial(0, &[frame::PING as u8]), from);
        ep.datagram(
            &mut initial(1, &[frame::CONNECTION_CLOSE as u8, 0, 0, 0]),
            from,
        );
        assert!(ep.conns.is_empty());
        ep.flush_ready();
        ep.out.flush(&ep.socket).unwrap();
        assert_eq!(
            client.recv(&mut [0; 2048]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
