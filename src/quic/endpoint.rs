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
    udp::{ReceiveBatch, SendBatch},
};
use crate::sys;

mod timers;
use timers::Timers;

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
    conns: HashMap<SocketAddr, Peer>,
    timers: Timers,
    due: Vec<SocketAddr>,
    /// Peers awaiting output; the boolean in `conns` prevents duplicate entries.
    ready: Vec<SocketAddr>,
    max_streams: u32,
    next_cid: u64,
    out: SendBatch,
}

struct Peer {
    conn: Connection,
    last: Instant,
    queued: bool,
    /// A queued check may precede the current deadline, but never follow it.
    scheduled: Option<Instant>,
}

impl Peer {
    fn schedule(&mut self, addr: SocketAddr, timers: &mut Timers) {
        // Idle expiry is strictly after the advertised interval; recovery is
        // due at its deadline. Instant/Duration have nanosecond precision.
        let idle = self.last + IDLE_TIMEOUT + Duration::from_nanos(1);
        let next = self.conn.timeout().map_or(idle, |t| t.min(idle));
        timers.schedule(addr, &mut self.scheduled, next);
    }
}

impl Endpoint {
    pub fn new(socket: UdpSocket, config: Arc<rustls::ServerConfig>, max_streams: u32) -> Self {
        Endpoint {
            socket,
            config,
            conns: HashMap::new(),
            timers: Timers::default(),
            due: Vec::new(),
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
            let received = if self.conns.len() <= 1 {
                // A lone client need not pay for a receive batch on each
                // request/response round trip. Switch once more clients arrive.
                self.socket
                    .recv_from(batch.single_buffer())
                    .map(|(n, from)| {
                        self.datagram(&mut batch.single_buffer()[..n], from);
                        1
                    })
            } else {
                batch.receive(&self.socket).inspect(|&count| {
                    for i in 0..count {
                        let (datagram, from) = batch.datagram(i);
                        self.datagram(datagram, from);
                    }
                })
            };
            // Do not wait for another receive to finish a connection's output.
            self.flush_ready();
            match received {
                Ok(count) => {
                    since_tick += count as u32;
                    // Under load the socket never goes quiet, so the timers
                    // would never be looked at if this were the only way in
                    if since_tick >= TICK_EVERY {
                        since_tick = 0;
                        self.tick();
                    }
                }
                Err(_) => {
                    since_tick = 0;
                    self.tick();
                }
            }
            // Never wait for another receive to complete a partial send batch.
            let _ = self.out.flush(&self.socket);
        }
    }

    /// Give every connection that is waiting on something a chance to send it
    /// again, and forget the ones that have gone away
    fn tick(&mut self) {
        self.tick_at(Instant::now());
    }

    fn tick_at(&mut self, now: Instant) {
        // Snapshot the due set before transmitting: even a newly armed timer
        // already in the past must run at most once in this tick, as before.
        self.timers.drain_due(now, &mut self.due);
        for i in 0..self.due.len() {
            let addr = self.due[i];
            let peer = self.conns.get_mut(&addr).expect("timer has a peer");
            peer.scheduled = None;
            if now.duration_since(peer.last) > IDLE_TIMEOUT {
                self.conns.remove(&addr);
                continue;
            }
            if peer.conn.timeout().is_some_and(|t| now >= t) {
                peer.conn.on_timeout(now);
                self.flush(addr);
            } else {
                // A receive/ACK postponed or cancelled the original deadline.
                peer.schedule(addr, &mut self.timers);
            }
        }
        self.due.clear();
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
        let Some(peer) = self.conns.get_mut(&from) else {
            if self.accept(datagram, from) {
                self.datagram(datagram, from);
            }
            return;
        };
        peer.last = Instant::now();
        if peer.conn.recv(datagram).is_err() || peer.conn.closed {
            self.timers.remove(from, &mut peer.scheduled);
            self.conns.remove(&from);
            return;
        }
        if !peer.queued {
            peer.queued = true;
            self.ready.push(from);
        }
        // Every receive batch is flushed before tick. Refresh the timer there
        // once, after both receive and transmit have changed recovery state.
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
        let mut peer = Peer {
            conn,
            last: Instant::now(),
            queued: false,
            scheduled: None,
        };
        peer.schedule(from, &mut self.timers);
        self.conns.insert(from, peer);
        true
    }

    fn flush(&mut self, to: SocketAddr) {
        let Some(peer) = self.conns.get_mut(&to) else {
            return;
        };
        peer.queued = false;
        while peer.conn.wants_send() {
            match peer.conn.poll_transmit(self.out.buffer()) {
                Ok(true) => {}
                _ => break,
            }
            if self.out.push(to, &self.socket).is_err() {
                break;
            }
        }
        peer.schedule(to, &mut self.timers);
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
fn tls_config() -> rustls::ServerConfig {
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
    tls
}

#[cfg(test)]
mod tests {
    use super::super::{TAG_LEN, frame, wire};
    use super::*;
    use rustls::quic::{Keys, Version};

    mod timer_tests;

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
