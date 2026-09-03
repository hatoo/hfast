//! The socket loop: one thread, one socket, the connections it is routing for
//!
//! Connections are found by the address they came from rather than by their
//! connection id. The transport parameters say active migration is not
//! allowed, and the kernel hands a client's datagrams to the same
//! `SO_REUSEPORT` socket for as long as its address holds, so the two agree.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use super::conn::Connection;
use super::packet::{self, Kind, LOCAL_CID_LEN};
use super::wire::ConnectionId;
use super::{MAX_DATAGRAM, packet::VERSION_1};
use crate::sys;

/// How much of a client's first packet has to be there before it is worth
/// making a connection for (RFC 9000 Section 14.1)
const MIN_INITIAL: usize = 1200;

pub struct Endpoint {
    socket: UdpSocket,
    config: Arc<rustls::ServerConfig>,
    conns: HashMap<SocketAddr, Connection>,
    max_streams: u32,
    next_cid: u64,
    out: Vec<u8>,
}

impl Endpoint {
    pub fn new(socket: UdpSocket, config: Arc<rustls::ServerConfig>, max_streams: u32) -> Self {
        Endpoint {
            socket,
            config,
            conns: HashMap::new(),
            max_streams,
            next_cid: 1,
            out: Vec::with_capacity(MAX_DATAGRAM),
        }
    }

    pub fn run(&mut self) {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = self.socket.recv_from(&mut buf) else {
                continue;
            };
            self.datagram(&mut buf[..n], from);
        }
    }

    fn datagram(&mut self, datagram: &mut [u8], from: SocketAddr) {
        if !self.conns.contains_key(&from) && !self.accept(datagram, from) {
            return;
        }
        let Some(conn) = self.conns.get_mut(&from) else {
            return;
        };
        if conn.recv(datagram).is_err() || conn.closed {
            self.conns.remove(&from);
            return;
        }
        self.flush(from);
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
        self.conns.insert(from, conn);
        true
    }

    fn flush(&mut self, to: SocketAddr) {
        let Some(conn) = self.conns.get_mut(&to) else {
            return;
        };
        while conn.wants_send() {
            self.out.clear();
            match conn.poll_transmit(&mut self.out) {
                Ok(true) => {}
                _ => break,
            }
            if self.socket.send_to(&self.out, to).is_err() {
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
