//! HTTP/3, one constant response
//!
//! The transport is quinn's. A QUIC stack is packet protection, loss recovery,
//! congestion control and flow control before it is any use at all, and none of
//! that is worth hand-rolling for something whose whole job is to answer
//! quickly. What is ours is the HTTP/3 layer above it, which for a server that
//! sends the same response every time is a constant.

use std::sync::Arc;

use quinn::{Endpoint, EndpointConfig, ServerConfig, TokioRuntime};

use crate::sys;

/// A HEADERS frame carrying the field section, then a DATA frame carrying the
/// body. Every length fits in a one-byte varint, so the whole reply is a
/// constant. The field section is QPACK against the static table only, which is
/// all a client offering a zero-capacity dynamic table will accept (RFC 9204
/// Section 4.5):
///
/// `0x01 0x08` HEADERS frame, eight bytes of field section
/// `0x00 0x00` field section prefix: no dynamic entries required, base zero
/// `0xd9`      indexed static 25, `:status: 200`
/// `0xf5`      indexed static 53, `content-type: text/plain`
/// `0x54 ..`   literal with static name 4 (content-length), value `13`
/// `0x00 0x0d` DATA frame, thirteen bytes of body
const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

/// Stream type 0 (control), then an empty SETTINGS frame. RFC 9114 Section 6.2
/// requires the control stream, and Section 7.2.4 requires SETTINGS to be the
/// first thing on it; this server has nothing to say in it.
const CONTROL_PRELUDE: &[u8] = b"\x00\x04\x00";

pub fn serve(port: u16, threads: usize, max_streams: u32) {
    // One thread, one socket, one endpoint, one single-threaded runtime, the
    // same shape as the TCP side. Sharing an endpoint between threads instead
    // put every connection through the same lock and cost a third of the
    // throughput at 32 of them.
    let config = config(max_streams);
    // Steering by CPU the way the TCP side does would break this. A reuseport
    // program on TCP only picks the listener a new connection is accepted on,
    // and everything after that goes to the accepted socket; on UDP it picks
    // the socket for every datagram, so packets of one QUIC connection would
    // scatter across endpoints that know nothing about it. The kernel's own
    // hash keeps a client on one socket, which is what a connection needs.
    let mut sockets: Vec<_> = (0..threads).map(|_| sys::udp_listener(port)).collect();

    let mut running = Vec::new();
    for (cpu, socket) in sockets.drain(1..).enumerate() {
        let config = config.clone();
        running.push(std::thread::spawn(move || {
            endpoint(socket, config, cpu + 1)
        }));
    }
    endpoint(sockets.pop().expect("one socket per thread"), config, 0);
    for t in running {
        let _ = t.join();
    }
}

fn endpoint(socket: std::net::UdpSocket, config: ServerConfig, cpu: usize) {
    sys::pin_to_cpu(cpu);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async move {
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )
        .expect("QUIC endpoint");
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    connection(conn).await;
                }
            });
        }
    });
}

/// A self-signed certificate, generated at startup. This is a benchmark target:
/// there is nothing here worth authenticating, and a load generator pointed at
/// it is not checking.
fn config(max_streams: u32) -> ServerConfig {
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
    // Without this the handshake has nothing to agree on and every connection
    // fails: RFC 9114 Section 3.1 requires HTTP/3 to be named in ALPN.
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC TLS config");
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));

    let transport = Arc::get_mut(&mut config.transport).expect("sole owner");
    // What a client may have in flight at once. This is not free to raise: a
    // request costs 1.27us of server CPU at 128 and 2.14us at 16384, so the
    // number is a promise to be kept rather than a limit to set out of the way.
    // It has to be at least what the load generator asks for, or the run is
    // measuring this limit instead of either end's speed.
    transport.max_concurrent_bidi_streams(max_streams.into());
    // The control stream and the two QPACK streams, and room to spare
    transport.max_concurrent_uni_streams(16u32.into());
    transport.stream_receive_window((256 * 1024u32).into());
    transport.receive_window((16 * 1024 * 1024u32).into());
    transport.send_window(16 * 1024 * 1024);
    config
}

async fn connection(conn: quinn::Connection) {
    let Ok(mut control) = conn.open_uni().await else {
        return;
    };
    if control.write_all(CONTROL_PRELUDE).await.is_err() {
        return;
    }
    // Not finished: RFC 9114 Section 6.2.1 makes the control stream critical and
    // closing it is H3_CLOSED_CRITICAL_STREAM.

    // The peer's own control and QPACK streams have to be accepted or its
    // flow-control credit runs out, but nothing on them changes the answer.
    let peer = conn.clone();
    tokio::spawn(async move {
        while let Ok(mut s) = peer.accept_uni().await {
            tokio::spawn(async move {
                let mut sink = [0u8; 1024];
                while matches!(s.read(&mut sink).await, Ok(Some(_))) {}
            });
        }
    });

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        // Answered on this task rather than one of its own: a request is a
        // read and a write with nothing to wait for in between, and spawning
        // for it costs more than doing it.
        let mut sink = [0u8; 1024];
        while matches!(recv.read(&mut sink).await, Ok(Some(_))) {}
        if send.write_all(RESPONSE).await.is_err() {
            return;
        }
        let _ = send.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `RESPONSE` is supposed to be carrying, spelt out separately so the
    /// hand-assembled bytes are checked against something rather than restated
    const FIELD_SECTION: &[u8] = b"\x00\x00\xd9\xf5\x54\x02\x31\x33";
    const BODY: &[u8] = b"Hello, World!";

    /// The bytes are hand-assembled, so the frame lengths have to be checked
    /// against what they are supposed to be carrying
    #[test]
    fn the_response_frames_say_how_long_they_are() {
        assert_eq!(RESPONSE[0], 0x01, "HEADERS frame");
        assert_eq!(RESPONSE[1] as usize, FIELD_SECTION.len());
        let data = 2 + FIELD_SECTION.len();
        assert_eq!(&RESPONSE[2..data], FIELD_SECTION);
        assert_eq!(RESPONSE[data], 0x00, "DATA frame");
        assert_eq!(RESPONSE[data + 1] as usize, BODY.len());
        assert_eq!(&RESPONSE[data + 2..], BODY);
    }

    /// RFC 9204 Section 4.5.2: an indexed field line is `1` `T` and a 6-bit
    /// index, with T set for the static table
    #[test]
    fn the_field_section_references_only_the_static_table() {
        assert_eq!(FIELD_SECTION[0..2], [0, 0], "no dynamic entries needed");
        assert_eq!(FIELD_SECTION[2] & 0xc0, 0xc0, "indexed, static");
        assert_eq!(FIELD_SECTION[2] & 0x3f, 25, ":status: 200");
        assert_eq!(FIELD_SECTION[3] & 0xc0, 0xc0, "indexed, static");
        assert_eq!(FIELD_SECTION[3] & 0x3f, 53, "content-type: text/plain");
        // Section 4.5.4: `01` `N` `T` and a 4-bit name index
        assert_eq!(FIELD_SECTION[4] & 0xf0, 0x50, "literal, static name");
        assert_eq!(FIELD_SECTION[4] & 0x0f, 4, "content-length");
        assert_eq!(FIELD_SECTION[5], 2, "two bytes of value, unhuffmanned");
        assert_eq!(&FIELD_SECTION[6..], b"13");
    }
}
