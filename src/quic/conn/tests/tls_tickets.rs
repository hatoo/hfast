use super::*;
use rustls::server::StoresServerSessions;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct CountedStorage {
    inner: Arc<dyn StoresServerSessions>,
    puts: AtomicUsize,
}

impl StoresServerSessions for CountedStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.inner.put(key, value)
    }
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.take(key)
    }
    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

// Retain the production policy, replacing only its randomly generated
// certificate so the client can use ordinary certificate verification.
pub(super) fn production_pair(
    mut config: rustls::ServerConfig,
    ticket_request: bool,
) -> (Connection, rustls::quic::ClientConnection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let certified = rustls::sign::CertifiedKey::from_der(
        vec![cert.cert.der().clone()],
        key,
        config.crypto_provider(),
    )
    .unwrap();
    config.cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h3".to_vec()];
    if ticket_request {
        client_config.send_ticket_request = Some(rustls::client::TicketRequest {
            new_session_count: 255,
            resumption_count: 255,
        });
    }
    let mut params = Vec::new();
    for (id, value) in [
        (4, 1 << 30),
        (5, 1 << 24),
        (6, 1 << 24),
        (7, 1 << 24),
        (9, 8),
    ] {
        put_varint(&mut params, id);
        put_varint(&mut params, varint_len(value) as u64);
        put_varint(&mut params, value);
    }
    let client = rustls::quic::ClientConnection::new(
        Arc::new(client_config),
        Version::V1,
        "localhost".try_into().unwrap(),
        params,
    )
    .unwrap();
    let conn = Connection::accept(
        &Arc::new(config),
        ConnectionId::new(&[1; 8]).unwrap(),
        ConnectionId::new(&[2; 8]).unwrap(),
        ConnectionId::new(&[3; 8]).unwrap(),
        64,
        1 << 30,
        1 << 24,
    )
    .unwrap();
    (conn, client)
}

fn before_finished(
    config: rustls::ServerConfig,
    request: bool,
) -> (Connection, Keys, Keys, Vec<u8>) {
    let (mut conn, mut client) = production_pair(config, request);
    let mut hello = Vec::new();
    assert!(client.write_hs(&mut hello).is_none());
    conn.on_frame(
        &frame::Frame::Crypto {
            offset: 0,
            data: &hello,
        },
        Space::Initial,
    )
    .unwrap();
    client.read_hs(&conn.spaces[0].crypto_out).unwrap();
    let mut finished = Vec::new();
    let Some(KeyChange::Handshake { keys: handshake }) = client.write_hs(&mut finished) else {
        panic!("missing client handshake keys");
    };
    assert!(finished.is_empty());
    client.read_hs(&conn.spaces[1].crypto_out).unwrap();
    let Some(KeyChange::OneRtt { keys: data, .. }) = client.write_hs(&mut finished) else {
        panic!("missing client application keys");
    };
    assert!(!client.is_handshaking());
    assert!(conn.tls.is_handshaking());
    assert_eq!(client.alpn_protocol(), Some(b"h3".as_slice()));
    // Model already-transmitted server flights. Finished itself must go
    // through recv, including packet authentication and key retirement.
    conn.spaces[0].crypto_out.clear();
    conn.spaces[1].crypto_out.clear();
    (conn, handshake, data, finished)
}

fn packet(
    conn: &Connection,
    keys: &DirectionalKeys,
    space: Space,
    pn: u32,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let length_at = if space == Space::Handshake {
        packet::put_long_header(
            &mut out,
            Kind::Handshake,
            &conn.local_cid,
            &conn.peer_cid,
            4,
            body.len(),
        )
    } else {
        out.push(0x43);
        out.extend_from_slice(conn.local_cid.as_slice());
        usize::MAX
    };
    let pn_offset = out.len();
    out.extend_from_slice(&pn.to_be_bytes());
    let end = out.len();
    out.extend_from_slice(body);
    if length_at != usize::MAX {
        packet::patch_length(&mut out, length_at, (4 + body.len() + TAG_LEN) as u64).unwrap();
    }
    let (header, payload) = out.split_at_mut(end);
    let tag = keys
        .packet
        .encrypt_in_place(pn as u64, header, payload)
        .unwrap();
    out.extend_from_slice(tag.as_ref());
    protect_header(keys.header.as_ref(), &mut out, pn_offset, 4).unwrap();
    out
}

fn send_finished(
    conn: &mut Connection,
    keys: &Keys,
    pn: u32,
    offset: u64,
    finished: &[u8],
) -> Result<()> {
    let mut body = Vec::new();
    frame::put_crypto(&mut body, offset, finished);
    conn.recv(&mut packet(conn, &keys.local, Space::Handshake, pn, &body))
}

fn response_and_ack(conn: &mut Connection, keys: &Keys) {
    let mut request = Vec::new();
    frame::put_stream(&mut request, 0, 0, true, b"request");
    conn.recv(&mut packet(conn, &keys.local, Space::Data, 0, &request))
        .unwrap();
    let pn = conn.spaces[2].next_pn;
    let mut out = Vec::new();
    assert!(conn.poll_transmit(&mut out).unwrap());
    assert_eq!(packet::parse(&out, 0).unwrap().kind, Kind::Short);
    let offset = 1 + conn.peer_cid.len();
    let (_, len) = unprotect_header(keys.remote.header.as_ref(), &mut out, offset).unwrap();
    let (header, payload) = out.split_at_mut(offset + len);
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(pn, header, payload)
        .unwrap();
    let mut responses = 0;
    let mut confirmed = 0;
    for f in frame::Frames::new(plain) {
        match f.unwrap() {
            frame::Frame::Crypto { .. } => panic!("unexpected post-handshake CRYPTO"),
            // HANDSHAKE_DONE is the only ignored frame this server emits.
            frame::Frame::Ignored => confirmed += 1,
            frame::Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data,
            } => {
                assert_eq!(data, RESPONSE);
                responses += 1;
            }
            _ => {}
        }
    }
    assert_eq!((responses, confirmed), (1, 1));
    let mut ack = Vec::new();
    frame::put_ack(&mut ack, &[(pn, pn)], 0);
    conn.recv(&mut packet(conn, &keys.local, Space::Data, 1, &ack))
        .unwrap();
    assert_eq!(conn.finished, 1);
    assert!(conn.unacked.is_empty());
}

fn counted(mut config: rustls::ServerConfig) -> (rustls::ServerConfig, Arc<CountedStorage>) {
    let storage = Arc::new(CountedStorage {
        inner: config.session_storage.clone(),
        puts: AtomicUsize::new(0),
    });
    config.session_storage = storage.clone();
    (config, storage)
}

#[test]
fn audit_production_ticket_discard() {
    let config = crate::quic::endpoint::tls_config();
    let expected = config.send_tls13_tickets;
    let (config, storage) = counted(config);
    let (mut conn, handshake, data, finished) = before_finished(config, false);
    send_finished(&mut conn, &handshake, 0, 0, &finished).unwrap();
    assert!(!conn.tls.is_handshaking());
    assert!(conn.initial.is_none() && conn.handshake.is_none());
    assert!(
        conn.spaces
            .iter()
            .all(|s| s.crypto_out.is_empty() && s.crypto_flight.is_empty())
    );
    assert_eq!(storage.puts.load(Ordering::Relaxed), expected);
    println!(
        "production tickets stored={} queued_after_recv=0",
        storage.puts.load(Ordering::Relaxed)
    );
    response_and_ack(&mut conn, &data);
}

#[test]
fn production_config_disables_session_storage_and_tickets() {
    let config = crate::quic::endpoint::tls_config();
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.max_tls13_tickets, 0);
    assert!(!config.session_storage.can_cache());
    assert!(!config.session_storage.put(vec![1], vec![2]));
    assert!(config.session_storage.get(&[1]).is_none());
    assert!(config.session_storage.take(&[1]).is_none());
    assert!(!config.ticketer.enabled());
}

fn without_ticket_work(request: bool, fragmented: bool) {
    let mut config = crate::quic::endpoint::tls_config();
    // Even a functioning cache must never be asked to store a ticket. This
    // detects generation work that a no-op cache alone would merely discard.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
    let (config, storage) = counted(config);
    let (mut conn, handshake, data, finished) = before_finished(config, request);
    if fragmented {
        let split = finished.len() / 2;
        send_finished(&mut conn, &handshake, 0, split as u64, &finished[split..]).unwrap();
        send_finished(&mut conn, &handshake, 1, split as u64, &finished[split..]).unwrap();
        assert!(conn.tls.is_handshaking());
        assert_eq!(storage.puts.load(Ordering::Relaxed), 0);
        // The missing prefix arrives after two copies of the suffix.
        send_finished(&mut conn, &handshake, 2, 0, &finished[..split]).unwrap();
        // Late retransmission after key retirement must remain harmless.
        send_finished(&mut conn, &handshake, 3, 0, &finished).unwrap();
    } else {
        send_finished(&mut conn, &handshake, 0, 0, &finished).unwrap();
    }
    assert!(!conn.tls.is_handshaking());
    assert!(conn.initial.is_none() && conn.handshake.is_none());
    assert!(conn.spaces.iter().all(|s| s.crypto_out.is_empty()));
    assert_eq!(storage.puts.load(Ordering::Relaxed), 0);
    response_and_ack(&mut conn, &data);
}

#[test]
fn successful_finished_does_not_generate_tickets() {
    without_ticket_work(false, false);
}

#[test]
fn ticket_request_cannot_enable_generation() {
    without_ticket_work(true, false);
}

#[test]
fn reordered_finished_and_late_duplicates_complete_without_tickets() {
    without_ticket_work(true, true);
}

#[test]
fn malformed_finished_is_still_rejected_before_application_traffic() {
    let (config, storage) = counted(crate::quic::endpoint::tls_config());
    let (mut conn, handshake, data, mut finished) = before_finished(config, true);
    let mut request = Vec::new();
    frame::put_stream(&mut request, 0, 0, true, b"request");
    conn.recv(&mut packet(&conn, &data.local, Space::Data, 0, &request))
        .unwrap();
    assert!(conn.streams.is_empty());
    *finished.last_mut().unwrap() ^= 1;
    assert!(send_finished(&mut conn, &handshake, 0, 0, &finished).is_err());
    assert!(conn.tls.is_handshaking());
    assert!(conn.streams.is_empty());
    assert_eq!(conn.finished, 0);
    assert_eq!(storage.puts.load(Ordering::Relaxed), 0);
}

#[test]
fn finished_and_request_can_share_a_datagram() {
    let (config, storage) = counted(crate::quic::endpoint::tls_config());
    let (mut conn, handshake, data, finished) = before_finished(config, false);
    let mut body = Vec::new();
    frame::put_crypto(&mut body, 0, &finished);
    let mut datagram = packet(&conn, &handshake.local, Space::Handshake, 0, &body);
    body.clear();
    frame::put_stream(&mut body, 0, 0, true, b"request");
    datagram.extend_from_slice(&packet(&conn, &data.local, Space::Data, 0, &body));
    conn.recv(&mut datagram).unwrap();
    assert!(!conn.tls.is_handshaking());
    assert!(conn.handshake.is_none());
    assert_eq!(conn.ready, [0]);
    assert_eq!(storage.puts.load(Ordering::Relaxed), 0);
    // The helper's request repeats packet 0 and must not double-complete it.
    response_and_ack(&mut conn, &data);
}
