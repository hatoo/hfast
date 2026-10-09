use super::*;

#[test]
fn idle_boundary_refresh_and_stale_checks_match_the_scan() {
    let (mut ep, client) = endpoint();
    let from = client.local_addr().unwrap();
    ep.datagram(&mut initial(0, &[frame::PING as u8]), from);
    ep.flush_ready();
    let original = ep.conns[&from].last;
    ep.tick_at(original + IDLE_TIMEOUT);
    assert_eq!(ep.conns.len(), 1, "strict idle boundary");
    let refreshed = original + Duration::from_secs(10);
    ep.conns.get_mut(&from).unwrap().last = refreshed;
    ep.flush(from);
    ep.tick_at(original + IDLE_TIMEOUT + Duration::from_nanos(1));
    assert_eq!(ep.conns.len(), 1, "old check must recheck current state");
    assert_eq!(
        ep.conns[&from].scheduled,
        Some(refreshed + IDLE_TIMEOUT + Duration::from_nanos(1))
    );
    ep.tick_at(refreshed + IDLE_TIMEOUT);
    assert_eq!(ep.conns.len(), 1);
    ep.tick_at(refreshed + IDLE_TIMEOUT + Duration::from_nanos(1));
    assert!(ep.conns.is_empty());
    assert!(ep.timers.is_empty());
    ep.tick_at(refreshed + IDLE_TIMEOUT + Duration::from_secs(1));
}

#[test]
fn closing_and_reaccepting_a_queued_address_cancels_the_old_timer() {
    let (mut ep, client) = endpoint();
    let from = client.local_addr().unwrap();
    for _ in 0..32 {
        ep.datagram(&mut initial(0, &[frame::PING as u8]), from);
        assert_eq!(ep.conns.len(), 1);
        ep.datagram(
            &mut initial(1, &[frame::CONNECTION_CLOSE as u8, 0, 0, 0]),
            from,
        );
        assert!(ep.conns.is_empty());
        assert!(ep.timers.is_empty());
    }
    ep.datagram(&mut initial(0, &[frame::PING as u8]), from);
    assert_eq!(ep.conns.len(), 1);
    ep.flush_ready();
    let last = ep.conns[&from].last;
    ep.tick_at(last + IDLE_TIMEOUT);
    assert_eq!(ep.conns.len(), 1);
    ep.tick_at(last + IDLE_TIMEOUT + Duration::from_nanos(1));
    assert!(ep.timers.is_empty());
    assert!(ep.conns.is_empty());
}

#[test]
fn invalid_receive_cancels_timer_and_ready_entry_is_harmless() {
    let (mut ep, client) = endpoint();
    let from = client.local_addr().unwrap();
    ep.datagram(&mut initial(0, &[frame::PING as u8]), from);
    ep.datagram(&mut initial(1, &[0xff]), from);
    assert!(ep.conns.is_empty());
    assert!(ep.timers.is_empty());
    ep.flush_ready();
    ep.tick();
}

#[test]
fn flush_arms_handshake_recovery_and_each_tick_probes_only_once() {
    let (mut ep, client) = endpoint();
    let from = client.local_addr().unwrap();
    let mut conf = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    conf.alpn_protocols = vec![b"h3".to_vec()];
    let mut tls = rustls::quic::ClientConnection::new(
        Arc::new(conf),
        Version::V1,
        "localhost".try_into().unwrap(),
        vec![],
    )
    .unwrap();
    let mut hello = Vec::new();
    tls.write_hs(&mut hello);
    let mut payload = Vec::new();
    frame::put_crypto(&mut payload, 0, &hello);
    assert!(payload.len() < 1100);
    ep.datagram(&mut initial(0, &payload), from);
    assert!(ep.conns[&from].conn.timeout().is_none());
    let idle_check = ep.conns[&from].scheduled.unwrap();
    ep.flush_ready();
    let first = ep.conns[&from].conn.timeout().unwrap();
    assert!(first < idle_check);
    assert_eq!(ep.conns[&from].scheduled, Some(first));
    ep.tick_at(first - Duration::from_nanos(1));
    assert_eq!(ep.conns[&from].conn.timeout(), Some(first));
    ep.tick_at(first);
    let second = ep.conns[&from].conn.timeout().unwrap();
    assert!(second > first);
    assert_eq!(ep.conns[&from].scheduled, Some(second));
    // Simulated time far ahead of real transmit time leaves the next probe
    // already due. It must remain queued for the next tick, not spin here.
    ep.tick_at(first + Duration::from_secs(20));
    let third = ep.conns[&from].conn.timeout().unwrap();
    assert!(third > second);
    assert!(third < first + Duration::from_secs(20));
    assert_eq!(ep.conns[&from].scheduled, Some(third));
    assert_eq!(ep.conns.len(), 1);
    assert!(ep.due.is_empty());
}
