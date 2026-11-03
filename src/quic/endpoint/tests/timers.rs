use super::*;
use crate::quic::conn::tests::{endpoint_timers as transport, key_updates};
use std::collections::BTreeMap;

fn insert(ep: &mut Endpoint, addr: SocketAddr, conn: Connection, last: Instant) {
    assert!(ep.conns.insert(addr, (conn, last, false)).is_none());
}

fn set_last(ep: &mut Endpoint, addr: SocketAddr, last: Instant) {
    ep.conns.get_mut(&addr).unwrap().1 = last;
}

fn request() -> Vec<u8> {
    let mut body = Vec::new();
    frame::put_stream(
        &mut body,
        0,
        0,
        true,
        b"\x01\x10\x00\x00\xd1\xd7\xc1\x50\x09localhost",
    );
    body
}

fn acknowledge(ep: &mut Endpoint, addr: SocketAddr, peer: &key_updates::Peer, pn: u32, ack: u64) {
    let mut body = Vec::new();
    frame::put_ack(&mut body, &[(ack, ack)], 0);
    ep.datagram(&mut peer.packet(&ep.conns[&addr].0, pn, &body), addr);
}

fn receive_one(
    ep: &mut Endpoint,
    client: &UdpSocket,
    peer: &key_updates::Peer,
    pn: u64,
) -> Vec<u8> {
    ep.out.flush(&ep.socket).unwrap();
    let mut packet = [0; 2048];
    let (len, from) = client.recv_from(&mut packet).unwrap();
    assert_eq!(from, ep.socket.local_addr().unwrap());
    let plain = peer.decrypt(
        &ep.conns[&client.local_addr().unwrap()].0,
        &mut packet[..len],
        pn,
    );
    assert_no_packet(client);
    plain
}

fn assert_no_packet(client: &UdpSocket) {
    assert_eq!(
        client.recv(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn assert_response(plain: &[u8]) {
    let replies: Vec<_> = frame::Frames::new(plain)
        .map(Result::unwrap)
        .filter(|f| matches!(f, frame::Frame::Stream { id: 0, .. }))
        .collect();
    // Independent expected HTTP/3 HEADERS (:status 200, text/plain, length 13)
    // and DATA, including the exact body, offset and FIN of the request stream.
    assert_eq!(
        replies,
        [frame::Frame::Stream {
            id: 0,
            offset: 0,
            fin: true,
            data: b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!",
        }]
    );
}

#[test]
fn empty_quiet_and_strict_idle_boundary() {
    let (mut ep, client) = endpoint();
    ep.tick_at(Instant::now());
    let addr = client.local_addr().unwrap();
    assert!(ep.accept(&initial(0, &[1]), addr));
    let last = ep.conns[&addr].1;
    let cid = ep.conns[&addr].0.local_cid;
    for now in [
        last,
        last + IDLE_TIMEOUT - Duration::from_nanos(1),
        last + IDLE_TIMEOUT,
    ] {
        ep.tick_at(now);
        assert_eq!(ep.conns.len(), 1);
        assert_eq!(ep.conns[&addr].0.local_cid, cid);
        assert!(ep.conns[&addr].0.timeout().is_none());
    }
    ep.tick_at(last + IDLE_TIMEOUT + Duration::from_nanos(1));
    assert!(ep.conns.is_empty());
    ep.out.flush(&ep.socket).unwrap();
    assert_no_packet(&client);
    // The same address starts a distinct connection after expiry.
    assert!(ep.accept(&initial(0, &[1]), addr));
    assert_ne!(ep.conns[&addr].0.local_cid, cid);
    assert!(ep.conns[&addr].0.timeout().is_none());
}

#[derive(Clone, Copy)]
struct Model {
    last: Instant,
    deadline: Option<Instant>,
    fired: u32,
}

#[test]
fn mixed_logical_schedule_matches_independent_full_scan() {
    for seed in [339, 0x1234_5678_9abc_def0] {
        let (mut ep, _) = endpoint();
        let mut model = BTreeMap::<SocketAddr, Model>::new();
        let mut now = Instant::now() + Duration::from_secs(1);
        let mut random = seed;
        let (mut expirations, mut dispatches, mut closes) = (0, 0, 0);
        for step in 0..4096 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let addr = SocketAddr::from(([127, 0, 0, 1], 41000 + (random % 32) as u16));
            if !model.contains_key(&addr) {
                assert!(ep.accept(&initial(0, &[1]), addr));
                set_last(&mut ep, addr, now);
                model.insert(
                    addr,
                    Model {
                        last: now,
                        deadline: None,
                        fired: 0,
                    },
                );
            }
            match step % 7 {
                0 => {
                    ep.datagram(
                        &mut initial(0, &[frame::CONNECTION_CLOSE as u8, 0, 0, 0]),
                        addr,
                    );
                    assert!(!ep.conns.contains_key(&addr));
                    model.remove(&addr);
                    closes += 1;
                }
                1..=3 => {
                    let delta = Duration::from_millis((random >> 8) % 40);
                    let deadline = (step % 7 != 3).then_some(now + delta);
                    transport::seed_deadline(&mut ep.conns.get_mut(&addr).unwrap().0, deadline);
                    model.get_mut(&addr).unwrap().deadline = deadline;
                    ep.flush(addr);
                }
                4 => {
                    set_last(&mut ep, addr, now);
                    model.get_mut(&addr).unwrap().last = now;
                }
                _ => (),
            }
            now += if step % 67 == 0 {
                Duration::from_secs(30)
            } else {
                Duration::from_millis((random >> 16) % 13)
            };
            // This oracle uses only the logical input schedule: no Connection
            // deadline query, transport helper, cache or hash iteration order.
            model.retain(|_, m| {
                if now - m.last > Duration::from_secs(30) {
                    expirations += 1;
                    return false;
                }
                if m.deadline.is_some_and(|t| now >= t) {
                    m.deadline = None;
                    m.fired += 1;
                    dispatches += 1;
                }
                true
            });
            ep.tick_at(now);
            assert_eq!(ep.conns.len(), model.len(), "seed {seed}, step {step}");
            for (addr, m) in &model {
                let (conn, last, queued) = &ep.conns[addr];
                assert_eq!(*last, m.last);
                assert!(!queued);
                assert_eq!(conn.timeout(), m.deadline, "seed {seed}, step {step}");
                assert_eq!(
                    transport::state(conn).pto_count,
                    m.fired,
                    "seed {seed}, step {step}"
                );
            }
        }
        assert!(expirations > 100 && dispatches > 100 && closes > 100);
    }
}

#[test]
fn simultaneous_deadlines_preserve_idle_precedence_and_live_peers() {
    let (mut ep, _) = endpoint();
    let now = Instant::now() + Duration::from_secs(1);
    let clients: Vec<_> = (0..6)
        .map(|_| {
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            c.set_nonblocking(true).unwrap();
            c
        })
        .collect();
    for (i, client) in clients.iter().enumerate() {
        let addr = client.local_addr().unwrap();
        assert!(ep.accept(&initial(0, &[1]), addr));
        let last = if i < 2 { now - IDLE_TIMEOUT } else { now };
        set_last(
            &mut ep,
            addr,
            last - if i == 0 {
                Duration::from_nanos(1)
            } else {
                Duration::ZERO
            },
        );
        let deadline = match i {
            0..=3 => Some(now),
            4 => Some(now + Duration::from_nanos(1)),
            _ => None,
        };
        transport::seed_deadline(&mut ep.conns.get_mut(&addr).unwrap().0, deadline);
        ep.flush(addr);
    }
    ep.tick_at(now);
    assert_eq!(ep.conns.len(), 5);
    assert!(!ep.conns.contains_key(&clients[0].local_addr().unwrap()));
    for (i, client) in clients.iter().enumerate().skip(1) {
        let conn = &ep.conns[&client.local_addr().unwrap()].0;
        assert_eq!(transport::state(conn).pto_count, u32::from(i <= 3));
        assert_eq!(
            conn.timeout(),
            (i == 4).then_some(now + Duration::from_nanos(1))
        );
    }
    ep.tick_at(now + Duration::from_nanos(1));
    assert!(!ep.conns.contains_key(&clients[1].local_addr().unwrap()));
    assert_eq!(
        transport::state(&ep.conns[&clients[4].local_addr().unwrap()].0).pto_count,
        1
    );
    ep.out.flush(&ep.socket).unwrap();
    for client in &clients {
        assert_no_packet(client);
    }
}

#[test]
fn transmit_arms_pto_and_tick_flushes_recovery_at_exact_deadline() {
    let (mut ep, client) = endpoint();
    let addr = client.local_addr().unwrap();
    let (conn, peer, _) = key_updates::pair(true);
    assert!(conn.timeout().is_none());
    insert(&mut ep, addr, conn, Instant::now());
    ep.flush(addr);
    let original = receive_one(&mut ep, &client, &peer, 0);
    let deadline = ep.conns[&addr].0.timeout().unwrap();
    let before = transport::state(&ep.conns[&addr].0);
    ep.tick_at(deadline - Duration::from_nanos(1));
    assert_eq!(transport::state(&ep.conns[&addr].0), before);
    assert_no_packet(&client);
    ep.tick_at(deadline);
    assert_eq!(
        transport::state(&ep.conns[&addr].0).pto_count,
        before.pto_count + 1
    );
    assert_eq!(
        transport::state(&ep.conns[&addr].0).next_packet,
        before.next_packet + 1
    );
    let retry = receive_one(&mut ep, &client, &peer, 1);
    assert_eq!(
        frame::Frames::new(&retry).collect::<Vec<_>>(),
        frame::Frames::new(&original).collect::<Vec<_>>()
    );
}

#[test]
fn authenticated_ack_can_shorten_an_existing_deadline_without_output() {
    let (mut ep, client) = endpoint();
    let addr = client.local_addr().unwrap();
    let (conn, peer, _) = key_updates::pair(true);
    insert(&mut ep, addr, conn, Instant::now());
    ep.flush(addr);
    receive_one(&mut ep, &client, &peer, 0);
    ep.datagram(&mut peer.packet(&ep.conns[&addr].0, 0, &request()), addr);
    ep.flush_ready();
    assert_response(&receive_one(&mut ep, &client, &peer, 1));
    // Leave packet 1 in flight. ACK 0 resets the backoff and updates the RTT.
    transport::backoff(&mut ep.conns.get_mut(&addr).unwrap().0, 3);
    let previous = ep.conns[&addr].0.timeout().unwrap();
    acknowledge(&mut ep, addr, &peer, 1, 0);
    let earlier = ep.conns[&addr].0.timeout().unwrap();
    assert!(earlier < previous);
    let before = transport::state(&ep.conns[&addr].0);
    assert_eq!(before.pto_count, 0);
    ep.flush_ready();
    ep.out.flush(&ep.socket).unwrap();
    assert_no_packet(&client);
    assert_eq!(transport::state(&ep.conns[&addr].0), before);
    ep.tick_at(earlier - Duration::from_nanos(1));
    assert_eq!(transport::state(&ep.conns[&addr].0), before);
    ep.tick_at(earlier);
    assert_eq!(transport::state(&ep.conns[&addr].0).pto_count, 1);
    assert_response(&receive_one(&mut ep, &client, &peer, 2));
}

#[test]
fn authenticated_key_retirement_without_pto_or_pending_flush() {
    for flush_first in [true, false] {
        let (mut ep, client) = endpoint();
        let addr = client.local_addr().unwrap();
        let (conn, mut peer, _) = key_updates::pair(true);
        insert(&mut ep, addr, conn, Instant::now());
        ep.flush(addr);
        receive_one(&mut ep, &client, &peer, 0);
        acknowledge(&mut ep, addr, &peer, 0, 0);
        ep.flush_ready();
        assert!(ep.conns[&addr].0.timeout().is_none());
        peer.update();
        ep.datagram(&mut peer.packet(&ep.conns[&addr].0, 1, &[1]), addr);
        let deadline = ep.conns[&addr].0.timeout().unwrap();
        assert!(transport::state(&ep.conns[&addr].0).previous_keys);
        if flush_first {
            ep.flush_ready();
        }
        ep.tick_at(deadline - Duration::from_nanos(1));
        assert!(transport::state(&ep.conns[&addr].0).previous_keys);
        ep.tick_at(deadline);
        assert!(!transport::state(&ep.conns[&addr].0).previous_keys);
        assert_eq!(transport::state(&ep.conns[&addr].0).pto_count, 0);
        ep.flush_ready();
        let reply = receive_one(&mut ep, &client, &peer, 1);
        let frames: Vec<_> = frame::Frames::new(&reply)
            .map(Result::unwrap)
            .filter(|f| !matches!(f, frame::Frame::Padding))
            .collect();
        assert_eq!(frames.len(), 1);
        assert!(matches!(
            frames[0],
            frame::Frame::Ack {
                largest: 1,
                first_range: 1,
                rest: [],
                ..
            }
        ));
        assert!(ep.conns[&addr].0.timeout().is_none());
    }
}

#[test]
fn lost_response_and_late_original_ack_cancel_further_timer_work() {
    let (mut ep, client) = endpoint();
    let addr = client.local_addr().unwrap();
    let (conn, peer, _) = key_updates::pair(true);
    insert(&mut ep, addr, conn, Instant::now());
    ep.flush(addr);
    receive_one(&mut ep, &client, &peer, 0);
    acknowledge(&mut ep, addr, &peer, 0, 0);
    ep.flush_ready();
    assert!(ep.conns[&addr].0.timeout().is_none());
    ep.datagram(&mut peer.packet(&ep.conns[&addr].0, 1, &request()), addr);
    ep.flush_ready();
    assert_response(&receive_one(&mut ep, &client, &peer, 1));
    let deadline = ep.conns[&addr].0.timeout().unwrap();
    ep.tick_at(deadline);
    assert_response(&receive_one(&mut ep, &client, &peer, 2));
    let retry_deadline = ep.conns[&addr].0.timeout().unwrap();
    assert_eq!(transport::state(&ep.conns[&addr].0).finished, 0);
    acknowledge(&mut ep, addr, &peer, 2, 1);
    ep.flush_ready();
    assert_eq!(transport::state(&ep.conns[&addr].0).finished, 1);
    assert!(ep.conns[&addr].0.timeout().is_none());
    let before = transport::state(&ep.conns[&addr].0);
    ep.tick_at(retry_deadline);
    assert_eq!(transport::state(&ep.conns[&addr].0), before);
    // A duplicate late ACK must not count completion twice or rearm recovery.
    acknowledge(&mut ep, addr, &peer, 3, 1);
    ep.flush_ready();
    assert_eq!(transport::state(&ep.conns[&addr].0), before);
    ep.out.flush(&ep.socket).unwrap();
    assert_no_packet(&client);
}
