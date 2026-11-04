use super::*;
use crate::quic::conn::tests::{endpoint_timers as transport, key_updates};

const REQUEST: &[u8] = b"\x01\x10\x00\x00\xd1\xd7\xc1\x50\x09localhost";
const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

fn no_packet(client: &UdpSocket) {
    assert_eq!(
        client.recv(&mut [0; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

fn send(ep: &mut Endpoint, addr: SocketAddr, peer: &key_updates::Peer, pn: u32, body: &[u8]) {
    ep.datagram(&mut peer.packet(&ep.conns[&addr].0, pn, body), addr);
}

fn ack(ep: &mut Endpoint, addr: SocketAddr, peer: &key_updates::Peer, pn: u32, acked: u64) {
    let mut body = Vec::new();
    frame::put_ack(&mut body, &[(acked, acked)], 0);
    send(ep, addr, peer, pn, &body);
}

fn receive(ep: &mut Endpoint, client: &UdpSocket, peer: &key_updates::Peer, pn: u64) -> Vec<u8> {
    ep.out.flush(&ep.socket).unwrap();
    let mut buf = [0; 2048];
    let (len, from) = client.recv_from(&mut buf).unwrap();
    assert_eq!(from, ep.socket.local_addr().unwrap());
    let plain = peer.decrypt(
        &ep.conns[&client.local_addr().unwrap()].0,
        &mut buf[..len],
        pn,
    );
    no_packet(client);
    plain
}

fn responses(plain: &[u8]) -> Vec<(u64, u64, Vec<u8>, bool)> {
    frame::Frames::new(plain)
        .map(Result::unwrap)
        .filter_map(|f| match f {
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } if id & 3 == 0 => Some((id, offset, data.to_vec(), fin)),
            _ => None,
        })
        .collect()
}

#[test]
fn encrypted_ack_at_distance_three_retries_without_a_timer_or_extra_input() {
    for cancel_queued in [false, true] {
        let (mut ep, client) = endpoint();
        let addr = client.local_addr().unwrap();
        let (conn, peer, _) = key_updates::pair(true);
        assert!(
            ep.conns
                .insert(addr, (conn, Instant::now(), false))
                .is_none()
        );
        ep.flush(addr);
        receive(&mut ep, &client, &peer, 0);
        ack(&mut ep, addr, &peer, 0, 0);
        ep.flush_ready();
        for i in 0..4 {
            let mut body = Vec::new();
            frame::put_stream(&mut body, u64::from(i) * 4, 0, true, REQUEST);
            send(&mut ep, addr, &peer, i + 1, &body);
            ep.flush_ready();
            assert_eq!(
                responses(&receive(&mut ep, &client, &peer, u64::from(i) + 1)),
                [(u64::from(i) * 4, 0, RESPONSE.to_vec(), true)]
            );
        }
        // ACK PN2 and PN3 separately: neither may lose PN1. Socket output is
        // synchronous and no timer is invoked anywhere in this schedule.
        for pn in 2..=3 {
            ack(&mut ep, addr, &peer, pn + 3, u64::from(pn));
            ep.flush_ready();
            ep.out.flush(&ep.socket).unwrap();
            no_packet(&client);
        }
        ack(&mut ep, addr, &peer, 7, 4);
        if cancel_queued {
            // A late original can cancel even before the ready queue drains.
            ack(&mut ep, addr, &peer, 8, 1);
        }
        ep.flush_ready();
        if !cancel_queued {
            assert_eq!(
                responses(&receive(&mut ep, &client, &peer, 5)),
                [(0, 0, RESPONSE.to_vec(), true)]
            );
            ack(&mut ep, addr, &peer, 8, 1);
            ep.flush_ready();
            // The retry was never ACKed; the original still retires it.
        }
        ep.out.flush(&ep.socket).unwrap();
        no_packet(&client);
        let conn = &ep.conns[&addr].0;
        assert_eq!(transport::state(conn).finished, 4);
        assert_eq!(transport::state(conn).pto_count, 0);
        assert!(!conn.wants_send());
        assert!(conn.timeout().is_none());
        ack(&mut ep, addr, &peer, 9, 1);
        ep.flush_ready();
        assert_eq!(transport::state(&ep.conns[&addr].0).finished, 4);
        ep.out.flush(&ep.socket).unwrap();
        no_packet(&client);
    }
}
