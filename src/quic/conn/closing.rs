//! Terminal transport/application rejection. Cache the protected close for three
//! PTOs, with rate-limited replies to attributable datagrams. Closing metadata
//! is allocated only for rejected connections; normal output cannot resume.

use super::*;

pub(super) struct Closing {
    packet: Vec<u8>,
    initial_dcid: ConnectionId,
    pub(super) deadline: Instant,
    interval: Duration,
    next_reply: Instant,
    minimum_datagram: usize,
    pub(super) pending: bool,
}

impl Closing {
    pub(super) fn new(pto: Duration) -> Self {
        let now = Instant::now();
        Self {
            packet: Vec::new(),
            initial_dcid: ConnectionId::new(&[]).unwrap(),
            deadline: now + 3 * pto,
            interval: pto,
            next_reply: now,
            minimum_datagram: usize::MAX,
            pending: false,
        }
    }

    pub(super) fn needs_packet(&self) -> bool {
        self.packet.is_empty()
    }

    pub(super) fn receive(&mut self, datagram: &[u8], local_cid: ConnectionId) {
        self.receive_at(datagram, local_cid, Instant::now());
    }

    fn receive_at(&mut self, datagram: &[u8], local_cid: ConnectionId, now: Instant) {
        // Keys can be discarded in closing (RFC 9000 10.2.1). Only reply to
        // attributable packets, at most once per PTO. Before a completed
        // handshake the reply cannot exceed the received datagram. Afterwards
        // the address is validated and a minimum-size protected probe suffices:
        // its PING can be shorter than our close, especially with a shorter PN.
        if now < self.next_reply || now >= self.deadline || datagram.len() < self.minimum_datagram {
            return;
        }
        if let Ok(h) = packet::parse(datagram, 0)
            && h.version == packet::VERSION_1
            && (h.dcid == local_cid || (h.kind == Kind::Initial && h.dcid == self.initial_dcid))
        {
            self.pending = true;
        }
    }

    pub(super) fn transmit(&mut self, out: &mut Vec<u8>) -> bool {
        self.transmit_at(out, Instant::now())
    }

    fn transmit_at(&mut self, out: &mut Vec<u8>, now: Instant) -> bool {
        if !self.pending || now >= self.deadline {
            self.pending = false;
            return false;
        }
        out.extend_from_slice(&self.packet);
        self.pending = false;
        self.next_reply = now + self.interval;
        true
    }
}

impl Connection {
    pub(in crate::quic) fn is_closing(&self) -> bool {
        self.closing.is_some()
    }

    pub(super) fn prepare_application_close(&mut self, code: u64) -> Result<()> {
        if self.closing.is_some() {
            return Ok(());
        }
        let keys = self.local_keys(Space::Data).ok_or(Error)?;
        let pn = self.spaces[Space::Data as usize].next_pn;
        let phase = self.key_updates.as_ref().is_some_and(|keys| keys.phase);
        let mut out = vec![0x43 | (u8::from(phase) << 2)];
        out.extend_from_slice(self.peer_cid.as_slice());
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let header_end = out.len();
        out.push(0x1d); // application CONNECTION_CLOSE, no triggering frame type
        put_varint(&mut out, code);
        out.push(0); // empty reason
        let (header, payload) = out.split_at_mut(header_end);
        let tag = keys
            .packet
            .encrypt_in_place(pn, header, payload)
            .map_err(|_| Error)?;
        out.extend_from_slice(tag.as_ref());
        protect_header(keys.header.as_ref(), &mut out, pn_offset, 4)?;
        self.spaces[Space::Data as usize].next_pn += 1;
        let mut close = Closing::new(self.pto());
        close.minimum_datagram = 1 + packet::LOCAL_CID_LEN + 4 + TAG_LEN;
        close.packet = out;
        close.pending = true;
        self.closing = Some(Box::new(close));
        Ok(())
    }

    pub(super) fn prepare_handshake_close(&mut self, initial_dcid: ConnectionId) -> Result<()> {
        let mut out = Vec::new();
        // The peer may not have received ServerHello. Include both Initial
        // and Handshake close packets (RFC 9000 10.2.3), never queued CRYPTO
        // or application frames. 1-RTT keys were deliberately not installed.
        for space in [Space::Initial, Space::Handshake] {
            let Some(keys) = self.local_keys(space) else {
                continue;
            };
            let start = out.len();
            // Transport CONNECTION_CLOSE: TRANSPORT_PARAMETER_ERROR, no
            // triggering frame type, empty reason phrase (RFC 9000 20.1).
            let body = [0x1c, 0x08, 0, 0];
            let length_at = packet::put_long_header(
                &mut out,
                if space == Space::Initial {
                    Kind::Initial
                } else {
                    Kind::Handshake
                },
                &self.peer_cid,
                &self.local_cid,
                4,
                body.len(),
            );
            let pn = self.spaces[space as usize].next_pn;
            let pn_offset = out.len();
            out.extend_from_slice(&(pn as u32).to_be_bytes());
            let end = out.len();
            out.extend_from_slice(&body);
            packet::patch_length(&mut out, length_at, (4 + body.len() + TAG_LEN) as u64)?;
            let (header, payload) = out[start..].split_at_mut(end - start);
            let tag = keys
                .packet
                .encrypt_in_place(pn, header, payload)
                .map_err(|_| Error)?;
            out.extend_from_slice(tag.as_ref());
            protect_header(
                keys.header.as_ref(),
                &mut out[start..],
                pn_offset - start,
                4,
            )?;
            self.spaces[space as usize].next_pn += 1;
        }
        let close = self.closing.as_mut().ok_or(Error)?;
        close.initial_dcid = initial_dcid;
        close.minimum_datagram = out.len();
        close.packet = out;
        close.pending = true;
        for space in [Space::Initial, Space::Handshake, Space::Data] {
            self.discard(space);
        }
        self.initial = None;
        self.handshake = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_replies_are_bounded_attributed_and_stop_at_the_original_deadline() {
        let local = ConnectionId::new(&[3; 8]).unwrap();
        let original = ConnectionId::new(&[1; 8]).unwrap();
        let mut close = Closing::new(Duration::from_millis(100));
        close.initial_dcid = original;
        close.packet = vec![1; 64];
        close.minimum_datagram = close.packet.len();
        close.pending = true;
        let now = close.next_reply;
        let deadline = close.deadline;
        let mut out = vec![9];
        assert!(close.transmit_at(&mut out, now));
        assert_eq!(&out[..1], &[9]);
        assert_eq!(&out[1..], close.packet);
        assert!(!close.transmit_at(&mut out, now));

        let mut incoming = vec![0x43];
        incoming.extend_from_slice(local.as_slice());
        incoming.resize(64, 0);
        close.receive_at(&incoming, local, now);
        assert!(!close.pending);
        let retry = now + close.interval;
        close.receive_at(&incoming[..63], local, retry);
        assert!(!close.pending, "small packets must not amplify replies");
        incoming[1] ^= 1;
        close.receive_at(&incoming, local, retry);
        assert!(!close.pending, "wrong destination must not trigger a reply");
        incoming[1] ^= 1;
        close.receive_at(&incoming, local, retry);
        out.clear();
        assert!(close.transmit_at(&mut out, retry));
        assert_eq!(out, close.packet);
        assert_eq!(close.deadline, deadline);

        let mut initial = Vec::new();
        let length_at =
            packet::put_long_header(&mut initial, Kind::Initial, &original, &local, 4, 32);
        let header_end = initial.len();
        initial.resize(128, 0);
        packet::patch_length(&mut initial, length_at, (128 - header_end) as u64).unwrap();
        close.receive_at(&initial, local, retry + close.interval);
        assert!(
            close.pending,
            "lost close can be retried for the original Initial"
        );
        out.clear();
        assert!(!close.transmit_at(&mut out, deadline));
        assert!(out.is_empty());
        close.receive_at(&initial, local, deadline);
        assert!(!close.pending);
    }

    #[test]
    fn validated_application_close_answers_minimum_size_probes() {
        let local = ConnectionId::new(&[3; 8]).unwrap();
        let mut close = Closing::new(Duration::from_millis(100));
        close.packet = vec![1; 33];
        close.minimum_datagram = 1 + packet::LOCAL_CID_LEN + 4 + TAG_LEN;
        let mut probe = vec![0x43];
        probe.extend_from_slice(local.as_slice());
        probe.resize(close.minimum_datagram, 0);
        let now = close.next_reply;
        close.receive_at(&probe[..probe.len() - 1], local, now);
        assert!(!close.pending);
        close.receive_at(&probe, local, now);
        let mut out = Vec::new();
        assert!(close.transmit_at(&mut out, now));
        assert_eq!(out, close.packet);
        close.receive_at(&probe, local, now);
        assert!(!close.pending);
        close.receive_at(&probe, local, now + close.interval);
        assert!(close.pending);
    }
}
