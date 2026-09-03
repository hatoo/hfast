//! One connection: keys, packet numbers, acknowledgement and the handshake
//!
//! rustls does TLS 1.3, the QUIC key schedule and the AEAD. What is here is
//! the transport around it.

use std::sync::Arc;

use rustls::Side;
use rustls::quic::{DirectionalKeys, KeyChange, Keys, ServerConnection, Version};

use super::packet::{self, Kind, Space};
use super::wire::{
    ConnectionId, Error, Result, decode_packet_number, encode_packet_number, protect_header,
    put_varint, unprotect_header,
};
use super::{MAX_DATAGRAM, TAG_LEN, assemble::Assembler, frame, transport};

/// Room a packet's header and tag need before any payload fits
const PACKET_OVERHEAD: usize = 1 + 4 + 1 + ConnectionId::MAX + 1 + ConnectionId::MAX + 1 + 4 + 4;

/// What the peer has sent that we owe an acknowledgement for
#[derive(Default)]
struct AckState {
    /// `(smallest, largest)`, largest first, newest range at the front
    ranges: Vec<(u64, u64)>,
    /// An ack-eliciting packet has arrived that no ACK has covered yet
    owed: bool,
}

impl AckState {
    fn record(&mut self, pn: u64, ack_eliciting: bool) {
        self.owed |= ack_eliciting;
        // Almost always the next one along, which extends the newest range
        if let Some(front) = self.ranges.first_mut() {
            if pn == front.1 + 1 {
                front.1 = pn;
                return;
            }
            if pn >= front.0 && pn <= front.1 {
                return;
            }
        }
        self.insert(pn);
    }

    #[cold]
    fn insert(&mut self, pn: u64) {
        let at = self.ranges.partition_point(|r| r.0 > pn);
        if let Some(r) = self.ranges.get_mut(at)
            && pn >= r.0
            && pn <= r.1
        {
            return;
        }
        self.ranges.insert(at, (pn, pn));
        // An ACK frame that reaches back for ever costs more than it is worth;
        // a peer that has not had one of these acknowledged by now will not.
        self.ranges.truncate(8);
    }
}

/// One packet number space: what has been sent in it and what has arrived
#[derive(Default)]
struct SpaceState {
    next_pn: u64,
    largest_acked: Option<u64>,
    ack: AckState,
    /// TLS bytes still to send, and the offset they start at
    crypto_out: Vec<u8>,
    crypto_offset: u64,
    crypto_in: Assembler,
}

pub struct Connection {
    tls: ServerConnection,
    initial: Option<Keys>,
    handshake: Option<Keys>,
    one_rtt_local: Option<DirectionalKeys>,
    one_rtt_remote: Option<DirectionalKeys>,
    spaces: [SpaceState; 3],
    /// The id this server answers to
    pub local_cid: ConnectionId,
    /// The id the peer answers to
    peer_cid: ConnectionId,
    pub peer: transport::Peer,
    /// 1-RTT keys are in use. rustls hands a server these as soon as it has
    /// answered the ClientHello, so this says nothing about whether the
    /// handshake is confirmed - the older spaces still have a flight to send.
    pub connected: bool,
    handshake_done_sent: bool,
    /// A PATH_CHALLENGE waiting to be answered
    path_response: Option<[u8; 8]>,
    pub closed: bool,
}

impl Connection {
    /// Take up a client's first packet
    ///
    /// `original_dcid` is the id the client made up and addressed that packet
    /// to; the initial keys on both sides come from it, and the client checks
    /// that the server echoes it back in the handshake.
    pub fn accept(
        config: &Arc<rustls::ServerConfig>,
        original_dcid: ConnectionId,
        peer_cid: ConnectionId,
        local_cid: ConnectionId,
        max_streams_bidi: u64,
        initial_max_data: u64,
        initial_max_stream_data: u64,
    ) -> Result<Self> {
        let rustls::SupportedCipherSuite::Tls13(suite) =
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let quic = suite.quic.ok_or(Error)?;
        let initial = Keys::initial(
            Version::V1,
            suite,
            quic,
            original_dcid.as_slice(),
            Side::Server,
        );
        let params = transport::encode(&transport::Local {
            original_dcid,
            initial_scid: local_cid,
            max_streams_bidi,
            initial_max_data,
            initial_max_stream_data,
        });
        let tls = ServerConnection::new(config.clone(), Version::V1, params).map_err(|_| Error)?;
        Ok(Connection {
            tls,
            initial: Some(initial),
            handshake: None,
            one_rtt_local: None,
            one_rtt_remote: None,
            spaces: Default::default(),
            local_cid,
            peer_cid,
            peer: transport::Peer::default(),
            connected: false,
            handshake_done_sent: false,
            path_response: None,
            closed: false,
        })
    }

    fn remote_keys(&self, space: Space) -> Option<&DirectionalKeys> {
        match space {
            Space::Initial => self.initial.as_ref().map(|k| &k.remote),
            Space::Handshake => self.handshake.as_ref().map(|k| &k.remote),
            Space::Data => self.one_rtt_remote.as_ref(),
        }
    }

    fn local_keys(&self, space: Space) -> Option<&DirectionalKeys> {
        match space {
            Space::Initial => self.initial.as_ref().map(|k| &k.local),
            Space::Handshake => self.handshake.as_ref().map(|k| &k.local),
            Space::Data => self.one_rtt_local.as_ref(),
        }
    }

    /// Take in one datagram, which may hold several packets
    pub fn recv(&mut self, datagram: &mut [u8]) -> Result<()> {
        let mut at = 0;
        while at < datagram.len() {
            // A datagram is padded to its end once a packet fails to parse,
            // which is what a run of zeroes after the last packet is
            if datagram[at] == 0 {
                break;
            }
            let (end, kind) = {
                let h = packet::parse(datagram, at)?;
                (h.end, h.kind)
            };
            if kind == Kind::Retry || kind == Kind::ZeroRtt {
                at = end;
                continue;
            }
            let Some(space) = kind.space() else {
                at = end;
                continue;
            };
            // Keys for a space we have not reached yet: the packet is early,
            // and dropping it is allowed - the peer will send it again.
            if self.remote_keys(space).is_none() {
                at = end;
                continue;
            }
            self.recv_packet(&mut datagram[at..end], space)?;
            at = end;
        }
        Ok(())
    }

    fn recv_packet(&mut self, packet: &mut [u8], space: Space) -> Result<()> {
        let pn_offset = {
            let h = packet::parse(packet, 0)?;
            h.pn_offset
        };
        let keys = self.remote_keys(space).ok_or(Error)?;
        let (first, pn_len) = unprotect_header(keys.header.as_ref(), packet, pn_offset)?;
        packet[0] = first;

        let mut truncated = 0u64;
        for b in &packet[pn_offset..pn_offset + pn_len] {
            truncated = (truncated << 8) | *b as u64;
        }
        let st = &mut self.spaces[space as usize];
        let largest = st.ack.ranges.first().map_or(0, |r| r.1);
        let pn = decode_packet_number(largest, truncated, pn_len as u32 * 8);

        let header_end = pn_offset + pn_len;
        let (header, payload) = packet.split_at_mut(header_end);
        let keys = self.remote_keys(space).ok_or(Error)?;
        let plain = keys
            .packet
            .decrypt_in_place(pn, header, payload)
            .map_err(|_| Error)?;
        let plain_len = plain.len();

        // The borrow of `packet` ends here; the frames are read out of a copy
        // of the range so the connection can be mutated while walking them.
        let mut ack_eliciting = false;
        let payload_range = header_end..header_end + plain_len;
        let frames: Vec<_> =
            frame::Frames::new(&packet[payload_range]).collect::<Result<Vec<_>>>()?;
        for f in &frames {
            if !matches!(f, frame::Frame::Ack { .. } | frame::Frame::Padding) {
                ack_eliciting = true;
            }
            self.on_frame(f, space)?;
        }
        self.spaces[space as usize].ack.record(pn, ack_eliciting);
        Ok(())
    }

    fn on_frame(&mut self, f: &frame::Frame<'_>, space: Space) -> Result<()> {
        match *f {
            frame::Frame::Crypto { offset, data } => {
                let st = &mut self.spaces[space as usize];
                st.crypto_in.push(offset, data);
                let taken = st.crypto_in.read().len();
                if taken > 0 {
                    // The borrow checker will not let rustls read out of the
                    // assembler while it is borrowed from self, so the bytes
                    // are handed over as a slice of it first
                    let bytes = st.crypto_in.read().to_vec();
                    st.crypto_in.consume(taken);
                    self.tls.read_hs(&bytes).map_err(|_| Error)?;
                    self.pump_tls();
                }
            }
            frame::Frame::Ack { largest, .. } => {
                let st = &mut self.spaces[space as usize];
                st.largest_acked = Some(st.largest_acked.map_or(largest, |l| l.max(largest)));
            }
            frame::Frame::PathChallenge(data) => self.path_response = Some(data),
            frame::Frame::Close => self.closed = true,
            frame::Frame::MaxData(_)
            | frame::Frame::MaxStreamData { .. }
            | frame::Frame::MaxStreams { .. }
            | frame::Frame::Ping
            | frame::Frame::Padding
            | frame::Frame::Ignored => {}
            // Streams arrive once the handshake is done; the layer above this
            // takes them, and until it exists they are not an error
            frame::Frame::Stream { .. }
            | frame::Frame::StopSending { .. }
            | frame::Frame::ResetStream { .. } => {}
        }
        Ok(())
    }

    /// Collect whatever rustls now has to say, and the keys it hands over
    fn pump_tls(&mut self) {
        loop {
            let space = if self.handshake.is_none() {
                Space::Initial
            } else {
                Space::Handshake
            };
            let mut buf = Vec::new();
            let change = self.tls.write_hs(&mut buf);
            if !buf.is_empty() {
                self.spaces[space as usize]
                    .crypto_out
                    .extend_from_slice(&buf);
            }
            match change {
                Some(KeyChange::Handshake { keys }) => self.handshake = Some(keys),
                Some(KeyChange::OneRtt { keys, .. }) => {
                    self.one_rtt_local = Some(keys.local);
                    self.one_rtt_remote = Some(keys.remote);
                    if let Some(p) = self.tls.quic_transport_parameters()
                        && let Ok(peer) = transport::decode(p)
                    {
                        self.peer = peer;
                    }
                    self.connected = true;
                    return;
                }
                None => return,
            }
        }
    }

    /// Whether anything is waiting to go out
    pub fn wants_send(&self) -> bool {
        self.path_response.is_some()
            || (self.connected && !self.handshake_done_sent)
            || self
                .spaces
                .iter()
                .any(|s| !s.crypto_out.is_empty() || s.ack.owed)
    }

    /// Fill `out` with one datagram's worth of packets
    pub fn poll_transmit(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        let start = out.len();
        for space in [Space::Initial, Space::Handshake, Space::Data] {
            if self.local_keys(space).is_none() {
                continue;
            }
            self.write_packet(out, space, start)?;
        }
        Ok(out.len() > start)
    }

    fn write_packet(
        &mut self,
        out: &mut Vec<u8>,
        space: Space,
        datagram_start: usize,
    ) -> Result<()> {
        let room = MAX_DATAGRAM.saturating_sub(out.len() - datagram_start);
        if room < PACKET_OVERHEAD + 4 {
            return Ok(());
        }
        let body_room = room - PACKET_OVERHEAD;

        // What this packet will say
        let mut body = Vec::with_capacity(body_room.min(MAX_DATAGRAM));
        let st = &mut self.spaces[space as usize];
        if st.ack.owed && !st.ack.ranges.is_empty() {
            frame::put_ack(&mut body, &st.ack.ranges, 0);
            st.ack.owed = false;
        }
        if !st.crypto_out.is_empty() {
            let n = st
                .crypto_out
                .len()
                .min(body_room.saturating_sub(body.len() + 8));
            if n > 0 {
                let chunk: Vec<u8> = st.crypto_out.drain(..n).collect();
                frame::put_crypto(&mut body, st.crypto_offset, &chunk);
                st.crypto_offset += n as u64;
            }
        }
        if space == Space::Data {
            if let Some(data) = self.path_response.take() {
                put_varint(&mut body, frame::PATH_RESPONSE);
                body.extend_from_slice(&data);
            }
            if self.connected && !self.handshake_done_sent {
                put_varint(&mut body, frame::HANDSHAKE_DONE);
                self.handshake_done_sent = true;
            }
        }
        if body.is_empty() {
            return Ok(());
        }
        // Header protection samples 16 bytes starting four past where the
        // packet number begins, so a packet has to carry that much whatever it
        // has to say (RFC 9001 Section 5.4.2). A HANDSHAKE_DONE on its own
        // does not, and padding is what makes up the difference.
        // Reckoned against the shortest a packet number can be, since padding
        // a little more than needed costs nothing and guessing high loses the
        // packet.
        const SAMPLED: usize = 4 + 16;
        if 1 + body.len() + TAG_LEN < SAMPLED {
            body.resize(SAMPLED - TAG_LEN - 1, 0);
        }

        let st = &mut self.spaces[space as usize];
        let pn = st.next_pn;
        st.next_pn += 1;
        let (truncated, pn_len) = encode_packet_number(pn, st.largest_acked);

        let packet_start = out.len();
        let length_at = match space {
            Space::Data => {
                out.push(0x40 | (pn_len as u8 - 1));
                out.extend_from_slice(self.peer_cid.as_slice());
                usize::MAX
            }
            _ => {
                let kind = match space {
                    Space::Initial => Kind::Initial,
                    _ => Kind::Handshake,
                };
                packet::put_long_header(
                    out,
                    kind,
                    &self.peer_cid,
                    &self.local_cid,
                    pn_len,
                    body.len(),
                )
            }
        };
        let pn_offset = out.len();
        out.extend_from_slice(&truncated.to_be_bytes()[8 - pn_len..]);
        let header_end = out.len();
        out.extend_from_slice(&body);

        if length_at != usize::MAX {
            packet::patch_length(out, length_at, (pn_len + body.len() + TAG_LEN) as u64)?;
        }

        let keys = self.local_keys(space).ok_or(Error)?;
        let (header, payload) = out[packet_start..].split_at_mut(header_end - packet_start);
        let tag = keys
            .packet
            .encrypt_in_place(pn, header, payload)
            .map_err(|_| Error)?;
        out.extend_from_slice(tag.as_ref());

        // Header protection samples the ciphertext, so it goes on last
        let keys = self.local_keys(space).ok_or(Error)?;
        protect_header(
            keys.header.as_ref(),
            &mut out[packet_start..],
            pn_offset - packet_start,
            pn_len,
        )?;
        Ok(())
    }
}
