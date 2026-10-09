//! One connection: keys, packet numbers, acknowledgement and the handshake
//!
//! rustls does TLS 1.3, the QUIC key schedule and the AEAD. What is here is
//! the transport around it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::Side;
use rustls::quic::{DirectionalKeys, KeyChange, Keys, ServerConnection, Version};

use super::packet::{self, Kind, Space};
use super::wire::{
    ConnectionId, Error, Result, decode_packet_number, encode_packet_number, protect_header,
    put_varint, unprotect_header, varint_len,
};
use super::{MAX_DATAGRAM, TAG_LEN, assemble::Assembler, frame, transport};

/// Stream type 0 (control) and an empty SETTINGS frame, which RFC 9114
/// Sections 6.2 and 7.2.4 require to be the first thing a server says. It has
/// nothing to say in it.
const CONTROL_PRELUDE: &[u8] = b"\x00\x04\x00";

/// The one answer this server gives, framed for HTTP/3: a HEADERS frame
/// carrying a QPACK field section against the static table only, then a DATA
/// frame carrying the body. See `h3.rs` for what each byte is.
const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

/// The uni stream this server opens for its control stream. Server-initiated
/// unidirectional streams are 3, 7, 11 (RFC 9000 Section 2.1) and this opens
/// exactly one.
const CONTROL_STREAM: u64 = 3;

/// A request stream. Nothing about a request changes the answer, so the only
/// thing worth keeping is how far it got.
#[derive(Default)]
struct Request {
    /// The largest offset seen, which is the request's size once it ends
    size: u64,
    /// The client has said where the request ends
    fin: bool,
    /// The answer has been queued
    answered: bool,
}

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

    /// Out of order, or filling a gap. Ranges are kept largest first, and one
    /// that ends up next to another is joined to it: an ACK frame is a list of
    /// gaps, so two ranges with nothing between them cost a frame more to say
    /// and mean the same thing.
    #[cold]
    fn insert(&mut self, pn: u64) {
        let at = self.ranges.partition_point(|r| r.0 > pn);
        if let Some(r) = self.ranges.get(at)
            && pn >= r.0
            && pn <= r.1
        {
            return;
        }
        let joins_above = at > 0 && self.ranges[at - 1].0 == pn + 1;
        let joins_below = self.ranges.get(at).is_some_and(|r| r.1 + 1 == pn);
        match (joins_above, joins_below) {
            (true, true) => {
                self.ranges[at - 1].0 = self.ranges[at].0;
                self.ranges.remove(at);
            }
            (true, false) => self.ranges[at - 1].0 = pn,
            (false, true) => self.ranges[at].1 = pn,
            (false, false) => self.ranges.insert(at, (pn, pn)),
        }
        // Reaching back for ever costs more than it is worth: a peer that has
        // not had one of these acknowledged by now will not.
        self.ranges.truncate(8);
    }
}

/// A CRYPTO range and every packet that carried it. Keeping earlier packet
/// numbers lets a late ACK cancel a queued probe or a retransmitted copy.
struct CryptoFlight {
    sent_in: Vec<u64>,
    offset: u64,
    data: Vec<u8>,
    pending: bool,
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
    /// TLS bytes handed to a packet that has not been acknowledged, and the
    /// packet they went in. A handshake flight is a few of these at most.
    crypto_flight: Vec<CryptoFlight>,
    /// When the oldest unacknowledged packet in this space went out
    oldest_sent: Option<Instant>,
}

impl SpaceState {
    fn write_crypto(&mut self, body: &mut Vec<u8>, body_room: usize, pn: u64) {
        let retry = self.crypto_flight.iter().position(|f| f.pending);
        if retry.is_none() && self.crypto_out.is_empty() {
            return;
        }
        let offset = retry.map_or(self.crypto_offset, |i| self.crypto_flight[i].offset);
        // Use the available room's length encoding as an upper bound, so even
        // a large CRYPTO offset cannot make the frame exceed the packet.
        let room = body_room
            .saturating_sub(body.len() + 1 + varint_len(offset) + varint_len(body_room as u64));
        if room == 0 {
            return;
        }
        if let Some(i) = retry {
            let flight = &mut self.crypto_flight[i];
            if flight.data.len() > room {
                // ACKs can take more space in a probe than in the original
                // packet. Both pieces inherit the earlier transmissions.
                let tail = CryptoFlight {
                    sent_in: flight.sent_in.clone(),
                    offset: flight.offset + room as u64,
                    data: flight.data.split_off(room),
                    pending: true,
                };
                self.crypto_flight.insert(i + 1, tail);
            }
            let flight = &mut self.crypto_flight[i];
            frame::put_crypto(body, flight.offset, &flight.data);
            flight.sent_in.push(pn);
            flight.pending = false;
        } else if !self.crypto_out.is_empty() {
            let n = self.crypto_out.len().min(room);
            let chunk: Vec<u8> = self.crypto_out.drain(..n).collect();
            frame::put_crypto(body, self.crypto_offset, &chunk);
            self.crypto_flight.push(CryptoFlight {
                sent_in: vec![pn],
                offset: self.crypto_offset,
                data: chunk,
                pending: false,
            });
            self.crypto_offset += n as u64;
        }
    }
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

    // ---- streams ----
    /// Client bidirectional streams, which requests are, indexed by number
    /// from `base_stream`. A stream id says where its stream is, so nothing is
    /// searched for.
    streams: Vec<Option<Request>>,
    base_stream: u64,
    /// Streams whose answer is written but not yet in a packet
    ready: Vec<u64>,
    /// `(packet number, stream)` for every answer sent and not yet
    /// acknowledged, so a lost one can be sent again
    unacked: Vec<(u64, u64)>,
    /// Scratch ranges reused as ACK frames arrive.
    ack_ranges: Vec<(u64, u64)>,
    /// Packet assembly storage, returned here after each transmit attempt.
    packet_body: Vec<u8>,
    /// How much of the control stream has gone out
    control_sent: usize,
    /// Requests finished, which is the credit the client gets back
    finished: u64,
    /// The largest stream count and data limit told to the client
    streams_told: u64,
    data_told: u64,
    /// Bytes the client has sent us across all streams
    data_seen: u64,
    max_streams_bidi: u64,
    initial_max_data: u64,

    // ---- loss recovery ----
    /// Smoothed round trip time, and how much it varies (RFC 9002 Section 5)
    srtt: Duration,
    rttvar: Duration,
    /// When the packet a round trip is being measured from went out
    rtt_probe: Option<(Space, u64, Instant)>,
    /// How many probe timeouts have fired in a row without an acknowledgement,
    /// which is what backs the timer off
    pto_count: u32,
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
            streams: Vec::new(),
            base_stream: 0,
            ready: Vec::new(),
            unacked: Vec::new(),
            ack_ranges: Vec::new(),
            packet_body: Vec::new(),
            control_sent: 0,
            finished: 0,
            streams_told: max_streams_bidi,
            data_told: initial_max_data,
            data_seen: 0,
            max_streams_bidi,
            initial_max_data,
            // RFC 9002 Section 6.2.2: 333ms until a round trip has been seen
            srtt: Duration::from_millis(333),
            rttvar: Duration::from_millis(166),
            rtt_probe: None,
            pto_count: 0,
        })
    }

    /// The slot for a client bidirectional stream, made if it is new
    ///
    /// Client bidirectional streams are 0, 4, 8 (RFC 9000 Section 2.1), so the
    /// id says which slot without anything being searched for.
    fn stream_mut(&mut self, id: u64) -> Option<&mut Request> {
        if id & 3 != 0 {
            return None;
        }
        let n = id >> 2;
        let i = usize::try_from(n.checked_sub(self.base_stream)?).ok()?;
        // A client that opens more than it was allowed is not answered
        if i >= self.max_streams_bidi as usize + self.streams.len() {
            return None;
        }
        if i >= self.streams.len() {
            self.streams.resize_with(i + 1, || None);
        }
        Some(self.streams[i].get_or_insert_with(Request::default))
    }

    /// Forget the streams at the front that have been answered and
    /// acknowledged, so the table does not grow for the life of the run
    fn retire(&mut self) {
        let n = self
            .streams
            .iter()
            .position(|s| s.is_some())
            .unwrap_or(self.streams.len());
        if n > 0 {
            // Counted first and shifted once: taking them off the front one at
            // a time would move the rest as many times as there are of them
            self.streams.drain(..n);
            self.base_stream += n as u64;
        }
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
            // RFC 9001 Section 4.9.1: a Handshake packet from the client
            // proves it has moved on, and the Initial space is done with
            if space == Space::Handshake {
                self.discard(Space::Initial);
                self.initial = None;
            }
            // Section 4.9.2: once the handshake is complete the Handshake
            // space is done too. Holding on to either means sending packets
            // the peer threw away the keys for, for ever.
            if self.handshake.is_some() && !self.tls.is_handshaking() {
                self.discard(Space::Handshake);
                self.handshake = None;
            }
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

        // The caller owns packet independently of the connection. Consume
        // borrowed frames directly instead of allocating a list per packet.
        let mut ack_eliciting = false;
        let payload_range = header_end..header_end + plain_len;
        for f in frame::Frames::new(&packet[payload_range]) {
            let f = f?;
            if !matches!(f, frame::Frame::Ack { .. } | frame::Frame::Padding) {
                ack_eliciting = true;
            }
            self.on_frame(&f, space)?;
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
            frame::Frame::Ack {
                largest,
                first_range,
                rest,
                ..
            } => {
                let st = &mut self.spaces[space as usize];
                st.largest_acked = Some(st.largest_acked.map_or(largest, |l| l.max(largest)));
                let acknowledged = |pn| {
                    frame::AckRanges::new(largest, first_range, rest)
                        .any(|(lo, hi)| pn >= lo && pn <= hi)
                };
                let before = st.crypto_flight.len();
                st.crypto_flight
                    .retain(|f| !f.sent_in.iter().copied().any(acknowledged));
                let mut progress = st.crypto_flight.len() < before;
                if let Some((probe_space, pn, at)) = self.rtt_probe
                    && probe_space == space
                    && acknowledged(pn)
                {
                    self.rtt_probe = None;
                    progress = true;
                    // The ACK delay describes only the largest acknowledged
                    // packet (RFC 9002 Section 5.1).
                    if pn == largest {
                        self.on_rtt(Instant::now() - at);
                    }
                }
                if space == Space::Data && !self.unacked.is_empty() {
                    progress |= self.on_ack(largest, first_range, rest);
                }
                if progress {
                    self.pto_count = 0;
                    self.settle_timer(space, Instant::now());
                }
            }
            frame::Frame::PathChallenge(data) => self.path_response = Some(data),
            frame::Frame::Close => self.closed = true,
            frame::Frame::MaxData(_)
            | frame::Frame::MaxStreamData { .. }
            | frame::Frame::MaxStreams { .. }
            | frame::Frame::Ping
            | frame::Frame::Padding
            | frame::Frame::Ignored => {}
            frame::Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => self.on_stream(id, offset, data, fin),
            // A client that gives up on a stream is answered by forgetting it
            frame::Frame::StopSending { id } | frame::Frame::ResetStream { id } => {
                if let Some(i) = (id >> 2)
                    .checked_sub(self.base_stream)
                    .and_then(|n| usize::try_from(n).ok())
                    && i < self.streams.len()
                {
                    self.streams[i] = None;
                    self.finished += 1;
                    self.retire();
                }
            }
        }
        Ok(())
    }

    /// A request stream, or one of the client's own unidirectional streams
    ///
    /// The bytes are not read. A request's stream id is what says which stream
    /// to answer on, and its end is what says to answer at all; nothing in it
    /// changes the answer, so nothing in it is put back together.
    fn on_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) {
        let end = offset + data.len() as u64;
        let Some(req) = self.stream_mut(id) else {
            // The client's control and QPACK streams. They have to be counted
            // against the connection's flow control and read no further:
            // neither side may insert into a table both said has no room.
            self.data_seen += data.len() as u64;
            return;
        };
        let fresh = end.saturating_sub(req.size);
        req.size = req.size.max(end);
        req.fin |= fin;
        let answer = req.fin && !req.answered;
        req.answered |= answer;
        self.data_seen += fresh;
        if answer {
            self.ready.push(id);
        }
    }

    /// Retire every answer the peer has acknowledged, and send again the ones
    /// far enough behind an acknowledged packet to be lost
    ///
    /// RFC 9002 Section 6.1.1: three packets acknowledged after one is enough
    /// to call it lost, and waiting for the probe timer instead is the
    /// difference between recovering in a round trip and recovering in tens of
    /// milliseconds.
    const LOSS_THRESHOLD: u64 = 3;

    fn on_ack(&mut self, largest: u64, first_range: u64, rest: &[u8]) -> bool {
        let ranges = &mut self.ack_ranges;
        ranges.clear();
        ranges.extend(frame::AckRanges::new(largest, first_range, rest));
        let mut retired = false;
        let mut acknowledged = false;
        let lost_before = largest.saturating_sub(Self::LOSS_THRESHOLD);
        let ready = &mut self.ready;
        let streams = &mut self.streams;
        let base = self.base_stream;
        let mut finished = self.finished;
        self.unacked.retain(|&(pn, id)| {
            if !ranges.iter().any(|&(lo, hi)| pn >= lo && pn <= hi) {
                if pn < lost_before {
                    ready.push(id);
                    return false;
                }
                return true;
            }
            acknowledged = true;
            if let Some(i) = (id >> 2)
                .checked_sub(base)
                .and_then(|n| usize::try_from(n).ok())
                && i < streams.len()
            {
                streams[i] = None;
                finished += 1;
                retired = true;
            }
            false
        });
        self.finished = finished;
        if retired {
            self.retire();
        }
        acknowledged
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
        !self.ready.is_empty()
            || self.path_response.is_some()
            || (!self.tls.is_handshaking() && !self.handshake_done_sent)
            || (self.connected && self.control_sent < CONTROL_PRELUDE.len())
            || self.credit_owed()
            || self.spaces.iter().any(|s| {
                !s.crypto_out.is_empty() || s.crypto_flight.iter().any(|f| f.pending) || s.ack.owed
            })
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

    /// What the client may open and send by now
    fn streams_limit(&self) -> u64 {
        self.max_streams_bidi + self.finished
    }

    fn data_limit(&self) -> u64 {
        self.initial_max_data + self.data_seen
    }

    /// Whether a credit has grown enough to be worth a frame. Half a window at
    /// a time keeps the client from ever waiting without saying so on every
    /// request.
    fn credit_owed(&self) -> bool {
        self.streams_limit() >= self.streams_told + self.max_streams_bidi / 2
            || self.data_limit() >= self.data_told + self.initial_max_data / 2
    }

    /// The 1-RTT payload: the control stream, credit, and answers
    fn write_data(&mut self, body: &mut Vec<u8>, body_room: usize, pn: u64) {
        if self.control_sent < CONTROL_PRELUDE.len() {
            frame::put_stream(body, CONTROL_STREAM, 0, false, CONTROL_PRELUDE);
            self.control_sent = CONTROL_PRELUDE.len();
        }
        if self.streams_limit() >= self.streams_told + self.max_streams_bidi / 2 {
            self.streams_told = self.streams_limit();
            put_varint(body, frame::MAX_STREAMS_BIDI);
            put_varint(body, self.streams_told);
        }
        if self.data_limit() >= self.data_told + self.initial_max_data / 2 {
            self.data_told = self.data_limit();
            put_varint(body, frame::MAX_DATA);
            put_varint(body, self.data_told);
        }
        // Answers, as many as the packet holds. They go out newest first,
        // which costs nothing: every one of them is the same answer.
        while let Some(&id) = self.ready.last() {
            let need = frame::stream_overhead(id, 0, RESPONSE.len()) + RESPONSE.len();
            if body.len() + need > body_room {
                break;
            }
            self.ready.pop();
            frame::put_stream(body, id, 0, true, RESPONSE);
            self.unacked.push((pn, id));
        }
    }

    fn write_packet(
        &mut self,
        out: &mut Vec<u8>,
        space: Space,
        datagram_start: usize,
    ) -> Result<()> {
        // Take the scratch storage out so write_data can still mutate the
        // connection. Restore it on errors and empty packets as well.
        let mut body = std::mem::take(&mut self.packet_body);
        body.clear();
        let result = self.write_packet_into(out, space, datagram_start, &mut body);
        self.packet_body = body;
        result
    }

    fn write_packet_into(
        &mut self,
        out: &mut Vec<u8>,
        space: Space,
        datagram_start: usize,
        body: &mut Vec<u8>,
    ) -> Result<()> {
        let room = MAX_DATAGRAM.saturating_sub(out.len() - datagram_start);
        if room < PACKET_OVERHEAD + 4 {
            return Ok(());
        }
        let body_room = room - PACKET_OVERHEAD;

        // The packet number is needed while the body is built, because an
        // answer written into it has to be remembered against the packet it
        // went in. It is only spent if the packet turns out to have something
        // in it.
        let pn = self.spaces[space as usize].next_pn;

        body.reserve(body_room.min(MAX_DATAGRAM));
        let st = &mut self.spaces[space as usize];
        if st.ack.owed && !st.ack.ranges.is_empty() {
            frame::put_ack(body, &st.ack.ranges, 0);
            st.ack.owed = false;
        }
        let ack_only_len = body.len();
        st.write_crypto(body, body_room, pn);
        if space == Space::Data {
            if let Some(data) = self.path_response.take() {
                put_varint(body, frame::PATH_RESPONSE);
                body.extend_from_slice(&data);
            }
            // RFC 9001 Section 4.1.2: this says the handshake is confirmed,
            // which it is not until the client's Finished has arrived. Sending
            // it as soon as rustls hands over 1-RTT keys tells the client it is
            // done before it is, so it throws away its handshake keys and never
            // sends the Finished at all - and then nothing ever confirms.
            if !self.tls.is_handshaking() && !self.handshake_done_sent {
                put_varint(body, frame::HANDSHAKE_DONE);
                self.handshake_done_sent = true;
            }
            self.write_data(body, body_room, pn);
        }
        if body.is_empty() {
            return Ok(());
        }
        let ack_eliciting = body.len() > ack_only_len;
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
        out.extend_from_slice(body);

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

        // A packet carrying nothing but an acknowledgement is not itself
        // acknowledged, so waiting for one would be waiting for ever
        if ack_eliciting {
            let now = Instant::now();
            self.spaces[space as usize].oldest_sent.get_or_insert(now);
            if self.rtt_probe.is_none() {
                self.rtt_probe = Some((space, pn, now));
            }
        }
        Ok(())
    }

    /// When to give up waiting and send what has not been acknowledged again
    ///
    /// RFC 9002 Section 6.2. This is the fallback, not the usual way a loss is
    /// noticed: three packets acknowledged past one is what normally catches
    /// it, and this only has to be short enough that a connection with nothing
    /// left in flight to trigger that does not sit there. Making it tight
    /// instead turns every quiet moment into a resend of everything.
    pub fn timeout(&self) -> Option<Instant> {
        let oldest = self.spaces.iter().filter_map(|s| s.oldest_sent).min()?;
        let pto = (self.srtt
            + (4 * self.rttvar).max(Duration::from_millis(1))
            + Duration::from_millis(25))
            * (1 << self.pto_count.min(6));
        Some(oldest + pto)
    }

    /// Put back everything still in flight, to be sent again
    pub fn on_timeout(&mut self, now: Instant) {
        if self.timeout().is_none_or(|t| now < t) {
            return;
        }
        self.pto_count = self.pto_count.saturating_add(1);
        self.rtt_probe = None;
        for st in &mut self.spaces {
            st.oldest_sent = None;
            // An ACK can leave holes between CRYPTO ranges. Retransmit each
            // at its original offset without rewinding the unsent TLS bytes.
            for flight in &mut st.crypto_flight {
                flight.pending = true;
            }
        }
        // An answer that was not acknowledged is queued to go again
        for (_, id) in self.unacked.drain(..) {
            self.ready.push(id);
        }
    }

    /// Forget a space: its keys are gone, so nothing in it can be sent or
    /// acknowledged any more
    fn discard(&mut self, space: Space) {
        let st = &mut self.spaces[space as usize];
        st.crypto_out.clear();
        st.crypto_flight.clear();
        st.ack.ranges.clear();
        st.ack.owed = false;
        st.oldest_sent = None;
        if self.rtt_probe.is_some_and(|(s, _, _)| s == space) {
            self.rtt_probe = None;
        }
    }

    /// Whether this space is waiting on an acknowledgement for anything
    fn in_flight(&self, space: Space) -> bool {
        !self.spaces[space as usize].crypto_flight.is_empty()
            || (space == Space::Data && !self.unacked.is_empty())
    }

    /// An acknowledgement arrived: the timer either has nothing left to wait
    /// for, or starts again from now for whatever is still out there
    fn settle_timer(&mut self, space: Space, now: Instant) {
        let running = self.in_flight(space).then_some(now);
        self.spaces[space as usize].oldest_sent = running;
    }

    /// Fold a round trip sample in (RFC 9002 Section 5.3)
    fn on_rtt(&mut self, sample: Duration) {
        let var = self.srtt.abs_diff(sample);
        self.rttvar = (self.rttvar * 3 + var) / 4;
        self.srtt = (self.srtt * 7 + sample) / 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
        Connection::accept(
            &Arc::new(config),
            ConnectionId::new(&[1; 8]).unwrap(),
            ConnectionId::new(&[2; 8]).unwrap(),
            ConnectionId::new(&[3; 8]).unwrap(),
            64,
            1 << 30,
            1 << 24,
        )
        .unwrap()
    }

    #[test]
    fn successive_packets_decrypt_without_previous_payload_bytes() {
        let mut conn = connection();
        let rustls::SupportedCipherSuite::Tls13(suite) =
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let client_keys = Keys::initial(
            Version::V1,
            suite,
            suite.quic.unwrap(),
            &[1; 8],
            Side::Client,
        );
        let mut out = Vec::new();
        for (pn, largest) in [7, 100, 1000].into_iter().enumerate() {
            let ack = &mut conn.spaces[Space::Initial as usize].ack;
            ack.ranges.clear();
            ack.record(largest, true);
            out.clear();
            assert!(conn.poll_transmit(&mut out).unwrap());
            let header = packet::parse(&out, 0).unwrap();
            assert_eq!(header.end, out.len());
            let (_, pn_len) = unprotect_header(
                client_keys.remote.header.as_ref(),
                &mut out,
                header.pn_offset,
            )
            .unwrap();
            let (head, body) = out.split_at_mut(header.pn_offset + pn_len);
            let plain = client_keys
                .remote
                .packet
                .decrypt_in_place(pn as u64, head, body)
                .unwrap();
            let frames = frame::Frames::new(plain)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert!(
                matches!(frames.as_slice(), [frame::Frame::Ack { largest: n, .. }] if *n == largest)
            );
            out.clear();
            assert!(!conn.poll_transmit(&mut out).unwrap());
            assert!(out.is_empty());
        }
    }

    #[test]
    fn successive_acks_only_retire_their_own_ranges() {
        let mut conn = connection();
        for id in [0, 4, 8] {
            conn.on_stream(id, 0, b"request", true);
        }
        conn.ready.clear();
        conn.unacked = vec![(10, 0), (11, 4), (12, 8)];
        conn.on_ack(11, 0, &[]);
        assert_eq!(conn.unacked, [(10, 0), (12, 8)]);
        assert_eq!(conn.finished, 1);
        conn.on_ack(10, 0, &[]);
        assert_eq!(conn.unacked, [(12, 8)]);
        assert_eq!(conn.finished, 2);
        conn.on_ack(12, 0, &[]);
        assert!(conn.unacked.is_empty());
        assert!(conn.streams.is_empty());
        assert_eq!(conn.finished, 3);
    }

    fn acknowledge(conn: &mut Connection, space: Space, ranges: &[(u64, u64)]) {
        let mut bytes = Vec::new();
        frame::put_ack(&mut bytes, ranges, 0);
        let ack = frame::Frames::new(&bytes).next().unwrap().unwrap();
        conn.on_frame(&ack, space).unwrap();
    }

    fn send_crypto(conn: &mut Connection) -> Vec<(u64, Vec<u8>)> {
        let pn = conn.spaces[Space::Initial as usize].next_pn;
        let mut packet = Vec::new();
        assert!(conn.poll_transmit(&mut packet).unwrap());
        let header = packet::parse(&packet, 0).unwrap();
        assert_eq!(header.end, packet.len());
        let keys = conn.local_keys(Space::Initial).unwrap();
        let (_, pn_len) =
            unprotect_header(keys.header.as_ref(), &mut packet, header.pn_offset).unwrap();
        let (head, body) = packet.split_at_mut(header.pn_offset + pn_len);
        let plain = keys.packet.decrypt_in_place(pn, head, body).unwrap();
        frame::Frames::new(plain)
            .filter_map(|f| match f.unwrap() {
                frame::Frame::Crypto { offset, data } => Some((offset, data.to_vec())),
                frame::Frame::Ack { .. } | frame::Frame::Padding => None,
                other => panic!("unexpected frame: {other:?}"),
            })
            .collect()
    }

    fn crypto_connection() -> Connection {
        let mut conn = connection();
        conn.spaces[Space::Initial as usize].next_pn = 10;
        for data in [b"first".as_slice(), b"middle", b"last"] {
            conn.spaces[Space::Initial as usize]
                .crypto_out
                .extend_from_slice(data);
            send_crypto(&mut conn);
        }
        conn
    }

    #[test]
    fn sparse_crypto_ack_keeps_gaps_and_rtt_probe() {
        let mut conn = crypto_connection();
        let probe = conn.rtt_probe;
        let rtt = (conn.srtt, conn.rttvar);
        acknowledge(&mut conn, Space::Initial, &[(12, 12)]);
        assert_eq!(conn.spaces[0].crypto_flight.len(), 2);
        assert_eq!(conn.rtt_probe, probe);
        assert_eq!((conn.srtt, conn.rttvar), rtt);
        conn.on_timeout(conn.timeout().unwrap());
        assert_eq!(send_crypto(&mut conn), [(0, b"first".to_vec())]);
        assert_eq!(send_crypto(&mut conn), [(5, b"middle".to_vec())]);
    }

    #[test]
    fn crypto_pto_preserves_holes_and_unsent_offsets() {
        let mut conn = crypto_connection();
        acknowledge(&mut conn, Space::Initial, &[(11, 11)]);
        conn.spaces[0].crypto_out.extend_from_slice(b"new");
        conn.on_timeout(conn.timeout().unwrap());
        assert_eq!(send_crypto(&mut conn), [(0, b"first".to_vec())]);
        assert_eq!(send_crypto(&mut conn), [(11, b"last".to_vec())]);
        assert_eq!(send_crypto(&mut conn), [(15, b"new".to_vec())]);
        assert!(!conn.wants_send());
    }

    #[test]
    fn duplicate_crypto_ack_does_not_reset_pto() {
        let mut conn = crypto_connection();
        acknowledge(&mut conn, Space::Initial, &[(11, 11)]);
        conn.on_timeout(conn.timeout().unwrap());
        send_crypto(&mut conn);
        let deadline = conn.timeout();
        assert_eq!(conn.pto_count, 1);
        acknowledge(&mut conn, Space::Initial, &[(11, 11)]);
        assert_eq!(conn.pto_count, 1);
        assert_eq!(conn.timeout(), deadline);
    }

    #[test]
    fn late_crypto_ack_retires_retransmitted_and_queued_copies() {
        let mut conn = crypto_connection();
        conn.on_timeout(conn.timeout().unwrap());
        send_crypto(&mut conn);
        // The original pn10 and queued pn12 are covered, but pn11 is not.
        acknowledge(&mut conn, Space::Initial, &[(12, 12), (10, 10)]);
        assert_eq!(conn.spaces[0].crypto_flight.len(), 1);
        assert_eq!(send_crypto(&mut conn), [(5, b"middle".to_vec())]);
        acknowledge(&mut conn, Space::Initial, &[(11, 11)]);
        assert!(conn.spaces[0].crypto_flight.is_empty());
        assert!(!conn.wants_send());
        assert!(conn.timeout().is_none());
    }

    #[test]
    fn crypto_probe_split_keeps_original_transmission_and_offset() {
        let mut conn = connection();
        let data: Vec<_> = (0..2000).map(|i| (i % 251) as u8).collect();
        conn.spaces[0].crypto_out.extend_from_slice(&data);
        let original = send_crypto(&mut conn);
        let original_len = original[0].1.len();
        conn.on_timeout(conn.timeout().unwrap());
        // A larger ACK leaves less room than the original CRYPTO packet had.
        for pn in (100..116).step_by(2) {
            conn.spaces[0].ack.record(pn, true);
        }
        let first = send_crypto(&mut conn);
        let split = first[0].1.len();
        assert!(split < original_len);
        assert_eq!(first, [(0, data[..split].to_vec())]);
        // ACK the new, smaller packet. Only its prefix is delivered.
        acknowledge(&mut conn, Space::Initial, &[(1, 1)]);
        assert_eq!(
            send_crypto(&mut conn),
            [(split as u64, data[split..original_len].to_vec())]
        );
        // A late ACK of the original also covers its retransmitted tail.
        acknowledge(&mut conn, Space::Initial, &[(0, 0)]);
        assert!(conn.spaces[0].crypto_flight.is_empty());
        assert_eq!(
            send_crypto(&mut conn),
            [(original_len as u64, data[original_len..].to_vec())]
        );
    }

    #[test]
    fn crypto_repeated_pto_and_ack_of_retransmission() {
        let mut conn = crypto_connection();
        let deadline = conn.timeout().unwrap();
        conn.on_timeout(deadline - Duration::from_nanos(1));
        assert_eq!(conn.pto_count, 0);
        assert!(!conn.wants_send());
        conn.on_timeout(deadline);
        assert_eq!(send_crypto(&mut conn), [(0, b"first".to_vec())]);
        conn.on_timeout(conn.timeout().unwrap());
        assert_eq!(conn.pto_count, 2);
        assert_eq!(send_crypto(&mut conn), [(0, b"first".to_vec())]);
        // The first probe is still sufficient, even after the second probe.
        acknowledge(&mut conn, Space::Initial, &[(13, 13)]);
        assert_eq!(conn.pto_count, 0);
        assert_eq!(conn.spaces[0].crypto_flight.len(), 2);
        assert_eq!(send_crypto(&mut conn), [(5, b"middle".to_vec())]);
        assert_eq!(send_crypto(&mut conn), [(11, b"last".to_vec())]);
        acknowledge(&mut conn, Space::Initial, &[(15, 16)]);
        assert!(conn.timeout().is_none());
        assert!(!conn.wants_send());
    }

    #[test]
    fn crypto_ack_is_scoped_to_its_packet_number_space() {
        let mut conn = crypto_connection();
        let probe = conn.rtt_probe;
        let deadline = conn.timeout();
        acknowledge(&mut conn, Space::Handshake, &[(10, 12)]);
        assert_eq!(conn.spaces[0].crypto_flight.len(), 3);
        assert_eq!(conn.rtt_probe, probe);
        assert_eq!(conn.timeout(), deadline);
        acknowledge(&mut conn, Space::Initial, &[(10, 12)]);
        assert!(conn.spaces[0].crypto_flight.is_empty());
        assert!(conn.timeout().is_none());
    }

    #[test]
    fn crypto_rtt_sample_requires_the_largest_acknowledged_packet() {
        let mut conn = crypto_connection();
        let rtt = (conn.srtt, conn.rttvar);
        acknowledge(&mut conn, Space::Initial, &[(12, 12), (10, 10)]);
        assert!(conn.rtt_probe.is_none());
        assert_eq!((conn.srtt, conn.rttvar), rtt);
        conn.spaces[0].crypto_out.extend_from_slice(b"new");
        send_crypto(&mut conn);
        acknowledge(&mut conn, Space::Initial, &[(13, 13)]);
        assert_ne!((conn.srtt, conn.rttvar), rtt);
        let rtt = (conn.srtt, conn.rttvar);
        acknowledge(&mut conn, Space::Initial, &[(13, 13)]);
        assert_eq!((conn.srtt, conn.rttvar), rtt);
    }

    #[test]
    fn discard_cancels_queued_crypto_probes() {
        let mut conn = crypto_connection();
        conn.spaces[0].crypto_out.extend_from_slice(b"unsent");
        conn.on_timeout(conn.timeout().unwrap());
        assert!(conn.wants_send());
        conn.discard(Space::Initial);
        assert!(!conn.wants_send());
        assert!(conn.timeout().is_none());
        assert!(conn.spaces[0].crypto_flight.is_empty());
        let mut out = Vec::new();
        assert!(!conn.poll_transmit(&mut out).unwrap());
    }

    #[test]
    fn duplicate_data_ack_does_not_postpone_recovery() {
        let mut conn = connection();
        for id in [0, 4, 8] {
            conn.on_stream(id, 0, b"request", true);
        }
        conn.ready.clear();
        conn.unacked = vec![(10, 0), (11, 4), (12, 8)];
        acknowledge(&mut conn, Space::Data, &[(12, 12)]);
        let deadline = conn.timeout();
        conn.pto_count = 2;
        acknowledge(&mut conn, Space::Data, &[(12, 12)]);
        assert_eq!(conn.pto_count, 2);
        conn.pto_count = 0;
        assert_eq!(conn.timeout(), deadline);
        assert_eq!(conn.unacked, [(10, 0), (11, 4)]);
    }

    #[test]
    fn acknowledgement_ranges_grow_from_the_newest_end() {
        let mut a = AckState::default();
        for pn in [0u64, 1, 2, 3] {
            a.record(pn, true);
        }
        assert_eq!(a.ranges, [(0, 3)], "one run, extended in place");
        assert!(a.owed);
        // A gap opens a range in front of it
        a.record(6, true);
        assert_eq!(a.ranges, [(6, 6), (0, 3)]);
        // And the gap filling in makes a third
        a.record(5, true);
        assert_eq!(a.ranges, [(5, 6), (0, 3)]);
    }

    /// A packet that arrives twice, or out of order behind what we have, must
    /// not open a range that overlaps one already there
    #[test]
    fn a_repeat_changes_nothing() {
        let mut a = AckState::default();
        for pn in [0u64, 1, 2] {
            a.record(pn, true);
        }
        a.record(1, true);
        a.record(0, true);
        assert_eq!(a.ranges, [(0, 2)]);
    }

    /// An ACK frame that reaches back for ever costs more than it is worth
    #[test]
    fn the_ranges_remembered_are_bounded() {
        let mut a = AckState::default();
        for pn in (0..40u64).step_by(2) {
            a.record(pn, true);
        }
        assert!(a.ranges.len() <= 8, "{} ranges", a.ranges.len());
        assert_eq!(a.ranges[0], (38, 38), "the newest is kept");
    }

    /// Only a packet that asks to be acknowledged makes one owed
    #[test]
    fn an_ack_only_packet_owes_nothing_back() {
        let mut a = AckState::default();
        a.record(0, false);
        assert!(!a.owed);
        assert_eq!(a.ranges, [(0, 0)]);
        a.record(1, true);
        assert!(a.owed);
    }
}
