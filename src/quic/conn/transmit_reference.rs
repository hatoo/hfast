// Frozen packet construction from hfast 474d6da, before direct payload assembly.
// Test oracle only: preserve frame sizing, ordering and encryption decisions.
use super::*;

impl SpaceState {
    fn reference_write_crypto(&mut self, body: &mut Vec<u8>, body_room: usize, pn: u64) {
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

impl Connection {
    fn reference_write_data(&mut self, body: &mut Vec<u8>, body_room: usize, pn: u64) {
        let control_len = frame::stream_overhead(CONTROL_STREAM, 0, CONTROL_PRELUDE.len())
            + CONTROL_PRELUDE.len();
        if self.control.pending && body.len() + control_len <= body_room {
            frame::put_stream(body, CONTROL_STREAM, 0, false, CONTROL_PRELUDE);
            self.control.sent(pn);
        }
        if self
            .streams_credit
            .owed(self.streams_limit(), self.max_streams_bidi)
        {
            self.streams_credit.write(
                body,
                body_room,
                pn,
                frame::MAX_STREAMS_BIDI,
                self.streams_limit(),
            );
        }
        if self
            .data_credit
            .owed(self.data_limit(), self.initial_max_data)
        {
            self.data_credit
                .write(body, body_room, pn, frame::MAX_DATA, self.data_limit());
        }
        for reset in &mut self.resets {
            if !reset.flight.pending {
                continue;
            }
            let need = 1
                + varint_len(reset.id)
                + varint_len(reset.error_code)
                + varint_len(reset.final_size);
            if body.len() + need > body_room {
                break;
            }
            put_varint(body, frame::RESET_STREAM);
            put_varint(body, reset.id);
            put_varint(body, reset.error_code);
            put_varint(body, reset.final_size);
            reset.flight.sent(pn);
        }
        // Answers, as many as the packet holds. They go out newest first,
        // which costs nothing: every one of them is the same answer.
        while let Some(&id) = self.ready.last() {
            let need = frame::stream_overhead(id, 0, RESPONSE.len()) + RESPONSE.len();
            if body.len() + need > body_room {
                break;
            }
            self.ready.pop();
            if let Some(req) = self.stream_mut(id) {
                req.sent = true;
            }
            frame::put_stream(body, id, 0, true, RESPONSE);
            self.unacked.push((pn, id));
        }
    }
    pub(super) fn reference_write_packet_into(
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
        st.reference_write_crypto(body, body_room, pn);
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
            if !self.tls.is_handshaking() && self.handshake_done.pending && body.len() < body_room {
                put_varint(body, frame::HANDSHAKE_DONE);
                self.handshake_done.sent(pn);
            }
            self.reference_write_data(body, body_room, pn);
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
    pub(super) fn reference_poll_transmit(&mut self, out: &mut Vec<u8>) -> Result<bool> {
        let start = out.len();
        let mut body = Vec::new();
        for space in [Space::Initial, Space::Handshake, Space::Data] {
            if self.local_keys(space).is_some() {
                body.clear();
                self.reference_write_packet_into(out, space, start, &mut body)?;
            }
        }
        Ok(out.len() > start)
    }
}
