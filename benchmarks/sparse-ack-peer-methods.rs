// Included only in a disposable, pinned shb transport archive by the builder.
// Production hfast and shb binaries do not contain these benchmark methods.
impl Connection {
    pub fn probe_ready(&self) -> bool {
        self.handshake_done
    }

    pub fn probe_limits(&self) -> (u64, u64, u64) {
        (
            self.max_streams_bidi,
            self.max_data_peer,
            self.spaces[Space::Data as usize].largest_received.unwrap(),
        )
    }

    pub fn probe_seal(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<u64> {
        let state = &mut self.spaces[Space::Data as usize];
        let pn = state.next_packet_number;
        state.next_packet_number += 1;
        let keys = self.one_rtt_local.as_ref().unwrap();
        out.clear();
        header::put_short_header(out, &self.peer_cid, 4, self.key_phase);
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        out.extend_from_slice(payload);
        while out.len() < pn_offset + 4 + 3 {
            out.push(0);
        }
        let (head, body) = out.split_at_mut(pn_offset + 4);
        let tag = keys.packet.encrypt_in_place(pn, head, body)?;
        out.extend_from_slice(tag.as_ref());
        protect_header(keys.header.as_ref(), out, pn_offset, 4)?;
        anyhow::ensure!(out.len() <= MAX_DATAGRAM, "oversized probe packet");
        Ok(pn)
    }

    pub fn probe_open<'a>(&mut self, buf: &'a mut [u8]) -> Result<(u64, &'a [u8])> {
        let Incoming::Short { pn_offset, end, .. } =
            header::decode_header(buf, self.local_cid.len())?
        else {
            bail!("unexpected long-header packet after handshake");
        };
        let keys = self.one_rtt_remote.as_ref().unwrap();
        let (first, n) = unprotect_header(keys.header.as_ref(), &mut buf[..end], pn_offset)?;
        anyhow::ensure!((first & 4 != 0) == self.key_phase, "unexpected key update");
        let truncated = buf[pn_offset..pn_offset + n]
            .iter()
            .fold(0, |a, b| (a << 8) | u64::from(*b));
        let state = &mut self.spaces[Space::Data as usize];
        let pn = decode_packet_number(state.largest_received.unwrap_or(0), truncated, n as u32 * 8);
        let (head, body) = buf[..end].split_at_mut(pn_offset + n);
        let plain = keys.packet.decrypt_in_place(pn, head, body)?;
        state.largest_received = Some(state.largest_received.unwrap_or(0).max(pn));
        Ok((pn, plain))
    }
}
