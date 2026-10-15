// Appended only to the pinned, disposable shb source archive.
impl Connection {
    pub fn churn_schedule(&mut self, mode: crate::crypto_schedule::Mode) {
        self.churn = Some(crate::crypto_schedule::Audit::new(mode));
    }

    pub fn churn_verify(&self) -> Result<[crate::crypto_schedule::Plan; 2]> {
        anyhow::ensure!(self.churn_tls_completed(), "incomplete TLS");
        anyhow::ensure!(self.closed.is_none(), "failed TLS connection");
        let audit = self.churn.as_ref().unwrap();
        audit.verify()?;
        Ok(std::array::from_fn(|i| {
            audit.plans[i].as_ref().unwrap().clone()
        }))
    }

    pub fn churn_tls_completed(&self) -> bool {
        self.handshake_done && !self.tls.is_handshaking()
    }

    fn churn_crypto(
        &mut self,
        space: Space,
        out: &mut Vec<u8>,
        available: usize,
        frames: &mut Vec<SentFrame>,
    ) -> Result<bool> {
        let state = &mut self.spaces[space as usize];
        if state.crypto_out.is_empty() {
            return Ok(false);
        }
        let audit = self.churn.as_mut().unwrap();
        let plan = audit.plans[space as usize].get_or_insert_with(|| {
            crate::crypto_schedule::Plan::new(audit.mode, &state.crypto_out)
        });
        anyhow::ensure!(
            plan.bytes == state.crypto_out.len(),
            "unexpected extra TLS flight"
        );
        let Some((start, stop)) = plan.next() else {
            // Timing rejects a retransmission instead of silently changing the
            // offered schedule. The ordinary transport's recovery remains intact
            // in independent loss tests; no recovery result is claimed here.
            anyhow::ensure!(
                state.crypto_sent == state.crypto_out.len(),
                "CRYPTO retransmission"
            );
            return Ok(false);
        };
        if available < stop - start + 16 {
            return Ok(false);
        }
        let data = &state.crypto_out[start..stop];
        plan.record(state.next_packet_number, start, data)?;
        frame::put_crypto(out, start as u64, data);
        frames.push(SentFrame::Crypto {
            offset: start as u64,
            len: stop - start,
        });
        // Exactly one fragment per freshly sealed packet. Repeated ranges are
        // different authenticated packets, not encrypted datagram replay.
        state.crypto_sent = if plan.next().is_none() { plan.bytes } else { 0 };
        Ok(true)
    }
}
