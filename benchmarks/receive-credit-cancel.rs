//! Bounded sustained sparse aborts. Final sizes count holes; wire bytes do not.
//! Only the diagnostic archive includes this file and the shared manual peer.
mod credit_control;
use std::os::fd::AsRawFd;

const HALF: u64 = 1 << 23;
const SEGMENT: usize = 1200;
const FRAME_BATCH: usize = 64;
const MAX_CYCLES: usize = 8192;

struct CreditCycle {
    first: u64,
    cancellation_ns: u64,
    cycle_ns: u64,
    cancellations: Vec<(u64, u64)>,
    responses: [(u64, u64); 2],
    sent_through: u64,
    received_through: u64,
    flow: u64,
    stream_limit: u64,
    data_limit: u64,
}
impl CreditCycle {
    // Called only after the native interval has ended.
    fn report(&self) -> Value {
        json!({"first_stream_id":self.first,"cancellation_cohort_ns":self.cancellation_ns,
            "cycle_ns":self.cycle_ns,"sent_through":self.sent_through,
            "received_through":self.received_through,"flow_control_bytes":self.flow,
            "advertised_stream_limit":self.stream_limit,"advertised_data_limit":self.data_limit})
    }
}

fn cycle_budget(warmup: usize, measured: usize) -> Result<usize> {
    let total = warmup
        .checked_add(measured)
        .context("cycle count overflow")?;
    ensure!(
        warmup > 0 && measured > 0 && total <= MAX_CYCLES,
        "invalid cycle budget"
    );
    Ok(total)
}

fn post_prefix() -> Vec<u8> {
    let headers = b"\x00\x00\xd4\xd7\x50\x09localhost\xc1";
    let mut prefix = vec![1];
    put_varint(&mut prefix, headers.len() as u64);
    prefix.extend(headers);
    prefix.push(0);
    // The four-byte DATA length plus this prefix and the body end at HALF.
    let body = HALF - prefix.len() as u64 - 4;
    put_varint(&mut prefix, body);
    assert_eq!(prefix.len() as u64 + body, HALF);
    prefix
}

fn crossings(ids: &[u64]) -> Vec<Vec<u8>> {
    ids.chunks(FRAME_BATCH)
        .map(|chunk| {
            let mut body = Vec::new();
            for &id in chunk {
                frame::put_stream(&mut body, id, HALF - 1, false, b"x");
            }
            body
        })
        .collect()
}

fn cancellations(ids: &[u64]) -> Vec<Vec<u8>> {
    ids.chunks(FRAME_BATCH)
        .map(|chunk| {
            let mut body = Vec::new();
            put_receive_resets(&mut body, chunk, HALF);
            body
        })
        .collect()
}

// Each aggregate's packets may be acknowledged separately. Snapshot actual
// flow progress per packet, never the aggregate's eventual high-water mark.
fn crossing_bytes(payload: &[u8]) -> Result<u64> {
    let mut fresh = 0;
    for item in frame::Iter::new(payload) {
        match item? {
            Frame::Stream {
                offset,
                fin: false,
                data: b"x",
                ..
            } if offset == HALF - 1 => fresh += 1,
            Frame::Ack { .. } | Frame::ResetStream { .. } => {}
            _ => bail!("unexpected aggregate frame"),
        }
    }
    Ok(fresh)
}

// One bounded GSO send allows the normal server GRO/receive boundary to decide
// which cancellations share a flush. Every encrypted datagram respects 1200 B.
// No socket/window/flush/timer setting in the server is changed.
fn segmented(socket: &UdpSocket, bytes: &[u8]) -> Result<()> {
    ensure!(!bytes.is_empty() && bytes.len().is_multiple_of(SEGMENT));
    ensure!(bytes.len() <= 16 * SEGMENT, "bounded aggregate exceeded");
    let space = unsafe { libc::CMSG_SPACE(2) } as usize;
    let mut control = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space;
    // SAFETY: aligned ancillary storage, one live iovec, and all pointers stay
    // valid until the synchronous sendmsg returns. The socket is still owned.
    let sent = unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = libc::UDP_SEGMENT;
        (*header).cmsg_len = libc::CMSG_LEN(2) as usize;
        std::ptr::copy_nonoverlapping(
            (SEGMENT as u16).to_ne_bytes().as_ptr(),
            libc::CMSG_DATA(header),
            2,
        );
        libc::sendmsg(socket.as_raw_fd(), &msg, 0)
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(sent as usize == bytes.len(), "partial GSO send");
    Ok(())
}

impl Peer {
    fn credit_burst(&mut self, payloads: Vec<Vec<u8>>) -> Result<u64> {
        ensure!(!payloads.is_empty() && payloads.len() <= 16);
        let excess = payloads.len() as u64 - 1;
        let increments = payloads
            .iter()
            .map(|p| crossing_bytes(p))
            .collect::<Result<Vec<_>>>()?;
        let mut flow = self
            .sent_data
            .checked_sub(increments.iter().sum())
            .context("crossing flow underflow")?;
        let mut aggregate = Vec::new();
        let mut last = 0;
        for (mut payload, fresh) in payloads.into_iter().zip(increments) {
            flow += fresh;
            // The shared transport uses a four-byte PN and a fixed eight-byte
            // peer CID here. Check the exact sealed size instead of assuming it.
            ensure!(payload.len() <= SEGMENT - 29, "oversized frame batch");
            payload.resize(SEGMENT - 29, 0);
            last = self.conn.probe_seal(&payload, &mut self.wire)?;
            ensure!(self.wire.len() == SEGMENT, "unexpected packet overhead");
            trace(&mut self.trace, "tx", last, &payload)?;
            self.sent_packets.push(last);
            self.flow_packets.push((last, flow));
            aggregate.extend_from_slice(&self.wire);
        }
        segmented(&self.socket, &aggregate)?;
        self.gso_segment_excess += excess;
        Ok(last)
    }

    fn credit_fence(&mut self, sent: u64, resets: usize) -> Result<()> {
        while self.acked_through.is_none_or(|pn| pn < sent) || self.reset_count < resets {
            self.receive(None)?;
        }
        ensure!(self.reset_count == resets, "extra reset");
        Ok(())
    }

    fn credit_cancel(&mut self, count: usize, mode: &str) -> Result<CreditCycle> {
        ensure!([16, 64, 256].contains(&count), "unsupported cohort");
        ensure!(
            ["inline", "separate", "survivors", "late-ack"].contains(&mode),
            "unknown mode"
        );
        let (stream_bytes, _, _) = self.conn.credit_probe_limits();
        ensure!(
            stream_bytes == 2 * HALF && self.max_data >= 1 << 30,
            "production windows changed"
        );
        let prefix = post_prefix();
        let cycle_start = Instant::now();
        let first_id = self.next_stream;
        ensure!(
            first_id / 4 + count as u64 <= self.stream_limit,
            "ungranted cohort"
        );
        let reset_start = self.reset_count;
        let ids: Vec<_> = (0..count).map(|n| first_id + n as u64 * 4).collect();
        // Valid POST headers and two body bytes are sent. The body gap is
        // deliberately never claimed as uploaded: RESET accounts its final size.
        // Stage below the threshold in small ACK-fenced packets, allowing normal
        // MAX_DATA replenishment before a large cohort crosses by one byte each.
        for chunk in ids.chunks(16) {
            let mut body = Vec::new();
            frame::put_ack(&mut body, &[(0, self.last_received)], 0);
            for &id in chunk {
                frame::put_stream(&mut body, id, 0, false, &prefix);
                frame::put_stream(&mut body, id, HALF - 2, false, b"x");
                self.sent_data += HALF - 1;
                ensure!(
                    self.sent_data <= self.max_data,
                    "connection credit exceeded during staging"
                );
                self.next_stream += 4;
            }
            let sent = self.send(&body)?;
            self.credit_fence(sent, reset_start)?;
        }
        self.resets = Some(ResetBatch::with_size(&ids, 0)?);
        self.sent_data += count as u64;
        ensure!(
            self.sent_data <= self.max_data,
            "crossing exceeds connection credit"
        );
        let start = Instant::now();
        self.cancellation_started = Some(start);
        let mut packets = crossings(&ids);
        let mut ack = Vec::new();
        frame::put_ack(&mut ack, &[(0, self.last_received)], 0);
        packets[0].splice(0..0, ack);
        let first = if mode == "survivors" {
            ids.iter().step_by(2).copied().collect()
        } else {
            ids.clone()
        };
        if mode == "inline" || mode == "survivors" {
            packets.extend(cancellations(&first));
            let sent = self.credit_burst(packets)?;
            self.credit_fence(sent, reset_start + first.len())?;
            if mode == "survivors" {
                let rest: Vec<_> = ids.iter().skip(1).step_by(2).copied().collect();
                let sent = self.credit_burst(cancellations(&rest))?;
                self.credit_fence(sent, reset_start + count)?;
            }
        } else {
            let sent = self.credit_burst(packets)?;
            self.credit_fence(sent, reset_start)?;
            if mode == "late-ack" {
                // Three ACK-only server packets move the loss threshold past
                // all credit copies. In ONE authenticated packet, declare those
                // copies lost, then acknowledge the originals before flushing.
                for _ in 0..3 {
                    self.ping(None)?;
                }
                let mut body = Vec::new();
                frame::put_ack(&mut body, &[(self.last_received, self.last_received)], 0);
                frame::put_ack(&mut body, &[(0, self.last_received)], 0);
                body.push(frame::PING as u8);
                let sent = self.send(&body)?;
                self.credit_fence(sent, reset_start)?;
            }
            let sent = self.credit_burst(cancellations(&ids))?;
            self.credit_fence(sent, reset_start + count)?;
        }
        self.resets.as_ref().unwrap().complete()?;
        self.cancelled += count;
        let cancellation_ns = start.elapsed().as_nanos() as u64;
        self.ping(Some(self.last_received))?;
        self.check_credit(self.completed + self.cancelled)?;
        // Successful requests and their latencies remain separate from aborts.
        let mut samples = [(0, 0); 2];
        for sample in &mut samples {
            let id = self.next_stream;
            let start = Instant::now();
            self.request(1, &[(0, self.last_received)])?;
            *sample = (id, start.elapsed().as_nanos() as u64);
            self.ping(Some(self.last_received))?;
        }
        self.check_credit(self.completed + self.cancelled)?;
        ensure!(self.ping(Some(self.last_received))?.1, "undrained output");
        empty_socket(&self.socket)?;
        let sent_through = *self.sent_packets.last().context("missing sent history")?;
        ensure!(
            self.acked_through == Some(sent_through),
            "unacknowledged cycle"
        );
        ensure!(
            self.sent_packets.len() <= 128,
            "packet history exceeded bound"
        );
        self.max_packet_history = self.max_packet_history.max(self.sent_packets.len());
        self.retired_sent_packets += self.sent_packets.len() as u64;
        self.sent_packets.clear();
        ensure!(
            self.flow_packets.len() <= 129,
            "flow history exceeded bound"
        );
        self.flow_packets.clear();
        self.flow_packets.push((sent_through, self.sent_data));
        ensure!(
            self.cancellation_samples.len() == count,
            "missing cancellation samples"
        );
        let cancellations =
            std::mem::replace(&mut self.cancellation_samples, Vec::with_capacity(count));
        self.resets = None;
        self.cancellation_started = None;
        Ok(CreditCycle {
            first: first_id,
            cancellation_ns,
            cycle_ns: cycle_start.elapsed().as_nanos() as u64,
            cancellations,
            responses: samples,
            sent_through,
            received_through: self.last_received,
            flow: self.sent_data,
            stream_limit: self.stream_limit,
            data_limit: self.max_data,
        })
    }
}

fn report(
    peer: &Peer,
    rows: &[CreditCycle],
    count: usize,
    mode: &str,
    warmup: usize,
    interval: Value,
) -> Value {
    let prefix = post_prefix();
    json!({"mode":mode,"cohort":count,"iterations":rows.len(),"warmup":warmup,
        "measured":rows.len()-warmup,"interval":interval,"cycles":rows.iter().map(CreditCycle::report).collect::<Vec<_>>(),
        "responses":peer.completed,"cancelled":peer.cancelled,"resets":peer.reset_count,"reset_final_size":HALF,
        "aborted_wire_bytes":peer.cancelled*(prefix.len()+2),"reset_final_bytes":peer.cancelled as u64*HALF,
        "initial_stream_limit":peer.initial_limit,"advertised_stream_limit":peer.stream_limit,
        "advertised_data_limit":peer.max_data,"flow_control_bytes":peer.sent_data,
        "request_bytes":peer.completed*peer.request.len(),"prefix_bytes":prefix.len(),
        "sent_datagrams_before_close":peer.handshake_sent+peer.retired_sent_packets+peer.sent_packets.len() as u64,
        "received_datagrams":peer.handshake_received+peer.packet_count as u64,
        "gso_segment_excess":peer.gso_segment_excess,"max_packet_history":peer.max_packet_history,
        "response_latency_ns":rows.iter().flat_map(|r| r.responses.iter().map(|s|s.1)).collect::<Vec<_>>(),
        "response_stream_ids":rows.iter().flat_map(|r| r.responses.iter().map(|s|s.0)).collect::<Vec<_>>(),
        "cancellation_latency_ns":rows.iter().flat_map(|r| r.cancellations.iter().map(|s|s.1)).collect::<Vec<_>>(),
        "cancellation_stream_ids":rows.iter().flat_map(|r| r.cancellations.iter().map(|s|s.0)).collect::<Vec<_>>(),
        "errors":0,"timing_qualified":false,"manual_sparse_driver":true})
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: peer PORT COHORT MODE WARMUP MEASURED"
    );
    let count = args[2].parse()?;
    let warmup = args[4].parse()?;
    let measured = args[5].parse()?;
    let total = cycle_budget(warmup, measured)?;
    ensure!([16, 64, 256].contains(&count), "unsupported cohort");
    let mut peer = Peer::connect(args[1].parse()?, count)?;
    let mut rows = Vec::with_capacity(total);
    peer.sent_packets.reserve(128);
    peer.cancellation_samples.reserve(count);
    credit_control::emit(json!({"event":"ready","port":peer.socket.local_addr()?.port()}))?;
    credit_control::command(0, "warmup", Duration::from_secs(30))?;
    for _ in 0..warmup {
        rows.push(peer.credit_cancel(count, &args[3])?);
    }
    credit_control::emit(
        json!({"event":"warmed","cycles":rows.len(),"cancelled":peer.cancelled,
        "responses":peer.completed,"next_stream":peer.next_stream}),
    )?;
    credit_control::command(0, "start", Duration::from_secs(30))?;
    // No controller interaction, logging (unless explicitly auditing), JSON,
    // or unbounded histories occur inside this fixed-work native interval.
    let start = credit_control::Start::now()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    for _ in 0..measured {
        ensure!(Instant::now() < deadline, "native phase deadline exceeded");
        rows.push(peer.credit_cancel(count, &args[3])?);
    }
    let interval = start.finish()?;
    credit_control::emit(report(&peer, &rows, count, &args[3], warmup, interval))?;
    credit_control::command(0, "exit", Duration::from_secs(120))?;
    peer.send(&[0x1c, 0, 0, 0])?;
    Ok(())
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn cohorts_respect_packet_and_aggregate_bounds() {
        for (count, first) in [16, 64, 256]
            .into_iter()
            .flat_map(|c| [0, 64, 16384, (MAX_CYCLES as u64 * 258) * 4].map(|first| (c, first)))
        {
            let ids: Vec<_> = (0..count).map(|n| first + n * 4).collect();
            let mut packets = crossings(&ids);
            packets.extend(cancellations(&ids));
            assert!(packets.len() <= 8);
            assert!(packets.iter().all(|p| p.len() + 29 + 16 <= SEGMENT));
            let parsed: Vec<_> = packets
                .iter()
                .flat_map(|p| frame::Iter::new(p).map(Result::unwrap))
                .collect();
            assert_eq!(parsed.len(), count as usize * 2);
        }
    }
    #[test]
    fn aggregate_flow_snapshots_advance_only_on_crossings() {
        let ids: Vec<_> = (0..256).map(|n| 16384 + 4 * n).collect();
        assert_eq!(
            crossings(&ids)
                .iter()
                .map(|p| crossing_bytes(p).unwrap())
                .collect::<Vec<_>>(),
            vec![64; 4]
        );
        assert!(
            cancellations(&ids)
                .iter()
                .all(|p| crossing_bytes(p).unwrap() == 0)
        );
        assert!(crossing_bytes(&[frame::PING as u8]).is_err());
    }
    #[test]
    fn invalid_cycle_budgets_fail() {
        for (a, b) in [(0, 1), (1, 0), (MAX_CYCLES, 1), (usize::MAX, 1)] {
            assert!(cycle_budget(a, b).is_err());
        }
        assert_eq!(cycle_budget(1, MAX_CYCLES - 1).unwrap(), MAX_CYCLES);
    }
    #[test]
    fn sparse_payload_counts_never_include_the_gap() {
        let prefix = post_prefix();
        assert_eq!(prefix.len(), 23);
        assert_eq!((prefix.len() + 2) * 256, 6400);
        assert_eq!(HALF * 256, 2_147_483_648);
        assert!(((prefix.len() + 2) as u64) < HALF);
    }
}
