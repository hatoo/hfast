//! Two authenticated peers exercise the default batched receive policy.
//! Only the active peer sends requests; both peers have exact delivery accounting.
#![allow(dead_code)]
mod clock;
mod quic;
mod tls;
#[cfg(test)]
mod http3 {
    pub mod proto;
    pub mod qpack;
}
#[cfg(test)]
mod status;
#[cfg(test)]
pub fn is_informational(status: u16) -> bool {
    (100..200).contains(&status)
}

use anyhow::{Context, Result, bail, ensure};
use quic::{
    conn::{Connection, LocalParamsInput},
    frame::{self, Frame},
    varint::put_varint,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::UdpSocket,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

const RESPONSE: &[u8] = b"\x01\x08\x00\x00\xd9\xf5\x54\x02\x31\x33\x00\x0dHello, World!";

const CONTROL_SIZE: usize = unsafe { libc::CMSG_SPACE(2) as usize };
union SegmentControl {
    header: libc::cmsghdr,
    bytes: [u8; CONTROL_SIZE],
}

// Checking a whole batch makes omitted responses fail, even if all received
// bytes look valid. Request IDs cannot be counted twice or cross batch bounds.
struct Batch {
    first: u64,
    count: usize,
    seen: Vec<u64>,
    completed: usize,
}
impl Batch {
    fn new(first: u64, count: usize) -> Self {
        assert!((1..=1024).contains(&count));
        Self {
            first,
            count,
            seen: vec![0; count.div_ceil(64)],
            completed: 0,
        }
    }
    fn response(&mut self, _pn: u64, id: u64, offset: u64, fin: bool, data: &[u8]) -> Result<()> {
        ensure!(
            id >= self.first && (id - self.first).is_multiple_of(4),
            "unexpected stream {id}"
        );
        let i = ((id - self.first) / 4) as usize;
        ensure!(
            i < self.count && self.seen[i / 64] & (1 << (i % 64)) == 0,
            "duplicate or unsolicited response {id}"
        );
        ensure!(
            offset == 0 && fin && data == RESPONSE,
            "wrong response bytes or incomplete FIN"
        );
        self.seen[i / 64] |= 1 << (i % 64);
        self.completed += 1;
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        ensure!(
            self.completed == self.count,
            "missing responses: {}/{}",
            self.completed,
            self.count
        );
        Ok(())
    }
}

fn cpu(pid: u32) -> Result<f64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>()? + fields[12].parse::<u64>()?;
    Ok(ticks as f64 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64)
}

struct Peer {
    socket: UdpSocket,
    conn: Connection,
    wire: Vec<u8>,
    request: Vec<u8>,
    last_received: u64,
    next_stream: u64,
    stream_limit: u64,
    initial_limit: u64,
    max_data: u64,
    initial_max_data: u64,
    sent_data: u64,
    completed: usize,
    packet_count: usize,
    // Every sent 1-RTT request/PING packet must ultimately be acknowledged.
    acked_through: Option<u64>,
    last_sent: Option<u64>,
    sent_datagrams: u64,
    sent_messages: u64,
    received_datagrams: u64,
    fence: Fence,
    queue_audit: Option<std::fs::File>,
}
impl Peer {
    fn connect(port: u16, window: usize) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut conn = Connection::connect(
            tls::client_config(b"h3")?,
            "localhost",
            LocalParamsInput {
                initial_max_data: 1 << 30,
                initial_max_stream_data: 1 << 20,
                initial_max_streams_uni: 16,
                max_idle_timeout_ms: 30_000,
                handshake_timeout_ms: 5_000,
            },
        )?;
        let mut wire = Vec::with_capacity(1200);
        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent_datagrams = 0;
        let mut received_datagrams = 0;
        loop {
            wire.clear();
            while conn.poll_transmit(clock::Instant::now(), &mut wire, None)? != 0 {
                ensure!(socket.send(&wire)? == wire.len());
                sent_datagrams += 1;
                wire.clear();
            }
            if conn.probe_ready() {
                break;
            }
            ensure!(Instant::now() < deadline, "handshake timeout");
            let n = socket.recv(&mut buf)?;
            received_datagrams += 1;
            conn.handle_datagram(clock::Instant::now(), &mut buf[..n])?;
            while let Some(ev) = conn.poll_event() {
                if let quic::conn::Event::Lost(reason) = ev {
                    bail!("handshake lost: {reason}");
                }
            }
        }
        // Busy receive avoids a scheduler wakeup in each measured round trip.
        // The peer has its own pinned CPU; both servers use the same workload.
        socket.set_nonblocking(true)?;
        let (stream_limit, max_data, last_received) = conn.probe_limits();
        ensure!(
            stream_limit == (window * 2) as u64,
            "unexpected initial stream credit"
        );
        // Static QPACK: GET, https, literal :authority=localhost, path=/.
        let headers = b"\x00\x00\xd1\xd7\x50\x09localhost\xc1";
        let mut request = vec![1];
        put_varint(&mut request, headers.len() as u64);
        request.extend(headers);
        let mut peer = Self {
            socket,
            conn,
            wire,
            request,
            last_received,
            next_stream: 0,
            initial_limit: stream_limit,
            stream_limit,
            max_data,
            initial_max_data: max_data,
            sent_data: 0,
            completed: 0,
            packet_count: 0,
            acked_through: None,
            last_sent: None,
            sent_datagrams,
            sent_messages: sent_datagrams,
            received_datagrams,
            fence: Fence::default(),
            queue_audit: None,
        };
        let mut control = Vec::new();
        frame::put_stream(&mut control, 2, 0, false, &[0, 4, 0]);
        frame::put_stream(&mut control, 6, 0, false, &[2]);
        frame::put_stream(&mut control, 10, 0, false, &[3]);
        peer.sent_data += 5;
        peer.send(&control)?;
        peer.receive(None)?;
        peer.ping(Some(peer.last_received))?;
        Ok(peer)
    }
    fn send(&mut self, payload: &[u8]) -> Result<u64> {
        let pn = self.conn.probe_seal(payload, &mut self.wire)?;
        ensure!(self.socket.send(&self.wire)? == self.wire.len());
        ensure!(
            self.last_sent.is_none_or(|last| pn == last + 1),
            "noncontiguous request PN"
        );
        self.last_sent = Some(pn);
        self.sent_datagrams += 1;
        self.sent_messages += 1;
        Ok(pn)
    }
    fn receive(&mut self, mut batch: Option<&mut Batch>) -> Result<(u64, bool)> {
        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + Duration::from_secs(5);
        let n = loop {
            match self.socket.recv(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(Instant::now() < deadline, "missing response or ACK fence");
                    std::hint::spin_loop();
                }
                Err(e) => return Err(e.into()),
            }
        };
        self.received_datagrams += 1;
        let (pn, plain) = self.conn.probe_open(&mut buf[..n])?;
        // A dropped, reordered or duplicated packet invalidates this timing
        // fixture. Independent protocol regression fixtures exercise recovery.
        ensure!(
            pn == self.last_received + 1,
            "noncontiguous packet: {} after {}",
            pn,
            self.last_received
        );
        self.last_received = pn;
        self.packet_count += 1;
        let mut ack_only = true;
        for f in frame::Iter::new(plain) {
            match f? {
                Frame::Padding => {}
                Frame::Ack {
                    largest,
                    first_range,
                    ranges,
                    ..
                } => {
                    ensure!(
                        first_range == largest && ranges.is_empty(),
                        "client packet missing from server ACK"
                    );
                    self.acked_through = Some(self.acked_through.unwrap_or(0).max(largest));
                }
                Frame::Stream {
                    id,
                    offset,
                    fin,
                    data,
                } if id & 3 == 0 => {
                    ack_only = false;
                    batch
                        .as_mut()
                        .context("response outside requested batch")?
                        .response(pn, id, offset, fin, data)?;
                }
                Frame::Stream {
                    id: 3,
                    offset: 0,
                    fin: false,
                    data: [0, 4, 0],
                } => {
                    ack_only = false;
                }
                Frame::MaxStreams { uni: false, limit } => {
                    ack_only = false;
                    ensure!(limit >= self.stream_limit);
                    self.stream_limit = limit;
                }
                Frame::MaxStreams { uni: true, .. } => {
                    ack_only = false;
                }
                Frame::MaxData(limit) => {
                    ack_only = false;
                    ensure!(
                        limit <= self.initial_max_data + self.sent_data,
                        "connection credit counts duplicate bytes"
                    );
                    self.max_data = self.max_data.max(limit);
                }
                Frame::PathResponse(token) => {
                    self.fence.response(token.try_into().unwrap())?;
                    ack_only = false;
                }
                Frame::HandshakeDone => {
                    ack_only = false;
                }
                other => bail!("unexpected frame: {other:?}"),
            }
        }
        Ok((pn, ack_only))
    }
    fn ping(&mut self, acknowledge_through: Option<u64>) -> Result<(u64, bool)> {
        let mut payload = Vec::new();
        if let Some(last) = acknowledge_through {
            frame::put_ack(&mut payload, &[(0, last)], 0);
        }
        payload.push(frame::PING as u8);
        let sent = self.send(&payload)?;
        let mut last;
        loop {
            last = self.receive(None)?;
            if self.acked_through.is_some_and(|pn| pn >= sent) {
                break;
            }
        }
        Ok(last)
    }
}

#[derive(Default)]
struct Fence {
    expected: Option<[u8; 8]>,
    seen: bool,
}
impl Fence {
    fn response(&mut self, token: [u8; 8]) -> Result<()> {
        ensure!(
            Some(token) == self.expected && !self.seen,
            "wrong or repeated fence"
        );
        self.seen = true;
        Ok(())
    }
    fn complete(&self) -> Result<()> {
        ensure!(self.seen, "missing authenticated burst fence");
        Ok(())
    }
}

fn udp() -> Result<BTreeMap<String, u64>> {
    let text = std::fs::read_to_string("/proc/net/snmp")?;
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("Udp: "));
    let names = rows.next().context("no UDP counters")?;
    let values = rows.next().context("no UDP values")?;
    names
        .split_whitespace()
        .zip(values.split_whitespace())
        .map(|(k, v)| Ok((k.to_owned(), v.parse()?)))
        .collect()
}

// InDatagrams counts receive entries, including GRO aggregates. The peer has
// GRO disabled and sends exactly one GSO message per request burst. This
// controlled loopback workload requires each group to be retained intact when
// the server enables GRO. A changed kernel behavior fails the accounting gate.
// OutDatagrams counts send messages; hfast groups at most eight datagrams.
fn validate_delivery(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
    sent: u64,
    sent_messages: u64,
    received: u64,
    gro: bool,
) -> Result<()> {
    for key in [
        "InErrors",
        "RcvbufErrors",
        "SndbufErrors",
        "NoPorts",
        "InCsumErrors",
        "MemErrors",
    ] {
        ensure!(before.get(key) == after.get(key), "UDP error: {key}");
    }
    let incoming = after["InDatagrams"] - before["InDatagrams"];
    let outgoing = after["OutDatagrams"] - before["OutDatagrams"];
    ensure!(
        incoming == (if gro { sent_messages } else { sent }) + received,
        "UDP InDatagrams: {incoming} expected {} (loss, unread packets or unrelated traffic)",
        (if gro { sent_messages } else { sent }) + received
    );
    ensure!(
        (sent_messages + received.div_ceil(8)..=sent_messages + received).contains(&outgoing),
        "UDP OutDatagrams: {outgoing} incompatible with GSO groups of at most eight"
    );
    Ok(())
}

fn empty_socket(port: u16) -> Result<()> {
    let text = std::fs::read_to_string("/proc/net/udp")?;
    let mut found = false;
    for line in text.lines().skip(1) {
        let f: Vec<_> = line.split_whitespace().collect();
        if u16::from_str_radix(f[1].split_once(':').context("UDP address")?.1, 16)? == port {
            ensure!(!found, "shared UDP port");
            found = true;
            let (tx, rx) = f[4].split_once(':').context("UDP queue")?;
            ensure!(
                u64::from_str_radix(tx, 16)? == 0 && u64::from_str_radix(rx, 16)? == 0,
                "queued datagram on {port}"
            );
            ensure!(
                f.last().context("missing UDP drops")?.parse::<u64>()? == 0,
                "socket drops on {port}"
            );
        }
    }
    ensure!(found, "socket {port} not found");
    Ok(())
}

// A bounded, reusable next-burst workspace. Prepare STREAM frames while the
// server handles the current burst, then add the current ACK and encrypt only
// after its response fence. Packet numbers and exact per-burst credit stay serial.
struct BurstWorkspace {
    first: u64,
    streams: Vec<Vec<u8>>,
    packets: Vec<Vec<u8>>,
    payload: Vec<u8>,
}
impl BurstWorkspace {
    fn new(datagrams: usize) -> Self {
        Self {
            first: 0,
            streams: (0..datagrams).map(|_| Vec::with_capacity(1200)).collect(),
            packets: (0..datagrams).map(|_| Vec::with_capacity(1200)).collect(),
            payload: Vec::with_capacity(1200),
        }
    }
    fn prepare(&mut self, first: u64, count: usize, request: &[u8]) {
        self.first = first;
        for (part, payload) in self.streams.iter_mut().enumerate() {
            payload.clear();
            for i in 0..count {
                frame::put_stream(
                    payload,
                    first + 4 * (part * count + i) as u64,
                    0,
                    true,
                    request,
                );
            }
        }
    }
}

// Untimed mechanism fixture only. The matching libc audit hook holds a shared
// lock around nonblocking receives. An exclusive lock lets the peer queue a full
// burst without interrupting a blocked syscall with SIGSTOP. Production timing
// rejects this mode, and Drop releases the lock on all send-error paths.
struct QueuedBurst<'a>(&'a std::fs::File);
impl<'a> QueuedBurst<'a> {
    fn lock(file: &'a std::fs::File) -> Result<Self> {
        ensure!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0);
        Ok(Self(file))
    }
}
impl Drop for QueuedBurst<'_> {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) }, 0);
    }
}

impl Peer {
    fn burst_batch(
        &mut self,
        count: usize,
        work: &mut BurstWorkspace,
        prepare_next: bool,
    ) -> Result<()> {
        let datagrams = work.streams.len();
        ensure!(
            work.first == self.next_stream,
            "wrong prepared request window"
        );
        let total = count * datagrams;
        ensure!(
            self.next_stream / 4 + total as u64 <= self.stream_limit,
            "stream credit exceeded"
        );
        self.sent_data += (total * self.request.len()) as u64;
        ensure!(
            self.sent_data <= self.max_data,
            "connection credit exceeded"
        );
        let mut batch = Batch::new(self.next_stream, total);
        for part in 0..datagrams {
            work.payload.clear();
            if part == 0 {
                frame::put_ack(&mut work.payload, &[(0, self.last_received)], 0);
            }
            work.payload.extend_from_slice(&work.streams[part]);
            // Pad plaintext before authentication, identically for both servers.
            // Every request packet has the same GSO segment length even as ACK
            // and stream-ID encodings grow. No encrypted packet is replayed.
            ensure!(work.payload.len() <= 1160, "request exceeds GSO payload");
            work.payload.resize(1160, 0);
            let pn = self
                .conn
                .probe_seal(&work.payload, &mut work.packets[part])?;
            ensure!(
                self.last_sent.is_some_and(|last| pn == last + 1),
                "noncontiguous request PN"
            );
            self.last_sent = Some(pn);
            self.next_stream += 4 * count as u64;
        }
        let mut iovecs: Vec<libc::iovec> = work
            .packets
            .iter_mut()
            .map(|p| libc::iovec {
                iov_base: p.as_mut_ptr().cast(),
                iov_len: p.len(),
            })
            .collect();
        let length = work.packets[0].len();
        ensure!(work.packets.iter().all(|p| p.len() == length));
        ensure!(length <= u16::MAX as usize && length * datagrams <= 65507);
        let mut control = SegmentControl {
            bytes: [0; CONTROL_SIZE],
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = iovecs.as_mut_ptr();
        message.msg_iovlen = iovecs.len();
        if datagrams > 1 {
            control.header = libc::cmsghdr {
                cmsg_level: libc::IPPROTO_UDP,
                cmsg_type: libc::UDP_SEGMENT,
                cmsg_len: unsafe { libc::CMSG_LEN(2) as usize },
            };
            let offset = unsafe { libc::CMSG_LEN(0) as usize };
            unsafe {
                control.bytes[offset..offset + 2].copy_from_slice(&(length as u16).to_ne_bytes());
            }
            message.msg_control = (&mut control as *mut SegmentControl).cast();
            message.msg_controllen = CONTROL_SIZE;
        }
        let stopped = self
            .queue_audit
            .as_ref()
            .map(QueuedBurst::lock)
            .transpose()?;
        // iovecs, ciphertext buffers and aligned ancillary storage all outlive
        // this synchronous syscall. UDP sends are atomic; partial sends fail.
        let sent = unsafe { libc::sendmsg(self.socket.as_raw_fd(), &message, 0) };
        drop(stopped);
        ensure!(
            sent == (length * datagrams) as isize,
            "GSO burst send: {sent}: {}",
            std::io::Error::last_os_error()
        );
        self.sent_datagrams += datagrams as u64;
        self.sent_messages += 1;
        if prepare_next {
            work.prepare(self.next_stream, count, &self.request);
        }
        while batch.complete().is_err() {
            self.receive(Some(&mut batch))?;
        }
        batch.complete()?;
        self.completed += total;
        let fence_token = (self.next_stream | (1 << 63)).to_be_bytes();
        self.fence = Fence {
            expected: Some(fence_token),
            seen: false,
        };
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, self.last_received)], 0);
        payload.push(0x1a);
        payload.extend_from_slice(&fence_token);
        let sent = self.send(&payload)?;
        while self.fence.complete().is_err() {
            self.receive(None)?;
        }
        self.fence.complete()?;
        ensure!(
            self.acked_through.is_some_and(|pn| pn >= sent),
            "fence packet not ACKed"
        );
        ensure!(
            self.stream_limit == self.initial_limit + self.completed as u64,
            "incorrect exact stream credit after burst fence"
        );
        ensure!(self.max_data <= self.initial_max_data + self.sent_data);
        ensure!(
            self.initial_max_data + self.sent_data - self.max_data < self.initial_max_data / 2,
            "connection credit not replenished"
        );
        Ok(())
    }
    fn burst_cycle(
        &mut self,
        batches: usize,
        batch: usize,
        datagrams: usize,
        pid: u32,
    ) -> Result<Value> {
        let before = cpu(pid)?;
        let sent = self.sent_datagrams;
        let messages = self.sent_messages;
        let recv = self.received_datagrams;
        let start = Instant::now();
        let mut work = BurstWorkspace::new(datagrams);
        work.prepare(self.next_stream, batch, &self.request);
        for i in 0..batches {
            self.burst_batch(batch, &mut work, i + 1 < batches)?;
        }
        let seconds = start.elapsed().as_secs_f64();
        let after = cpu(pid)?;
        let requests = batches * batch * datagrams;
        Ok(
            json!({"requests":requests,"seconds":seconds,"requests_per_second":requests as f64/seconds,
            "server_cpu_ns_per_request":(after-before)*1e9/requests as f64,
            "sent_datagrams":self.sent_datagrams-sent,"received_datagrams":self.received_datagrams-recv,
            "sent_messages":self.sent_messages-messages,
            "request_datagrams":batches*datagrams,"fences":batches}),
        )
    }
    fn final_ack(&mut self) -> Result<()> {
        let mut payload = Vec::new();
        frame::put_ack(&mut payload, &[(0, self.last_received)], 0);
        self.send(&payload)?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 9,
        "usage: peer PORT PID BATCH DATAGRAMS BATCHES CYCLES WARMUP GRO(0|1)"
    );
    let port = args[1].parse()?;
    let pid = args[2].parse()?;
    let batch: usize = args[3].parse()?;
    let datagrams: usize = args[4].parse()?;
    let batches: usize = args[5].parse()?;
    let cycles: usize = args[6].parse()?;
    let warmup: usize = args[7].parse()?;
    ensure!(args[8] == "0" || args[8] == "1");
    let gro = args[8] == "1";
    ensure!(
        (1..=32).contains(&batch)
            && (1..=32).contains(&datagrams)
            && batches > 0
            && cycles > 0
            && warmup > 0
    );
    let before = udp()?;
    let mut peer = Peer::connect(port, batch * datagrams)?;
    peer.queue_audit = std::env::var_os("BURST_QUEUE_AUDIT")
        .map(|p| std::fs::OpenOptions::new().read(true).write(true).open(p))
        .transpose()?;
    let mut quiet = Peer::connect(port, batch * datagrams)?;
    quiet.ping(Some(quiet.last_received))?;
    let warmup_row = peer.burst_cycle(warmup, batch, datagrams, pid)?;
    let mut rows = Vec::new();
    for _ in 0..cycles {
        quiet.ping(Some(quiet.last_received))?;
        rows.push(peer.burst_cycle(batches, batch, datagrams, pid)?);
    }
    quiet.ping(Some(quiet.last_received))?;
    ensure!(quiet.completed == 0 && quiet.next_stream == 0);
    ensure!(quiet.stream_limit == quiet.initial_limit);
    peer.final_ack()?;
    quiet.final_ack()?;
    let sent_datagrams = peer.sent_datagrams + quiet.sent_datagrams;
    let sent_messages = peer.sent_messages + quiet.sent_messages;
    let received_datagrams = peer.received_datagrams + quiet.received_datagrams;
    // Only final ACK consumption is outside timing. It elicits no response.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let counts = udp()?;
        if counts["InDatagrams"]
            >= before["InDatagrams"]
                + (if gro { sent_messages } else { sent_datagrams })
                + received_datagrams
        {
            break;
        }
        ensure!(Instant::now() < deadline, "final ACK not consumed");
        std::thread::yield_now();
    }
    let after = udp()?;
    empty_socket(port)?;
    empty_socket(peer.socket.local_addr()?.port())?;
    empty_socket(quiet.socket.local_addr()?.port())?;
    validate_delivery(
        &before,
        &after,
        sent_datagrams,
        sent_messages,
        received_datagrams,
        gro,
    )?;
    println!(
        "{}",
        json!({"batch":batch,"datagrams":datagrams,"batches":batches,"warmup":warmup_row,"cycles":rows,
        "completed":peer.completed,"errors":0,"lost_packets":0,"duplicate_responses":0,
        "sent_datagrams":sent_datagrams,"received_datagrams":received_datagrams,
        "sent_messages":sent_messages,"gro":gro,
        "active_sent":peer.sent_datagrams,"active_received":peer.received_datagrams,
        "quiet_sent":quiet.sent_datagrams,"quiet_received":quiet.received_datagrams,
        "quiet_completed":quiet.completed,"quiet_stream_limit":quiet.stream_limit,
        "quiet_pings":cycles+2,"connections":2,"queue_audit":peer.queue_audit.is_some(),
        "udp_before":before,"udp_after":after,
        "advertised_stream_limit":peer.stream_limit,"sent_data":peer.sent_data,"max_data":peer.max_data})
    );
    Ok(())
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    #[test]
    fn missing_response_fails() {
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.complete().is_err());
    }
    #[test]
    fn duplicates_and_wrong_streams_fail() {
        let mut b = Batch::new(4, 2);
        b.response(10, 4, 0, true, RESPONSE).unwrap();
        assert!(b.response(10, 4, 0, true, RESPONSE).is_err());
        assert!(b.response(10, 12, 0, true, RESPONSE).is_err());
    }
    #[test]
    fn incorrect_bytes_and_partial_fin_fail() {
        for (offset, fin, data) in [
            (1, true, RESPONSE),
            (0, false, RESPONSE),
            (0, true, &RESPONSE[..RESPONSE.len() - 1]),
        ] {
            assert!(Batch::new(4, 1).response(10, 4, offset, fin, data).is_err());
        }
    }
    #[test]
    fn aggregation_and_multiple_packets_preserve_all_256_responses() {
        let mut b = Batch::new(4, 256);
        for i in (0..256).rev() {
            b.response(10 + i / 41, 4 + i * 4, 0, true, RESPONSE)
                .unwrap();
            if i > 0 {
                assert!(b.complete().is_err());
            }
        }
        b.complete().unwrap();
        assert!(b.response(99, 4, 0, true, RESPONSE).is_err());
    }
    #[test]
    fn missing_wrong_or_repeated_fence_fails() {
        let mut fence = Fence {
            expected: Some([42; 8]),
            seen: false,
        };
        assert!(fence.complete().is_err());
        assert!(fence.response([41; 8]).is_err());
        fence.response([42; 8]).unwrap();
        fence.complete().unwrap();
        assert!(fence.response([42; 8]).is_err());
    }
    #[test]
    fn prepared_windows_keep_every_stream_once_across_reuse() {
        let mut work = BurstWorkspace::new(8);
        for first in [0, 1024, 1 << 20] {
            work.prepare(first, 32, b"exact request");
            assert_eq!(work.first, first);
            let mut expected = first;
            for payload in &work.streams {
                let mut count = 0;
                for f in frame::Iter::new(payload) {
                    match f.unwrap() {
                        Frame::Stream {
                            id,
                            offset: 0,
                            fin: true,
                            data,
                        } => {
                            assert_eq!(id, expected);
                            assert_eq!(data, b"exact request");
                            expected += 4;
                            count += 1;
                        }
                        other => panic!("unexpected prepared frame: {other:?}"),
                    }
                }
                assert_eq!(count, 32);
            }
            assert_eq!(expected, first + 1024);
        }
    }
    #[test]
    fn quiet_peer_delivery_cannot_be_omitted() {
        let before = BTreeMap::from([("InDatagrams".into(), 0), ("OutDatagrams".into(), 0)]);
        let after = BTreeMap::from([("InDatagrams".into(), 24), ("OutDatagrams".into(), 24)]);
        validate_delivery(&before, &after, 15, 15, 9, false).unwrap();
        assert!(validate_delivery(&before, &after, 10, 10, 4, false).is_err());
        assert!(validate_delivery(&before, &after, 15, 15, 4, false).is_err());
        assert!(validate_delivery(&before, &after, 10, 10, 9, false).is_err());
    }
    #[test]
    fn missing_or_extra_delivery_and_drops_fail() {
        let before = [
            "InErrors",
            "RcvbufErrors",
            "SndbufErrors",
            "NoPorts",
            "InCsumErrors",
            "MemErrors",
            "InDatagrams",
            "OutDatagrams",
        ]
        .into_iter()
        .map(|k| (k.to_owned(), 0))
        .collect::<BTreeMap<_, _>>();
        let mut after = before.clone();
        after.insert("InDatagrams".into(), 14);
        after.insert("OutDatagrams".into(), 14);
        validate_delivery(&before, &after, 10, 10, 4, false).unwrap();
        for key in after.keys() {
            let mut corrupt = after.clone();
            *corrupt.get_mut(key).unwrap() += 1;
            assert!(validate_delivery(&before, &corrupt, 10, 10, 4, false).is_err());
        }
        after.insert("OutDatagrams".into(), 11);
        validate_delivery(&before, &after, 10, 10, 4, false).unwrap();
        after.insert("OutDatagrams".into(), 10);
        assert!(validate_delivery(&before, &after, 10, 10, 4, false).is_err());
        after.insert("OutDatagrams".into(), 14);
        after.insert("InDatagrams".into(), 13);
        assert!(validate_delivery(&before, &after, 10, 10, 4, false).is_err());
    }
    #[test]
    fn gro_delivery_requires_exact_aggregate_counts() {
        let before = BTreeMap::from([("InDatagrams".into(), 0), ("OutDatagrams".into(), 0)]);
        // 18 logical sends = two 8-segment GSO messages plus two plain packets.
        // The peer receives eight ordinary datagrams, perhaps in one GSO send.
        let mut after = BTreeMap::from([("InDatagrams".into(), 12), ("OutDatagrams".into(), 5)]);
        validate_delivery(&before, &after, 18, 4, 8, true).unwrap();
        assert!(validate_delivery(&before, &after, 18, 4, 8, false).is_err());
        for count in [11, 13, 26] {
            after.insert("InDatagrams".into(), count);
            assert!(validate_delivery(&before, &after, 18, 4, 8, true).is_err());
        }
        after.insert("InDatagrams".into(), 26);
        validate_delivery(&before, &after, 18, 4, 8, false).unwrap();
    }
}
