//! The TCP side: one thread per core, each with its own listener and io_uring
//!
//! Both HTTP/1.1 and HTTP/2 are served on the same port. Which one a connection
//! is talking is decided by its first bytes: HTTP/2 over cleartext opens with a
//! preface (RFC 9113 Section 3.4) that no HTTP/1.1 request can begin with, so
//! nothing has to be negotiated and no client has to be told which port to use.

use std::collections::VecDeque;
use std::os::fd::RawFd;

use crate::sys;
use crate::{h1, h2};

const BATCH: usize = 128;
const LISTENER: u64 = u32::MAX as u64;
const IO: u64 = 1 << 63;

enum Proto {
    /// Too few bytes to tell yet
    Unknown,
    H1 {
        remaining_body: usize,
        head: h1::Head,
    },
    H2(h2::Conn),
}

struct Conn {
    /// Undecided protocol bytes or incomplete HTTP/2 frames. HTTP/1 headers
    /// and body bytes are consumed directly.
    inbuf: Vec<u8>,
    /// Responses waiting to go out, written once per wakeup
    outbuf: Vec<u8>,
    /// How much of `outbuf` the socket has taken
    out_off: usize,
    proto: Proto,
}

impl Conn {
    fn new() -> Self {
        Conn {
            // Both start empty and grow to whatever the connection turns out
            // to need. Reserving a read's worth up front put 128MB of buffers
            // behind a thousand connections and evicted everything else.
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            out_off: 0,
            proto: Proto::Unknown,
        }
    }

    /// Answer everything complete in `buf`, returning how much of it was used,
    /// or `None` if the connection is over.
    fn drive(&mut self, buf: &[u8]) -> Option<usize> {
        let mut at = 0;
        if let Proto::Unknown = self.proto {
            match settle(buf) {
                Which::Undecided => return Some(0), // wait for more bytes
                Which::H1 => {
                    self.proto = Proto::H1 {
                        remaining_body: 0,
                        head: h1::Head::default(),
                    }
                }
                Which::H2 => {
                    at = h2::PREFACE.len();
                    self.proto = Proto::H2(h2::Conn::new(&mut self.outbuf));
                }
            }
        }
        match &mut self.proto {
            Proto::H1 {
                remaining_body,
                head,
            } => {
                if *remaining_body > 0 {
                    let used = (*remaining_body).min(buf.len());
                    *remaining_body -= used;
                    at = used;
                    if *remaining_body > 0 {
                        return Some(at);
                    }
                    h1::respond(&mut self.outbuf);
                }
                while at < buf.len() {
                    match head.parse(&buf[at..]) {
                        h1::Request::Whole(n) => {
                            h1::respond(&mut self.outbuf);
                            at += n;
                        }
                        h1::Request::Body(n) => {
                            *remaining_body = n;
                            return Some(buf.len());
                        }
                        h1::Request::Partial => return Some(buf.len()),
                        h1::Request::Bad => return None,
                    }
                }
            }
            Proto::H2(c) => at += c.drive(&buf[at..], &mut self.outbuf)?,
            Proto::Unknown => unreachable!("settled above"),
        }
        Some(at)
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Which {
    H1,
    H2,
    /// The bytes so far are a prefix of the preface and of nothing else
    Undecided,
}

/// Which protocol the first bytes belong to
fn settle(buf: &[u8]) -> Which {
    let seen = buf.len().min(h2::PREFACE.len());
    if buf[..seen] != h2::PREFACE[..seen] {
        // No HTTP/1.1 request line can begin with the preface
        return Which::H1;
    }
    match seen == h2::PREFACE.len() {
        true => Which::H2,
        false => Which::Undecided,
    }
}

/// `lfd` is this worker's own listener, already bound; see
/// [`sys::attach_reuseport_cbpf`] for why each worker has one of its own and
/// why it is pinned.
pub fn worker(lfd: RawFd, cpu: usize) {
    let ring = io_uring::IoUring::new(BATCH as u32).expect("TCP workers require io_uring");
    worker_ring(lfd, cpu, ring);
}

/// Bound accepts so established connections keep making progress.
fn accept_batch(ring: &mut io_uring::IoUring, lfd: RawFd, conns: &mut Vec<Option<Conn>>) {
    for _ in 0..BATCH {
        let fd = sys::accept(lfd);
        if fd < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            return;
        }
        sys::set_nodelay(fd);
        if conns.len() <= fd as usize {
            conns.resize_with(fd as usize + 1, || None);
        }
        conns[fd as usize] = Some(Conn::new());
        arm_poll(ring, fd, libc::POLLIN, fd as u64);
    }
}

fn consume(conn: &mut Conn, data: &[u8]) -> bool {
    if conn.inbuf.is_empty() {
        let Some(used) = conn.drive(data) else {
            return false;
        };
        if used < data.len() {
            conn.inbuf.extend_from_slice(&data[used..]);
        }
    } else {
        let mut buf = std::mem::take(&mut conn.inbuf);
        buf.extend_from_slice(data);
        let used = conn.drive(&buf);
        conn.inbuf = buf;
        match used {
            Some(used) => conn.inbuf.drain(..used),
            None => return false,
        };
    }
    true
}

/// Submit the ready sockets' reads and writes in two batches. Completion
/// barriers keep every kernel buffer borrow inside its batch; no buffer or
/// connection is moved or changed while the corresponding operation is live.
fn worker_ring(lfd: RawFd, cpu: usize, mut ring: io_uring::IoUring) -> ! {
    use io_uring::{opcode, types};
    const CHUNK: usize = 16 * 1024;
    sys::pin_to_cpu(cpu);
    arm_poll(&mut ring, lfd, libc::POLLIN, LISTENER);
    let mut conns: Vec<Option<Conn>> = Vec::new();
    let mut ready = VecDeque::new();
    let mut events = Vec::with_capacity(BATCH);
    let mut scratch = vec![0u8; BATCH * CHUNK];
    let mut completions = Vec::with_capacity(BATCH);
    loop {
        // Polls are one-shot: each socket is rearmed only after its I/O batch
        // finishes, so closing a socket cannot leave a stale poll for a reused fd.
        submit(&mut ring, usize::from(ready.is_empty()));
        drain_completions(&mut ring, &mut ready, &mut completions);
        events.clear();
        events.extend(ready.drain(..ready.len().min(BATCH)));
        let mut reads = 0;
        for (i, &(token, result)) in events.iter().enumerate() {
            if token == LISTENER {
                assert!(result >= 0, "io_uring listener poll: {result}");
                continue;
            }
            let fd = token as RawFd;
            if conns.get(fd as usize).and_then(Option::as_ref).is_none() {
                continue;
            }
            if result < 0 || result & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) as i32 != 0 {
                unsafe {
                    libc::close(fd);
                }
                conns[fd as usize] = None;
                continue;
            }
            if result & libc::POLLIN as i32 != 0 {
                let entry = opcode::Recv::new(
                    types::Fd(fd),
                    unsafe { scratch.as_mut_ptr().add(i * CHUNK) },
                    CHUNK as _,
                )
                .flags(libc::MSG_DONTWAIT)
                .build()
                .user_data(IO | i as u64);
                // scratch is stable and each receive owns a distinct chunk.
                unsafe { push(&mut ring, &entry) };
                reads += 1;
            }
        }
        if reads > 0 {
            wait_batch(&mut ring, reads, &mut ready, &mut completions);
            for &(i, result) in &completions {
                let fd = events[i].0 as RawFd;
                let conn = conns[fd as usize].as_mut().unwrap();
                let alive = if result > 0 {
                    consume(conn, &scratch[i * CHUNK..i * CHUNK + result as usize])
                } else {
                    result == -libc::EAGAIN || result == -libc::EINTR
                };
                if !alive {
                    unsafe {
                        libc::close(fd);
                    }
                    conns[fd as usize] = None;
                }
            }
        }
        let mut writes = 0;
        for &(token, _) in &events {
            if token == LISTENER {
                continue;
            }
            let fd = token as RawFd;
            let Some(conn) = conns.get_mut(fd as usize).and_then(Option::as_mut) else {
                continue;
            };
            if conn.out_off < conn.outbuf.len() {
                let entry = opcode::Send::new(
                    types::Fd(fd),
                    unsafe { conn.outbuf.as_ptr().add(conn.out_off) },
                    (conn.outbuf.len() - conn.out_off).min(u32::MAX as usize) as _,
                )
                .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
                .build()
                .user_data(IO | fd as u64);
                // No outbuf is changed until all send completions are drained.
                unsafe { push(&mut ring, &entry) };
                writes += 1;
            }
        }
        if writes > 0 {
            wait_batch(&mut ring, writes, &mut ready, &mut completions);
            for &(fd, result) in &completions {
                let conn = conns[fd].as_mut().unwrap();
                if result > 0 {
                    conn.out_off += result as usize;
                } else if result != -libc::EAGAIN && result != -libc::EINTR {
                    unsafe {
                        libc::close(fd as _);
                    }
                    conns[fd] = None;
                    continue;
                }
                let pending = conn.out_off < conn.outbuf.len();
                if !pending {
                    conn.outbuf.clear();
                    conn.out_off = 0;
                }
            }
        }
        for &(token, _) in &events {
            if token == LISTENER {
                continue;
            }
            if let Some(conn) = conns[token as usize].as_ref() {
                let flags = libc::POLLIN
                    | if conn.out_off < conn.outbuf.len() {
                        libc::POLLOUT
                    } else {
                        0
                    };
                arm_poll(&mut ring, token as RawFd, flags, token);
            }
        }
        // Accept only after the old batch is retired: accept4 may reuse any
        // descriptor closed above, and its poll must be armed exactly once.
        if events.iter().any(|&(token, _)| token == LISTENER) {
            accept_batch(&mut ring, lfd, &mut conns);
            arm_poll(&mut ring, lfd, libc::POLLIN, LISTENER);
        }
    }
}

/// Submit queued entries even when readiness completions are already available.
fn submit(ring: &mut io_uring::IoUring, count: usize) {
    loop {
        match ring.submit_and_wait(count) {
            Ok(_) => return,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => panic!("io_uring submit: {e}"),
        }
    }
}

/// The caller must keep an entry's buffers valid until its completion is drained.
unsafe fn push(ring: &mut io_uring::IoUring, entry: &io_uring::squeue::Entry) {
    while unsafe { ring.submission().push(entry) }.is_err() {
        submit(ring, 0);
    }
}

fn arm_poll(ring: &mut io_uring::IoUring, fd: RawFd, flags: i16, token: u64) {
    let entry = io_uring::opcode::PollAdd::new(io_uring::types::Fd(fd), flags as u32)
        .build()
        .user_data(token);
    // PollAdd borrows no userspace storage.
    unsafe { push(ring, &entry) };
}

fn drain_completions(
    ring: &mut io_uring::IoUring,
    ready: &mut VecDeque<(u64, i32)>,
    completions: &mut Vec<(usize, i32)>,
) {
    for c in ring.completion() {
        if c.user_data() & IO == 0 {
            ready.push_back((c.user_data(), c.result()));
        } else {
            completions.push(((c.user_data() & !IO) as usize, c.result()));
        }
    }
}

fn wait_batch(
    ring: &mut io_uring::IoUring,
    count: usize,
    ready: &mut VecDeque<(u64, i32)>,
    completions: &mut Vec<(usize, i32)>,
) {
    completions.clear();
    while completions.len() < count {
        // Poll completions can arrive alongside I/O. Save them for the next
        // batch, and count only I/O completions toward the buffer barrier.
        submit(ring, 1);
        drain_completions(ring, ready, completions);
    }
}

#[cfg(test)]
mod h2_continuation_tests;

#[cfg(test)]
mod h1_body_tests;

#[cfg(test)]
mod h1_header_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preface_picks_http2_and_a_request_line_picks_http1() {
        assert_eq!(settle(h2::PREFACE), Which::H2);
        assert_eq!(settle(b"GET / HTTP/1.1\r\n"), Which::H1);
        assert_eq!(settle(b"POST / HTTP/1.1\r\n"), Which::H1);
    }

    /// "PRI" is a prefix of the preface, so a connection that has sent only
    /// that much has not said which protocol it is yet
    #[test]
    fn a_prefix_of_the_preface_is_not_yet_decided() {
        assert_eq!(settle(b""), Which::Undecided);
        assert_eq!(settle(b"PRI"), Which::Undecided);
        assert_eq!(
            settle(&h2::PREFACE[..h2::PREFACE.len() - 1]),
            Which::Undecided
        );
    }

    /// A method that starts like the preface and then does not
    #[test]
    fn a_request_that_starts_like_the_preface_is_still_http1() {
        assert_eq!(settle(b"PRINT / HTTP/1.1\r\n"), Which::H1);
    }
}
