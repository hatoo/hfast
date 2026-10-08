//! The TCP side: one thread per core, each with its own listener and epoll
//!
//! Both HTTP/1.1 and HTTP/2 are served on the same port. Which one a connection
//! is talking is decided by its first bytes: HTTP/2 over cleartext opens with a
//! preface (RFC 9113 Section 3.4) that no HTTP/1.1 request can begin with, so
//! nothing has to be negotiated and no client has to be told which port to use.

use std::os::fd::RawFd;

use crate::sys::{self, epoll_add, epoll_mod};
use crate::{h1, h2};

const READ_SIZE: usize = 64 * 1024;
const LISTENER: u64 = u64::MAX;

enum Proto {
    /// Too few bytes to tell yet
    Unknown,
    H1,
    H2(h2::Conn),
}

struct Conn {
    /// Bytes read but not yet consumed as whole requests or frames
    inbuf: Vec<u8>,
    /// Responses waiting to go out, written once per wakeup
    outbuf: Vec<u8>,
    /// How much of `outbuf` the socket has taken
    out_off: usize,
    proto: Proto,
    /// EPOLLOUT is armed because a write came up short
    want_write: bool,
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
            want_write: false,
        }
    }

    /// Answer everything complete in `buf`, returning how much of it was used,
    /// or `None` if the connection is over.
    fn drive(&mut self, buf: &[u8]) -> Option<usize> {
        let mut at = 0;
        if let Proto::Unknown = self.proto {
            match settle(buf) {
                Which::Undecided => return Some(0), // wait for more bytes
                Which::H1 => self.proto = Proto::H1,
                Which::H2 => {
                    at = h2::PREFACE.len();
                    self.proto = Proto::H2(h2::Conn::new(&mut self.outbuf));
                }
            }
        }
        match &mut self.proto {
            Proto::H1 => loop {
                match h1::parse(&buf[at..]) {
                    h1::Request::Whole(n) => {
                        h1::respond(&mut self.outbuf);
                        at += n;
                    }
                    h1::Request::Partial => break,
                    h1::Request::Bad => return None,
                }
            },
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
    if let Ok(ring) = io_uring::IoUring::new(128) {
        worker_ring(lfd, cpu, ring);
    }
    sys::pin_to_cpu(cpu);
    let ep = sys::epoll_create();
    epoll_add(ep, lfd, libc::EPOLLIN as u32, LISTENER);

    // Indexed by fd: the kernel hands out the lowest free one, so this stays as
    // dense as the connection count and costs one bounds check to look up.
    let mut conns: Vec<Option<Conn>> = Vec::new();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; 1024];
    let mut scratch = vec![0u8; READ_SIZE];

    loop {
        let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            if sys::errno() == libc::EINTR {
                continue;
            }
            return;
        }
        for ev in &events[..n as usize] {
            if ev.u64 == LISTENER {
                accept_all(ep, lfd, &mut conns);
                continue;
            }
            let fd = ev.u64 as RawFd;
            if conns.get(fd as usize).and_then(|c| c.as_ref()).is_none() {
                continue;
            }
            let mut close = ev.events & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0;
            if !close && ev.events & libc::EPOLLIN as u32 != 0 {
                close = !read_and_drive(fd, conns[fd as usize].as_mut().unwrap(), &mut scratch);
            }
            if !close {
                close = !write_out(ep, fd, conns[fd as usize].as_mut().unwrap());
            }
            if close {
                unsafe { libc::close(fd) };
                conns[fd as usize] = None;
            }
        }
    }
}

fn accept_all(ep: RawFd, lfd: RawFd, conns: &mut Vec<Option<Conn>>) {
    loop {
        let fd = sys::accept(lfd);
        if fd < 0 {
            return;
        }
        sys::set_nodelay(fd);
        if conns.len() <= fd as usize {
            conns.resize_with(fd as usize + 1, || None);
        }
        conns[fd as usize] = Some(Conn::new());
        epoll_add(ep, fd, libc::EPOLLIN as u32, fd as u64);
    }
}

/// Read until the socket is empty, answering as each read arrives
///
/// A read that finds nothing carried over is parsed where it landed, and only
/// the trailing partial request is copied anywhere. Appending every read to a
/// buffer first and then shifting that buffer down over what was used was two
/// copies a request, for the sake of the rare one that spans two reads.
fn read_and_drive(fd: RawFd, conn: &mut Conn, scratch: &mut [u8]) -> bool {
    loop {
        let r = unsafe { libc::read(fd, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len()) };
        if r == 0 {
            return false;
        }
        if r < 0 {
            let e = sys::errno();
            return e == libc::EAGAIN || e == libc::EINTR;
        }
        let n = r as usize;
        if !consume(conn, &scratch[..n]) {
            return false;
        }
        if n < scratch.len() {
            return true;
        }
    }
}

/// One write per wakeup, however many responses landed in it. This is why
/// HTTP/2 costs the kernel so much less per request than HTTP/1.1 does.
fn write_out(ep: RawFd, fd: RawFd, conn: &mut Conn) -> bool {
    while conn.out_off < conn.outbuf.len() {
        let w = unsafe {
            libc::write(
                fd,
                conn.outbuf.as_ptr().add(conn.out_off) as *const libc::c_void,
                conn.outbuf.len() - conn.out_off,
            )
        };
        if w > 0 {
            conn.out_off += w as usize;
            continue;
        }
        let e = sys::errno();
        if e == libc::EAGAIN {
            if !conn.want_write {
                conn.want_write = true;
                epoll_mod(ep, fd, (libc::EPOLLIN | libc::EPOLLOUT) as u32, fd as u64);
            }
            return true;
        }
        if e != libc::EINTR {
            return false;
        }
    }
    conn.outbuf.clear();
    conn.out_off = 0;
    if conn.want_write {
        conn.want_write = false;
        epoll_mod(ep, fd, libc::EPOLLIN as u32, fd as u64);
    }
    true
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
    const BATCH: usize = 128;
    const CHUNK: usize = 16 * 1024;
    sys::pin_to_cpu(cpu);
    let ep = sys::epoll_create();
    epoll_add(ep, lfd, libc::EPOLLIN as u32, LISTENER);
    let mut conns: Vec<Option<Conn>> = Vec::new();
    let mut events = vec![libc::epoll_event { events: 0, u64: 0 }; BATCH];
    let mut scratch = vec![0u8; BATCH * CHUNK];
    let mut completions = Vec::with_capacity(BATCH);
    loop {
        let n = unsafe { libc::epoll_wait(ep, events.as_mut_ptr(), BATCH as _, -1) };
        if n < 0 {
            continue;
        }
        let mut reads = 0;
        for (i, ev) in events[..n as usize].iter().enumerate() {
            if ev.u64 == LISTENER {
                accept_all(ep, lfd, &mut conns);
                continue;
            }
            let fd = ev.u64 as RawFd;
            if conns.get(fd as usize).and_then(Option::as_ref).is_none() {
                continue;
            }
            if ev.events & (libc::EPOLLHUP | libc::EPOLLERR) as u32 != 0 {
                unsafe {
                    libc::close(fd);
                }
                conns[fd as usize] = None;
                continue;
            }
            if ev.events & libc::EPOLLIN as u32 != 0 {
                let entry = opcode::Recv::new(
                    types::Fd(fd),
                    unsafe { scratch.as_mut_ptr().add(i * CHUNK) },
                    CHUNK as _,
                )
                .flags(libc::MSG_DONTWAIT)
                .build()
                .user_data(i as _);
                // scratch is stable and each receive owns a distinct chunk.
                unsafe {
                    ring.submission()
                        .push(&entry)
                        .expect("receive batch capacity");
                }
                reads += 1;
            }
        }
        if reads > 0 {
            wait_batch(&mut ring, reads);
            completions.clear();
            completions.extend(
                ring.completion()
                    .map(|c| (c.user_data() as usize, c.result())),
            );
            for &(i, result) in &completions {
                let fd = events[i].u64 as RawFd;
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
        for ev in &events[..n as usize] {
            if ev.u64 == LISTENER {
                continue;
            }
            let fd = ev.u64 as RawFd;
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
                .user_data(fd as _);
                // No outbuf is changed until all send completions are drained.
                unsafe {
                    ring.submission().push(&entry).expect("send batch capacity");
                }
                writes += 1;
            }
        }
        if writes > 0 {
            wait_batch(&mut ring, writes);
            completions.clear();
            completions.extend(
                ring.completion()
                    .map(|c| (c.user_data() as usize, c.result())),
            );
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
                if pending != conn.want_write {
                    conn.want_write = pending;
                    let flags = libc::EPOLLIN | if pending { libc::EPOLLOUT } else { 0 };
                    epoll_mod(ep, fd as _, flags as _, fd as _);
                }
            }
        }
    }
}

fn wait_batch(ring: &mut io_uring::IoUring, count: usize) {
    while ring.completion().len() < count {
        match ring.submit_and_wait(count) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
            Err(e) => panic!("io_uring batch: {e}"),
        }
    }
}

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
