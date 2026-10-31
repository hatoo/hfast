//! Bounded provided-buffer receives for classified HTTP/1 and HTTP/2 connections.
//! Unknown sockets retain poll/single-read batches; all sends keep their barrier.
use super::{BATCH, Conn, Proto, arm_poll, consume, push, submit};
use crate::sys;
use io_uring::{IoUring, cqueue, opcode, types};
use std::collections::VecDeque;

mod slots;
use slots::Slots;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU16, Ordering};

const CHUNK: usize = 16 * 1024;
const GROUP: u16 = 0;
const RECV: u64 = 1 << 60;
const POLL: u64 = 2 << 60;
const SEND: u64 = 3 << 60;
const READ: u64 = 4 << 60;
const KIND: u64 = 15 << 60;
const LISTEN: u64 = u64::MAX;
const CANCEL: u64 = u64::MAX - 1;
const PROBE: u64 = u64::MAX - 2;

#[repr(C)]
struct Descriptor {
    addr: u64,
    len: u32,
    id: u16,
    tail: u16,
}

/// mmap storage has stable addresses and no Rust references while the kernel owns
/// it. Only a completed buffer gets a shared slice; release requires &mut self.
struct Pool {
    descriptors: *mut Descriptor,
    payload: *mut u8,
    owned: Vec<bool>,
    tail: u16,
    published: u16,
    epoch: u64,
    keep_mapped: bool,
}

fn mapping(len: usize) -> io::Result<*mut u8> {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(p.cast())
    }
}

impl Pool {
    fn new(count: usize) -> io::Result<Self> {
        assert!(count.is_power_of_two() && count <= 32768);
        let descriptors = mapping(count * size_of::<Descriptor>())?.cast();
        let payload = match mapping(count * CHUNK) {
            Ok(p) => p,
            Err(e) => {
                unsafe {
                    libc::munmap(descriptors, count * size_of::<Descriptor>());
                }
                return Err(e);
            }
        };
        let mut pool = Self {
            descriptors: descriptors.cast(),
            payload,
            owned: vec![true; count],
            tail: 0,
            published: 0,
            epoch: 0,
            keep_mapped: false,
        };
        for id in 0..count {
            pool.release(id as u16);
        }
        pool.publish();
        Ok(pool)
    }

    fn claim(&mut self, result: i32, flags: u32) -> Option<u16> {
        let id = cqueue::buffer_select(flags);
        assert!(result <= CHUNK as i32);
        assert!(
            result <= 0 || id.is_some(),
            "positive receive without a buffer"
        );
        if let Some(id) = id {
            let owned = &mut self.owned[id as usize];
            assert!(!*owned, "provided buffer completed twice before release");
            *owned = true;
        }
        id
    }

    fn bytes(&self, id: u16, len: usize) -> &[u8] {
        assert!(self.owned[id as usize] && len <= CHUNK);
        // The CQE transferred exclusive ownership of this whole (non-incremental)
        // buffer. It cannot be selected again until release and publish.
        unsafe { std::slice::from_raw_parts(self.payload.add(id as usize * CHUNK), len) }
    }

    fn release(&mut self, id: u16) {
        assert!(self.owned[id as usize], "buffer returned twice");
        self.owned[id as usize] = false;
        let slot = self.tail as usize & (self.owned.len() - 1);
        // Write only descriptor fields, never the reserved/tail field. In slot 0
        // that field is shared with the kernel and published with release order.
        unsafe {
            let p = self.descriptors.add(slot);
            std::ptr::addr_of_mut!((*p).addr).write(self.payload.add(id as usize * CHUNK) as u64);
            std::ptr::addr_of_mut!((*p).len).write(CHUNK as u32);
            std::ptr::addr_of_mut!((*p).id).write(id);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn publish(&mut self) {
        let n = self.tail.wrapping_sub(self.published);
        if n == 0 {
            return;
        }
        unsafe {
            AtomicU16::from_ptr(std::ptr::addr_of_mut!((*self.descriptors).tail))
                .store(self.tail, Ordering::Release);
        }
        self.published = self.tail;
        self.epoch = self
            .epoch
            .checked_add(n as u64)
            .expect("buffer epoch exhausted");
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        if !self.keep_mapped {
            unsafe {
                libc::munmap(
                    self.descriptors.cast(),
                    self.owned.len() * size_of::<Descriptor>(),
                );
                libc::munmap(self.payload.cast(), self.owned.len() * CHUNK);
            }
        }
    }
}

struct ReceiveRing {
    ring: Option<IoUring>,
    pool: Pool,
}

impl ReceiveRing {
    fn new(ring: IoUring, count: usize) -> Result<Self, Box<IoUring>> {
        if !ring.params().is_feature_nodrop() {
            return Err(Box::new(ring));
        }
        let Ok(pool) = Pool::new(count) else {
            return Err(Box::new(ring));
        };
        // pool outlives registration and every receive; Drop synchronously cancels
        // operations before either mapping can be released, including on unwind.
        if unsafe {
            ring.submitter().register_buf_ring_with_flags(
                pool.descriptors as u64,
                count as u16,
                GROUP,
                0,
            )
        }
        .is_err()
        {
            return Err(Box::new(ring));
        }
        Ok(Self {
            ring: Some(ring),
            pool,
        })
    }

    fn ring(&mut self) -> &mut IoUring {
        self.ring.as_mut().unwrap()
    }

    /// Test the flags on a real stream operation, not just the RECV opcode probe.
    /// EOF retires even a supported multishot operation before fallback is allowed.
    fn supported(&mut self) -> bool {
        self.probe(0)
    }

    fn probe(&mut self, flags: i32) -> bool {
        let (socket, mut peer) = UnixStream::pair().expect("receive support socketpair");
        peer.write_all(b"p").unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let entry = opcode::RecvMulti::new(types::Fd(socket.as_raw_fd()), GROUP)
            .flags(flags)
            .build()
            .user_data(PROBE);
        unsafe {
            push(self.ring(), &entry);
        }
        let mut received = false;
        let mut terminal = false;
        while !terminal {
            submit(self.ring(), 1);
            let (ring, pool) = (self.ring.as_mut().unwrap(), &mut self.pool);
            for c in ring.completion() {
                assert_eq!(c.user_data(), PROBE);
                let id = pool.claim(c.result(), c.flags());
                if c.result() > 0 {
                    assert_eq!(pool.bytes(id.unwrap(), c.result() as usize), b"p");
                    received = true;
                }
                if let Some(id) = id {
                    pool.release(id);
                }
                terminal = !cqueue::more(c.flags());
            }
            self.pool.publish();
        }
        received
    }

    fn fallback(mut self) -> IoUring {
        // supported() drained the terminal CQE, so no receive holds a buffer.
        self.ring().submitter().unregister_buf_ring(GROUP).unwrap();
        self.ring.take().unwrap()
    }
}

impl Drop for ReceiveRing {
    fn drop(&mut self) {
        if let Some(ring) = &self.ring {
            // On normal process lifetime this is unreachable. Tests and unwinding
            // must nevertheless not unmap buffers while a kernel receive owns one.
            let result = ring
                .submitter()
                .register_sync_cancel(None, types::CancelBuilder::any());
            if result
                .as_ref()
                .is_err_and(|e| e.raw_os_error() != Some(libc::ENOENT))
            {
                // Send storage also must survive a failed synchronous teardown.
                eprintln!("could not synchronously retire TCP I/O: {result:?}");
                std::process::abort();
            }
            if ring.submitter().unregister_buf_ring(GROUP).is_err() {
                self.pool.keep_mapped = true;
            }
        }
    }
}

struct Socket {
    fd: OwnedFd,
    conn: Conn,
    recv_active: bool,
    recv_epoch: u64,
    starved: bool,
    poll_active: bool,
    queued: bool,
}

impl Socket {
    fn multishot(&self) -> bool {
        matches!(self.conn.proto, Proto::H1 { .. } | Proto::H2(_))
    }

    fn closing(&self) -> bool {
        self.conn.closing()
    }
}

#[derive(Clone, Copy)]
struct Event {
    token: u64,
    result: i32,
    more: bool,
    buffer: Option<u16>,
}

struct Worker {
    // Cancel all kernel borrows before connection/send storage is dropped.
    io: ReceiveRing,
    sockets: Slots<Socket>,
    pending: VecDeque<Event>,
    touched: Vec<u64>,
    single: Vec<u64>,
    read_results: Vec<(usize, i32)>,
    scratch: Vec<u8>,
    writes: Vec<(u64, i32)>,
    starved: VecDeque<(u64, u64)>,
    retry_epoch: u64,
    retry_remaining: usize,
    #[cfg(test)]
    receives: Vec<(u64, bool)>,
}

impl Worker {
    fn new(io: ReceiveRing) -> Self {
        Self {
            io,
            sockets: Slots::new(),
            pending: VecDeque::new(),
            touched: Vec::with_capacity(BATCH),
            single: Vec::with_capacity(BATCH),
            read_results: Vec::with_capacity(BATCH),
            scratch: vec![0; BATCH * CHUNK],
            writes: Vec::with_capacity(BATCH),
            starved: VecDeque::new(),
            retry_epoch: 0,
            retry_remaining: 0,
            #[cfg(test)]
            receives: Vec::new(),
        }
    }

    fn socket(&mut self, key: u64) -> Option<&mut Socket> {
        self.sockets.get_mut(key)
    }

    fn insert(&mut self, fd: OwnedFd) -> u64 {
        let key = self.sockets.insert(Socket {
            fd,
            conn: Conn::new(),
            recv_active: false,
            recv_epoch: 0,
            starved: false,
            poll_active: false,
            queued: false,
        });
        self.rearm(key);
        key
    }

    fn arm_receive(&mut self, key: u64) {
        let epoch = self.io.pool.epoch;
        let Some(s) = self.socket(key) else {
            return;
        };
        if !s.multishot() || s.recv_active || s.starved || s.closing() {
            return;
        }
        s.recv_active = true;
        s.recv_epoch = epoch;
        let entry = opcode::RecvMulti::new(types::Fd(s.fd.as_raw_fd()), GROUP)
            .build()
            .user_data(key | RECV);
        #[cfg(test)]
        self.receives.push((key, true));
        unsafe {
            push(self.io.ring(), &entry);
        }
    }

    fn touch(&mut self, key: u64) {
        if let Some(s) = self.socket(key)
            && !s.queued
        {
            s.queued = true;
            self.touched.push(key);
        }
    }

    fn cancel(&mut self, token: u64) {
        let entry = opcode::AsyncCancel::new(token).build().user_data(CANCEL);
        unsafe {
            push(self.io.ring(), &entry);
        }
    }

    fn retire(&mut self, key: u64) {
        let Some(s) = self.socket(key) else {
            return;
        };
        let (read, poll) = (s.recv_active, s.poll_active);
        if read {
            self.cancel(key | RECV);
        }
        if poll {
            self.cancel(key | POLL);
        }
        self.sockets.remove(key).unwrap();
        // Every old CQE (including buffered data) carries the retired generation.
    }

    fn drain(&mut self) {
        let ring = self.io.ring.as_mut().unwrap();
        for c in ring.completion() {
            let token = c.user_data();
            if token == CANCEL {
                continue;
            }
            if token & KIND == SEND {
                self.writes.push((token & !KIND, c.result()));
            } else if token & KIND == READ {
                self.read_results
                    .push(((token & !KIND) as usize, c.result()));
            } else {
                let buffer = if token != LISTEN && token & KIND == RECV {
                    self.io.pool.claim(c.result(), c.flags())
                } else {
                    None
                };
                self.pending.push_back(Event {
                    token,
                    result: c.result(),
                    more: cqueue::more(c.flags()),
                    buffer,
                });
            }
        }
    }

    fn event(&mut self, e: Event) {
        let key = e.token & !KIND;
        let kind = e.token & KIND;
        let mut alive = true;
        if let Some(s) = self.sockets.get_mut(key) {
            if kind == RECV {
                if !e.more {
                    s.recv_active = false;
                }
                if e.result > 0 && !s.closing() {
                    alive = consume(
                        &mut s.conn,
                        self.io.pool.bytes(e.buffer.unwrap(), e.result as usize),
                    );
                } else if e.result == 0 {
                    s.conn.read_eof = true;
                } else if e.result == -libc::ENOBUFS {
                    assert!(!e.more);
                    if !s.starved && !s.closing() {
                        s.starved = true;
                        self.starved.push_back((key, s.recv_epoch));
                        if s.recv_epoch != self.io.pool.epoch {
                            self.retry_remaining = self.starved.len();
                        }
                    }
                } else if e.result < 0 && e.result != -libc::EINTR && e.result != -libc::EAGAIN {
                    alive = false;
                }
            } else {
                assert_eq!(kind, POLL);
                s.poll_active = false;
                alive = e.result >= 0
                    && e.result & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) as i32 == 0;
                if alive && e.result & libc::POLLIN as i32 != 0 {
                    assert!(!s.recv_active && !s.multishot());
                    self.single.push(key);
                }
            }
        }
        // Even CQEs for retired descriptors return their buffers exactly once.
        if let Some(id) = e.buffer {
            self.io.pool.release(id);
        }
        if alive {
            self.touch(key);
        } else {
            self.retire(key);
        }
    }

    fn retry_starved(&mut self) {
        let epoch = self.io.pool.epoch;
        if epoch != self.retry_epoch {
            self.retry_epoch = epoch;
            self.retry_remaining = self.starved.len();
        }
        for _ in 0..self.retry_remaining.min(BATCH) {
            self.retry_remaining -= 1;
            let (key, attempted) = self.starved.pop_front().unwrap();
            if self.socket(key).is_none() {
                continue;
            }
            if epoch == attempted {
                self.starved.push_back((key, attempted));
            } else {
                self.socket(key).unwrap().starved = false;
                self.arm_receive(key);
            }
        }
    }

    /// One scratch chunk per ready poll, with the same read barrier as the
    /// fallback worker. No connection can retire or change protocol until all
    /// these reads finish. Multishot CQEs wait in pending during this barrier.
    fn read_batch(&mut self) {
        self.read_results.clear();
        assert!(self.single.len() <= BATCH);
        for i in 0..self.single.len() {
            let key = self.single[i];
            let fd = self.socket(key).unwrap().fd.as_raw_fd();
            let entry = opcode::Recv::new(
                types::Fd(fd),
                unsafe { self.scratch.as_mut_ptr().add(i * CHUNK) },
                CHUNK as u32,
            )
            .flags(libc::MSG_DONTWAIT)
            .build()
            .user_data(READ | i as u64);
            #[cfg(test)]
            self.receives.push((key, false));
            unsafe { push(self.io.ring(), &entry) };
        }
        while self.read_results.len() < self.single.len() {
            submit(self.io.ring(), 1);
            self.drain();
        }
        assert_eq!(self.read_results.len(), self.single.len());
        for i in 0..self.read_results.len() {
            let (slot, result) = self.read_results[i];
            let key = self.single[slot];
            let conn = &mut self.sockets.get_mut(key).unwrap().conn;
            let alive = if result > 0 {
                assert!(result <= CHUNK as i32);
                consume(
                    conn,
                    &self.scratch[slot * CHUNK..slot * CHUNK + result as usize],
                )
            } else if result == 0 {
                conn.read_eof = true;
                true
            } else {
                result == -libc::EAGAIN || result == -libc::EINTR
            };
            if !alive {
                self.retire(key);
            }
        }
    }

    fn rearm(&mut self, key: u64) {
        let Some(s) = self.socket(key) else {
            return;
        };
        s.queued = false;
        if s.closing() && s.conn.outbuf.is_empty() {
            self.retire(key);
            return;
        }
        // Classification occurs only after the old poll and single read have
        // completed. The switch cannot leave a second input operation alive.
        let flags = if !s.closing() && !s.multishot() {
            libc::POLLIN
        } else {
            0
        } | if !s.conn.outbuf.is_empty() {
            libc::POLLOUT
        } else {
            0
        };
        if flags != 0 && !s.poll_active {
            s.poll_active = true;
            let fd = s.fd.as_raw_fd();
            arm_poll(self.io.ring(), fd, flags, key | POLL);
        }
        self.arm_receive(key);
    }

    fn step(&mut self, lfd: RawFd, wait: bool) {
        submit(
            self.io.ring(),
            usize::from(wait && self.pending.is_empty() && self.retry_remaining == 0),
        );
        self.drain();
        self.touched.clear();
        self.single.clear();
        let mut listener = false;
        for _ in 0..self.pending.len().min(BATCH) {
            let event = self.pending.pop_front().unwrap();
            if event.token == LISTEN {
                assert!(event.result >= 0, "listener poll: {}", event.result);
                listener = true;
            } else {
                self.event(event);
            }
        }
        self.read_batch();
        self.io.pool.publish();
        self.retry_starved();
        self.writes.clear();
        let mut count = 0;
        for i in 0..self.touched.len() {
            let key = self.touched[i];
            let Some(s) = self.socket(key) else {
                continue;
            };
            let conn = &s.conn;
            if conn.out_off < conn.outbuf.len() {
                let entry = opcode::Send::new(
                    types::Fd(s.fd.as_raw_fd()),
                    unsafe { conn.outbuf.as_ptr().add(conn.out_off) },
                    (conn.outbuf.len() - conn.out_off).min(u32::MAX as usize) as u32,
                )
                .flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
                .build()
                .user_data(key | SEND);
                unsafe {
                    push(self.io.ring(), &entry);
                }
                count += 1;
            }
        }
        // Queue receive CQEs without consuming or recycling their buffers while
        // sends borrow outbuf. No accept/close/Vec relocation crosses this barrier.
        while self.writes.len() < count {
            submit(self.io.ring(), 1);
            self.drain();
        }
        assert_eq!(self.writes.len(), count);
        for i in 0..self.writes.len() {
            let (key, result) = self.writes[i];
            let s = self.socket(key).unwrap();
            if result > 0 {
                s.conn.out_off += result as usize;
            } else if result != -libc::EAGAIN && result != -libc::EINTR {
                self.retire(key);
                continue;
            }
            if s.conn.out_off == s.conn.outbuf.len() {
                s.conn.outbuf.clear();
                s.conn.out_off = 0;
            }
        }
        for i in 0..self.touched.len() {
            let key = self.touched[i];
            self.rearm(key);
        }
        if listener {
            for _ in 0..BATCH {
                let fd = sys::accept(lfd);
                if fd < 0 {
                    if sys::errno() == libc::EINTR {
                        continue;
                    }
                    break;
                }
                sys::set_nodelay(fd);
                self.insert(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            arm_poll(self.io.ring(), lfd, libc::POLLIN, LISTEN);
        }
    }
}

pub(super) fn worker(lfd: RawFd, cpu: usize, ring: IoUring) -> IoUring {
    let mut io = match ReceiveRing::new(ring, BATCH) {
        Ok(io) => io,
        Err(ring) => return *ring,
    };
    if !io.supported() {
        return io.fallback();
    }
    sys::pin_to_cpu(cpu);
    arm_poll(io.ring(), lfd, libc::POLLIN, LISTEN);
    let mut worker = Worker::new(io);
    loop {
        worker.step(lfd, true);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod selection_tests;

#[cfg(test)]
mod h2_tests;

#[cfg(test)]
mod taskrun_tests;
