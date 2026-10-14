use super::super::tests::{h1_pair, pair, response, ring, until};
use super::super::{Event, KIND, POLL, RECV, Worker, submit};
use super::*;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

#[test]
fn reuse_rejects_stale_and_malformed_identities() {
    let mut slots = Slots::new();
    let first = slots.insert(11);
    let other = slots.insert(22);
    assert_eq!(slots.remove(first), Some(11));
    assert_eq!(slots.remove(first), None);
    let next = slots.insert(33);
    assert_eq!(first & INDEX_MASK, next & INDEX_MASK);
    assert_eq!(next, first + GENERATION_STEP);
    for key in [
        0,
        first,
        next | RECV,
        next | KIND,
        u64::MAX,
        initial_key(99),
    ] {
        assert_eq!(slots.get_mut(key), None);
        assert_eq!(slots.remove(key), None);
    }
    assert_eq!(slots.get_mut(next), Some(&mut 33));
    assert_eq!(slots.get_mut(other), Some(&mut 22));
    assert_eq!(slots.entries.len(), 2);
    assert!(slots.free.is_empty());
}

#[test]
fn ordinary_churn_bounds_storage_by_peak_live_connections() {
    let mut slots = Slots::new();
    let mut keys = (0..31).map(|i| slots.insert(i)).collect::<Vec<_>>();
    let mut retired = Vec::new();
    for n in 0..100_000 {
        let index = (n * 17) % keys.len();
        let old = keys[index];
        assert!(slots.remove(old).is_some());
        retired.push(old);
        keys[index] = slots.insert(n);
        assert!(slots.get_mut(old).is_none());
    }
    assert_eq!(slots.entries.len(), keys.len());
    assert!(slots.free.is_empty());
    for key in retired {
        assert!(slots.get_mut(key).is_none());
        assert!(slots.remove(key).is_none());
    }
    for key in keys {
        assert!(slots.remove(key).is_some());
    }
    assert!(slots.is_empty());
    assert_eq!(slots.entries.len(), slots.free.len());
}

#[test]
fn exhausted_slot_is_never_reused_and_other_slots_keep_recycling() {
    let mut slots = Slots::new();
    let old = slots.insert(10);
    let other = slots.insert(20);
    slots.remove(old).unwrap();
    slots.entries[0].key = (MAX_GENERATION - 1) << INDEX_BITS;
    let last = slots.insert(30);
    assert_eq!(last >> INDEX_BITS, MAX_GENERATION);
    assert_eq!(slots.remove(last), Some(30));
    assert!(slots.free.is_empty());
    let new = slots.insert(40);
    assert_eq!(new & INDEX_MASK, 2);
    for key in [old, last, last - GENERATION_STEP] {
        assert!(slots.get_mut(key).is_none());
        assert!(slots.remove(key).is_none());
    }
    assert_eq!(slots.remove(other), Some(20));
    let recycled = slots.insert(50);
    assert_eq!(recycled & INDEX_MASK, other & INDEX_MASK);
    assert_eq!(slots.entries.len(), 3);
    assert_eq!(slots.get(new), Some(&40));
    assert_eq!(slots.get(recycled), Some(&50));
}

#[test]
fn last_slot_index_still_leaves_all_generation_and_kind_bits_distinct() {
    let key = initial_key(INDEX_MASK as usize);
    assert_eq!(key & INDEX_MASK, INDEX_MASK);
    assert_eq!(key >> INDEX_BITS, 1);
    assert_eq!((MAX_GENERATION << INDEX_BITS) | INDEX_MASK, RECV - 1);
}

#[test]
#[should_panic(expected = "connection slots exhausted")]
fn capacity_exhaustion_does_not_truncate_the_slot_index() {
    initial_key(INDEX_MASK as usize + 1);
}

#[test]
fn high_descriptors_do_not_expand_connection_storage() {
    let mut worker = Worker::new(ring(2));
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
        0
    );
    // Use fd 65536 here, while also allowing CI workers with lower fd limits.
    let minimum = 65536.min(unsafe { limit.assume_init() }.rlim_cur.saturating_sub(1)) as i32;
    let high = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(high >= minimum);
    drop(socket);
    peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let key = worker.insert(unsafe { OwnedFd::from_raw_fd(high) });
    assert_eq!(worker.sockets.entries.len(), 1);
    peer.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    peer.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.is_empty());
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    assert!(worker.socket(key).is_none());
    assert_eq!(worker.sockets.free.len(), 1);
}

#[test]
fn late_buffers_and_terminals_cannot_modify_reused_or_exhausted_slots() {
    let mut worker = Worker::new(ring(2));
    let (seed, _peer) = pair(&mut worker);
    submit(worker.io.ring(), 0);
    worker.retire(seed);
    // Seed a free slot so two real connections cross both the former 28-bit
    // global identity limit and the final per-slot generation without wrapping.
    worker.sockets.entries[0].key = (MAX_GENERATION - 2) << INDEX_BITS;
    let (old, mut peer) = h1_pair(&mut worker);
    peer.write_all(b"GET / HTTP/1.1\r\nHost: late\r\n\r\n")
        .unwrap();
    // The seed's cancellation may complete before this receive. Wait for the
    // actual selected buffer without consuming it or depending on CQE order.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !worker
        .pending
        .iter()
        .any(|e| e.token == old | RECV && e.buffer.is_some())
    {
        submit(worker.io.ring(), 0);
        worker.drain();
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    let pos = worker
        .pending
        .iter()
        .position(|e| e.token == old | RECV && e.buffer.is_some())
        .unwrap();
    let stale = worker.pending.remove(pos).unwrap();
    assert_eq!(stale.token, old | RECV);
    worker.retire(old);
    let (last, _peer2) = h1_pair(&mut worker);
    assert_eq!(last, MAX_GENERATION << INDEX_BITS);
    assert_eq!(old & INDEX_MASK, last & INDEX_MASK);
    let tail = worker.io.pool.tail;
    worker.event(stale);
    assert_eq!(worker.io.pool.tail, tail.wrapping_add(1));
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
    for result in [0, -libc::ECANCELED, -libc::ENOBUFS] {
        worker.event(Event {
            token: old | RECV,
            result,
            more: false,
            buffer: None,
        });
        let s = worker.socket(last).unwrap();
        assert!(s.recv_active && !s.conn.read_eof && !s.starved && s.conn.outbuf.is_empty());
    }
    submit(worker.io.ring(), 0);
    worker.retire(last);
    let (new, mut peer3) = pair(&mut worker);
    assert_ne!(new & INDEX_MASK, last & INDEX_MASK);
    let queued_reads = worker.single.clone();
    for old_key in [seed, old, last] {
        for (kind, result) in [
            (RECV, 0),
            (RECV, -libc::ECANCELED),
            (POLL, libc::POLLIN as i32),
        ] {
            worker.event(Event {
                token: old_key | kind,
                result,
                more: false,
                buffer: None,
            });
        }
    }
    assert_eq!(worker.single, queued_reads);
    assert!(worker.socket(new).unwrap().poll_active);
    assert!(!worker.socket(new).unwrap().conn.read_eof);
    peer3
        .write_all(b"GET / HTTP/1.1\r\nHost: replacement\r\n\r\n")
        .unwrap();
    peer3.shutdown(std::net::Shutdown::Write).unwrap();
    until(&mut worker, |w| w.sockets.is_empty());
    let mut bytes = Vec::new();
    peer3.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, response());
    assert_eq!(worker.sockets.entries.len(), 2);
    assert!(worker.io.pool.owned.iter().all(|&b| !b));
}
