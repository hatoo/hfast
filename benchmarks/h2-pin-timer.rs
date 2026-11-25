// Test fixture only. Poll a monotonic timer independently of socket traffic.
// Timer events are consumed by step(), outside every read/send buffer barrier.
const PIN_TIMER: u64 = u64::MAX - 3;

struct PinTicker(OwnedFd);

impl PinTicker {
    fn new() -> Self {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        assert!(fd >= 0, "pin timerfd: {}", io::Error::last_os_error());
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let tick = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        let spec = libc::itimerspec {
            it_interval: tick,
            it_value: tick,
        };
        assert_eq!(
            unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) },
            0
        );
        Self(fd)
    }

    fn drain(&self) {
        let mut expirations = 0_u64;
        loop {
            let n =
                unsafe { libc::read(self.0.as_raw_fd(), (&mut expirations as *mut u64).cast(), 8) };
            if n == 8 {
                assert!(expirations > 0);
                return;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                panic!("pin timer read: {n}: {error}");
            }
        }
    }
}

impl Worker {
    fn start_pin_ticker(&mut self) {
        assert!(self.pin_ticker.is_none());
        let ticker = PinTicker::new();
        arm_poll(
            self.io.ring(),
            ticker.0.as_raw_fd(),
            libc::POLLIN,
            PIN_TIMER,
        );
        self.pin_ticker = Some(ticker);
    }

    fn pin_timer_event(&mut self) {
        let ticker = self.pin_ticker.as_ref().unwrap();
        ticker.drain();
        let fd = ticker.0.as_raw_fd();
        let now = std::time::Instant::now();
        for (key, socket) in self.sockets.iter_mut() {
            if socket.closing() {
                continue;
            }
            let conn = &mut socket.conn;
            if let Proto::H2(h2) = &mut conn.proto {
                let before = conn.outbuf.len();
                h2.pin_tick(now, &mut conn.outbuf);
                if conn.outbuf.len() != before && !socket.queued {
                    socket.queued = true;
                    self.touched.push(key);
                }
            }
        }
        arm_poll(self.io.ring(), fd, libc::POLLIN, PIN_TIMER);
    }
}

#[cfg(test)]
mod pin_timer_tests {
    use super::selection_tests::frame;
    use super::tests::{pair, ring, until};
    use super::*;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    #[test]
    fn independent_timer_wakes_idle_socket_and_survives_slot_reuse() {
        let mut worker = Worker::new(ring(2));
        worker.start_pin_ticker();
        let (old, _) = pair(&mut worker);
        worker.retire(old);
        let (key, mut peer) = pair(&mut worker);
        assert_ne!(key, old);
        peer.write_all(crate::h2::PREFACE).unwrap();
        until(&mut worker, |w| w.sockets.get(key).unwrap().recv_active);
        if let Proto::H2(h2) = &mut worker.socket(key).unwrap().conn.proto {
            h2.enable_pin_test();
        }
        peer.write_all(&frame(4, 1, 0, &[])).unwrap();
        peer.write_all(&frame(1, 5, 1, b"\x82")).unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut all = Vec::new();
        let end = Instant::now() + Duration::from_secs(5);
        let pause = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
        while !all.windows(pause.len()).any(|w| w == pause) {
            worker.step(-1, false);
            let mut bytes = [0; 4096];
            match peer.read(&mut bytes) {
                Ok(n) if n > 0 => all.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                r => panic!("unexpected timer read {r:?}"),
            }
            assert!(Instant::now() < end, "timer failed to wake idle connection");
        }
        assert_eq!(all.windows(pause.len()).filter(|w| *w == pause).count(), 1);
        worker.retire(key);
        until(&mut worker, |w| {
            w.sockets.is_empty() && w.pending.is_empty()
        });
        assert!(worker.io.pool.owned.iter().all(|owned| !owned));
    }
}
