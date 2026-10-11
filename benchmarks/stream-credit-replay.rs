use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Counter;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(n, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOC: Counter = Counter;
#[repr(C)]
struct Timespec {
    sec: i64,
    nano: i64,
}
unsafe extern "C" {
    fn clock_gettime(clock: i32, time: *mut Timespec) -> i32;
}
fn cpu() -> u64 {
    let mut t = Timespec { sec: 0, nano: 0 };
    assert_eq!(unsafe { clock_gettime(2, &mut t) }, 0);
    (t.sec as u64) * 1_000_000_000 + t.nano as u64
}

// Appended inside the production stream_credit module by stream-credit-replay.py.
mod replay {
    use super::*;
    use crate::{ALLOCS, BYTES, Ordering, black_box, cpu};

    #[unsafe(no_mangle)]
    #[inline(never)]
    fn c95_work(
        c: &mut StreamCredits,
        body: &mut Vec<u8>,
        mode: &str,
        n: usize,
        iterations: usize,
    ) {
        for i in 0..iterations {
            if mode.starts_with("ack") {
                assert!(!black_box(&mut *c).on_ack(black_box(9), 0, &[]));
            } else if mode.starts_with("timeout") {
                black_box(&mut *c).on_timeout();
                body.clear();
                c.write(body, usize::MAX, 10);
            } else {
                let count = if mode.ends_with("dense") { n } else { 1 };
                for j in 0..count {
                    c.update(((n - 1 - j) * 4) as u64, 128 + i as u64 * 64);
                }
                body.clear();
                c.write(body, usize::MAX, 10 + i as u64);
                assert!(c.on_ack(10 + i as u64, 0, &[]));
            }
            black_box(&*c);
        }
    }

    pub fn run(mode: &str, n: usize, iterations: usize) {
        let a0 = ALLOCS.load(Ordering::Relaxed);
        let b0 = BYTES.load(Ordering::Relaxed);
        let mut c = StreamCredits::new(64);
        let mut body = Vec::with_capacity(n * 17);
        for j in 0..n {
            c.update(j as u64 * 4, 32);
        }
        c.write(&mut body, usize::MAX, 1);
        assert!(c.on_ack(1, 0, &[]));
        let active = if mode.ends_with("dense") { n } else { 1 };
        for j in 0..active {
            c.update(((n - 1 - j) * 4) as u64, 64);
        }
        body.clear();
        c.write(&mut body, usize::MAX, 10);
        let build_allocations = ALLOCS.load(Ordering::Relaxed) - a0;
        let build_requested_bytes = BYTES.load(Ordering::Relaxed) - b0;
        let a1 = ALLOCS.load(Ordering::Relaxed);
        let start = cpu();
        c95_work(&mut c, &mut body, mode, n, iterations);
        let elapsed = cpu() - start;
        let work_allocations = ALLOCS.load(Ordering::Relaxed) - a1;
        assert_eq!(c.streams.len(), n);
        println!(
            "{{\"mode\":\"{mode}\",\"retained\":{n},\"active\":{active},\"iterations\":{iterations},\"cpu_ns\":{elapsed},\"build_allocations\":{build_allocations},\"build_requested_bytes\":{build_requested_bytes},\"work_allocations\":{work_allocations},\"credits_size\":{},\"update_size\":{}}}",
            std::mem::size_of::<StreamCredits>(),
            std::mem::size_of::<Update>()
        );
    }
}
