//! Per-thread requested allocation counts for focused regression tests.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub allocations: usize,
    pub allocated: usize,
    pub freed: usize,
    /// Signed change from the start of the measured scope.
    pub live: isize,
    pub peak: isize,
}

thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}

fn record(allocated: usize, freed: usize, allocation: bool) {
    let _ = COUNTS.try_with(|cell| {
        if let Some(mut counts) = cell.get() {
            counts.allocations = counts.allocations.saturating_add(usize::from(allocation));
            counts.allocated = counts.allocated.saturating_add(allocated);
            counts.freed = counts.freed.saturating_add(freed);
            counts.live = counts
                .live
                .saturating_add(allocated as isize - freed as isize);
            counts.peak = counts.peak.max(counts.live);
            cell.set(Some(counts));
        }
    });
}

struct Allocator;

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

// SAFETY: Every operation delegates to System with the original allocation
// contract. Counting uses allocation-free thread-local Cells and never unwinds.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size(), 0, true);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size(), 0, true);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(0, layout.size(), false);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, size) };
        if !new_ptr.is_null() {
            record(size, layout.size(), true);
        }
        new_ptr
    }
}

pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    assert!(
        COUNTS.with(|cell| cell.get().is_none()),
        "nested measurement"
    );
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNTS.with(|cell| cell.set(None));
        }
    }
    let reset = Reset;
    COUNTS.with(|cell| cell.set(Some(Counts::default())));
    let result = f();
    let counts = COUNTS.with(|cell| cell.get().unwrap());
    drop(reset);
    (result, counts)
}
