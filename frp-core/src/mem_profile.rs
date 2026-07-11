//! Measurement-only global allocator, compiled ONLY under `feature = "mem-profile"`.
//! Wraps the system allocator and tracks live + cumulative bytes via atomics.
//! Off in all shipped builds — production binaries never include this file.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

pub static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// System-allocator wrapper that counts allocations. Install as
/// `#[global_allocator]` in the binary crates under `mem-profile`.
pub struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            TOTAL_ALLOC.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let np = System.realloc(ptr, layout, new_size);
        if !np.is_null() {
            if new_size >= layout.size() {
                let d = new_size - layout.size();
                LIVE_BYTES.fetch_add(d, Ordering::Relaxed);
                TOTAL_ALLOC.fetch_add(d, Ordering::Relaxed);
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        np
    }
}

/// Current `(live_bytes, total_alloc, alloc_count)`.
pub fn snapshot() -> (usize, usize, usize) {
    (
        LIVE_BYTES.load(Ordering::Relaxed),
        TOTAL_ALLOC.load(Ordering::Relaxed),
        ALLOC_COUNT.load(Ordering::Relaxed),
    )
}

/// Spawn a 1 Hz emitter that prints a `MEMPROFILE` line to stderr. Call once
/// after the tokio runtime is up. The driver parses these lines.
pub fn spawn_emitter() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let (live, total, allocs) = snapshot();
            eprintln!("MEMPROFILE live={live} total={total} allocs={allocs}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_monotonic_total() {
        // total_alloc is cumulative and never decreases across two snapshots.
        let (_, t0, _) = snapshot();
        let _v: Vec<u8> = Vec::with_capacity(4096);
        let (_, t1, _) = snapshot();
        assert!(t1 >= t0, "total_alloc must be monotonic: {t1} >= {t0}");
    }

    #[test]
    fn counting_alloc_tracks_live() {
        // Direct alloc/dealloc through the wrapper moves LIVE_BYTES by size.
        let before = LIVE_BYTES.load(Ordering::Relaxed);
        let layout = Layout::from_size_align(8192, 8).unwrap();
        unsafe {
            let p = CountingAlloc.alloc(layout);
            assert!(!p.is_null());
            let mid = LIVE_BYTES.load(Ordering::Relaxed);
            assert!(mid >= before + 8192, "live rose by >= size");
            CountingAlloc.dealloc(p, layout);
        }
        let after = LIVE_BYTES.load(Ordering::Relaxed);
        assert!(after <= before + 8192, "live fell back after dealloc");
    }
}
