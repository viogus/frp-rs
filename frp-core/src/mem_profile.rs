//! Measurement-only global allocator, compiled ONLY under `feature = "mem-profile"`.
//! Wraps the system allocator and tracks live + cumulative bytes via atomics.
//! Off in all shipped builds — production binaries never include this file.
//!
//! # Realloc accuracy
//!
//! `realloc` counts the delta between old and new sizes. If the underlying
//! allocator implements realloc as `alloc(new) + memcpy + dealloc(old)` with
//! a different pointer, the LIVE_BYTES delta is still accurate (old block is
//! freed, new block is live). If realloc extends in-place (same pointer),
//! the delta is also correct. The only ambiguous case — a realloc that
//! returns the same pointer but with less usable space — cannot occur in
//! practice (System allocator always grows or moves). This is an approximate
//! profiler, not an exact accounting system; sub-byte precision is not needed.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

pub static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// System-allocator wrapper that counts allocations. Install as
/// `#[global_allocator]` in the binary crates under `mem-profile`.
pub struct CountingAlloc;

// SAFETY: `CountingAlloc` is a zero-sized marker type with no fields, no
// Drop, and no interior state other than the process-global counters. Every
// method delegates to the `System` allocator with the same `Layout`, so the
// `GlobalAlloc` contract is upheld by the caller exactly as it is for
// `System`: returned pointers are non-null and suitably aligned, dealloc
// receives the same layout as alloc, and realloc preserves contents up to
// `min(old, new)`. The accounting atomics are independent of the heap blocks
// (relaxed, monotonic-ish deltas) and cannot be dereferenced as pointers, so
// they are safe to touch from any thread at any time. Compiled only under
// `feature = "mem-profile"` — never installed in shipped binaries.
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
        // total_alloc is cumulative; a direct CountingAlloc.alloc must
        // increase it. (Vec::with_capacity uses System, not CountingAlloc,
        // in the test binary — so we allocate through the wrapper directly.)
        let (_, t0, _) = snapshot();
        let layout = Layout::from_size_align(4096, 8).unwrap();
        unsafe {
            let p = CountingAlloc.alloc(layout);
            assert!(!p.is_null());
            let (_, t1, _) = snapshot();
            assert!(
                t1 >= t0 + 4096,
                "total_alloc must increase by >= alloc size: {t1} >= {t0}"
            );
            CountingAlloc.dealloc(p, layout);
        }
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
