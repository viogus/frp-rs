//! Simple buffer pool to reduce per-connection allocation pressure.
//!
//! The bridge module allocates bridge-sized read buffers per direction per
//! bridge call. Under high proxy connection churn, this creates sustained
//! allocator pressure. This pool recycles those buffers.
//!
//! Thread-safe (crossbeam lock-free `ArrayQueue` — the bridge acquires one
//! guard per connection (reused across all chunks of that bridge), and
//! concurrent releases during connection churn must not serialize on a
//! mutex). Fixed capacity:
//! `MAX_POOLED_BUFFERS` (128, env-overridable via `FRP_BRIDGE_POOL_MAX`).
//! Excess buffers are dropped.

use crossbeam_queue::ArrayQueue;
use std::sync::LazyLock;

/// Default pooled buffer size, in bytes, when `FRP_BRIDGE_BUF_KB` is unset.
///
/// 64 KiB everywhere except macOS. The buffer is also the yamux data-frame
/// payload (`mux.rs` derives `split_send_size` from it), so one full bridge
/// chunk travels as one frame — no second 12-byte header and no second
/// window-credit hand-off per chunk. The derived split is capped at 64 KiB,
/// which leaves the 12-byte frame header inside the WebSocket transport's
/// 65664-byte read limit (65548 of 65664 at 64 KiB), so anything above 64 KiB
/// does not buy more frames. It is also **not** harmless: with
/// `tcpMux` off, a WebSocket connection writes one transport frame per bridge
/// chunk, and above 64 KiB the peer rejects it ("WS frame too large") and drops
/// the session — keep `FRP_BRIDGE_BUF_KB` at or below 64 on `ws`/`wss` unless
/// `tcpMux` is on.
///
/// Measured on a 4-vCPU Linux VM against Go frp v0.72.0, five interleaved
/// pairs of the same binary with only this knob changing: `tcpMux` + TLS
/// 526.0 -> 597.0 MiB/s (**+13.5%**, every pair positive, +9.9% to +16.2%),
/// one flow 508.4 -> 573.5 (+12.8%), `ws` without `tcpMux` 1064 -> 1213
/// (+13.9%), and the no-mux plain and TLS rows unchanged within noise.
///
/// macOS keeps 32 KiB: the same 64 KiB buffer costs its non-mux WebSocket
/// rows ~40-45% there (301.5 -> 165.5 MiB/s for `ws`, 226.2 -> 134.0 for `wss`
/// via `scripts/protocol-matrix.sh`, three runs, knob as the only difference),
/// and its mux rows are within a few percent (one +8%, one -2.5%). The cause is
/// **unknown** — the frames there are the same size as a mux WS frame that does
/// not regress — so this is an observation about one code path on one OS, not a
/// transport property; `FRP_BRIDGE_BUF_KB` overrides it either way.
///
/// Measurements, cost model and the three structural alternatives that changed
/// nothing: `docs/archive/notes/2026-11-10-mux-frame-cost.md` and
/// `docs/archive/notes/2026-11-10-real-host-throughput.md`.
#[cfg(not(target_os = "macos"))]
const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Default pooled buffer size on macOS — see [`BUFFER_SIZE`].
#[cfg(target_os = "macos")]
const DEFAULT_BUFFER_SIZE: usize = 32 * 1024;

/// Pooled buffer size in bytes.
///
/// Default: [`DEFAULT_BUFFER_SIZE`] — 64 KiB, or 32 KiB on macOS. Keeping the
/// buffer equal to the frame payload is what makes a bridge chunk travel as a
/// single yamux frame; the per-bridge footprint is two buffers, so the default
/// costs 2x64 KiB (2x32 KiB on macOS) per live bridge.
///
/// Override via env `FRP_BRIDGE_BUF_KB` (valid range: 4-1024 KB, i.e. 4 KiB -
/// 1 MiB); values outside the range are ignored and the default applies. Read
/// once at process start via `LazyLock`.
///
/// This buffer size is used by the encrypted/compressed bridge data
/// path (`bridge.rs`), the V2 frame read path (`protocol.rs`), and —
/// via `copy_pooled`/`relay_plain_pooled` — the plain (unencrypted)
/// bridge path, so `FRP_BRIDGE_BUF_KB` applies uniformly.
pub static BUFFER_SIZE: LazyLock<usize> =
    LazyLock::new(|| resolve_buffer_size(std::env::var("FRP_BRIDGE_BUF_KB").ok().as_deref()));

/// Parse `FRP_BRIDGE_BUF_KB`, falling back to [`DEFAULT_BUFFER_SIZE`].
///
/// Kept as a pure function so the default/override rules are testable without
/// touching the process environment (which `BUFFER_SIZE` reads exactly once).
fn resolve_buffer_size(raw: Option<&str>) -> usize {
    raw.and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|kb| (4..=1024).contains(kb))
        .map(|kb| kb * 1024)
        .unwrap_or(DEFAULT_BUFFER_SIZE)
}

/// Maximum number of buffers to retain in the pool.
///
/// Default 128 (8 MiB of 64 KiB buffers, 4 MiB on macOS); override via
/// `FRP_BRIDGE_POOL_MAX` (capped at 4096). 32 was too small under high
/// connection churn — excess buffers were dropped and re-allocated. The
/// retained bytes scale with `FRP_BRIDGE_BUF_KB`: 128 x 64 KiB is the default
/// ceiling, and a 1 MiB buffer size reaches 128 MiB at the same count. The pool
/// only holds buffers that were used and released, so an idle process keeps
/// none of it. This ceiling covers this pool only: a compressed bridge also
/// holds `cap + cap/6 + 32` of compression scratch plus snap's encoder buffer
/// (a 64 KiB bridge is ~4x two buffers in total), and each KCP socket keeps its
/// own 8 x `BUFFER_SIZE` chunk pool.
static MAX_POOLED_BUFFERS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("FRP_BRIDGE_POOL_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        // Lower bound 4: a 0-capacity ArrayQueue drops every buffer and the
        // pool degrades to per-bridge allocation.
        .filter(|n| *n >= 4 && *n <= 4096)
        .unwrap_or(128)
});

/// A pool of reusable `Vec<u8>` buffers.
///
/// # Example
/// ```ignore
/// let mut buf = BUFFER_POOL.acquire();
/// // use buf ...
/// BUFFER_POOL.release(buf);
/// ```
pub struct BufferPool {
    inner: ArrayQueue<Vec<u8>>,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            inner: ArrayQueue::new(*MAX_POOLED_BUFFERS),
        }
    }
}

impl BufferPool {
    /// Acquire a buffer from the pool, or allocate a fresh one.
    ///
    /// The returned buffer has capacity >= BUFFER_SIZE. A recycled buffer may
    /// return at length BUFFER_SIZE (release preserves length); the miss path
    /// allocates via `Vec::with_capacity`, returning length 0.
    pub fn acquire(&self) -> Vec<u8> {
        self.inner
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(*BUFFER_SIZE))
    }

    /// Return a buffer to the pool for reuse.
    ///
    /// If the pool is full, the buffer is dropped. Buffers are recycled
    /// preserving length and capacity — length is left untouched (PoolGuard
    /// buffers are always full BUFFER_SIZE length). Contents are stale, but
    /// callers always overwrite via read() before use and only read the
    /// [..n] prefix, so stale bytes are never observed.
    pub fn release(&self, buf: Vec<u8>) {
        // ArrayQueue push returns Err(value) on overflow — buffer dropped.
        let _ = self.inner.push(buf);
    }
}

/// Global buffer pool instance shared across all bridge calls.
pub static BUFFER_POOL: LazyLock<BufferPool> = LazyLock::new(BufferPool::default);

/// RAII guard that returns a buffer to the pool on drop.
///
/// Use in bridge loops instead of bare `Vec<u8>` to ensure the buffer
/// is always returned, even on early break/return.
pub struct PoolGuard {
    buf: Vec<u8>,
}

impl PoolGuard {
    /// Acquire a buffer from the pool.
    ///
    /// Returned buffer has length == BUFFER_SIZE so `as_mut_slice()` is
    /// non-empty and `read()` can actually read data into it.
    #[inline]
    pub fn acquire() -> Self {
        let mut buf = BUFFER_POOL.acquire();
        // Only stretch a freshly allocated (len 0) buffer up to BUFFER_SIZE.
        // Recycled buffers already have length BUFFER_SIZE. We use an
        // uninitialized `set_len` instead of `resize(.., 0)` so the pool-miss
        // path skips a pool-sized memset: `read()` immediately overwrites the
        // whole slice and callers only observe the `[..n]` prefix, so stale
        // bytes are never read (same argument as the V2 UDP read path's
        // `set_len` in `protocol.rs::read_msg_v2_with_udp_codec`). The
        // `PoolGuard` docs above already declare the `[..n]`-prefix contract.
        if buf.len() < *BUFFER_SIZE {
            // SAFETY: on a pool miss `acquire()` allocates
            // `Vec::with_capacity(BUFFER_SIZE)`, so `capacity >= BUFFER_SIZE`
            // always holds; the region is fully overwritten by the caller's
            // next `read()` before any element is observed, so uninitialized
            // bytes are never read.
            #[allow(clippy::uninit_vec)]
            unsafe {
                buf.set_len(*BUFFER_SIZE);
            }
        }
        Self { buf }
    }

    /// Get a mutable byte slice for reading into.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Return the full underlying buffer (`len == BUFFER_SIZE`).
    ///
    /// **WARNING:** Recycled buffers contain stale bytes beyond the valid
    /// prefix.  Always slice to the length returned by the corresponding
    /// `read()` call: `buf.raw_buf()[..n]`.
    #[inline]
    pub fn raw_buf(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for PoolGuard {
    fn drop(&mut self) {
        // Take the buffer, leaving an empty Vec (cheap) in its place.
        // The taken buffer is returned to the pool.
        let buf = std::mem::take(&mut self.buf);
        BUFFER_POOL.release(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_creates_empty_pool() {
        let pool = BufferPool::default();
        let buf = pool.acquire();
        assert!(buf.capacity() >= *BUFFER_SIZE);
        assert_eq!(buf.len(), 0);
        pool.release(buf);
    }

    #[test]
    fn test_reuse_after_release() {
        let pool = BufferPool::default();
        let mut buf = pool.acquire();
        buf.push(42);
        pool.release(buf);

        // Recycling preserves length AND capacity; we no longer clear on
        // release, so the pushed byte survives (a regression re-adding clear()
        // would flip len back to 0).
        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 1, "release must not clear: length is preserved");
        assert!(buf2.capacity() >= *BUFFER_SIZE);
        pool.release(buf2);
    }

    /// PoolGuard reuse: a recycled buffer returns at full BUFFER_SIZE length,
    /// so acquire() skips the 64KB zero-fill (the P2 optimization) and raw_buf()
    /// still exposes a full-length slice.
    #[test]
    fn test_pool_guard_reuse_stays_full_length() {
        // Prime the global pool with one full-length buffer via a dropped guard.
        {
            let mut g = PoolGuard::acquire();
            assert_eq!(g.as_mut_slice().len(), *BUFFER_SIZE);
        } // dropped -> released at len BUFFER_SIZE (release no longer clears)

        // Reacquire: buffer is still full length, so the resize guard is a no-op.
        let g2 = PoolGuard::acquire();
        assert_eq!(
            g2.raw_buf().len(),
            *BUFFER_SIZE,
            "recycled buffer stays full length"
        );
    }

    #[test]
    fn test_pool_does_not_grow_unbounded() {
        let pool = BufferPool::default();
        let bufs: Vec<Vec<u8>> = (0..*MAX_POOLED_BUFFERS + 16)
            .map(|_| pool.acquire())
            .collect();
        // Release all — should not grow beyond MAX_POOLED_BUFFERS
        for b in bufs {
            pool.release(b);
        }
        // After releasing extras, pool size should be capped
        assert!(pool.inner.len() <= *MAX_POOLED_BUFFERS);
    }

    #[test]
    fn test_resolve_buffer_size_default_and_override() {
        let default = resolve_buffer_size(None);
        assert_eq!(default, DEFAULT_BUFFER_SIZE);
        if cfg!(target_os = "macos") {
            assert_eq!(default, 32 * 1024, "macOS keeps the 32 KiB default");
        } else {
            assert_eq!(default, 64 * 1024);
        }
        // Accepted overrides, with surrounding whitespace.
        assert_eq!(resolve_buffer_size(Some("4")), 4 * 1024);
        assert_eq!(resolve_buffer_size(Some("64")), 64 * 1024);
        assert_eq!(resolve_buffer_size(Some(" 128 ")), 128 * 1024);
        assert_eq!(resolve_buffer_size(Some("1024")), 1024 * 1024);
        // Out-of-range or unparsable values fall back to the platform default.
        for bad in ["3", "1025", "0", "abc", "", "-8"] {
            assert_eq!(resolve_buffer_size(Some(bad)), default, "raw = {bad:?}");
        }
    }

    /// The live static agrees with the pure resolver for the current process
    /// environment, so the LazyLock wrapper cannot drift from the rules.
    #[test]
    fn test_buffer_size_static_matches_resolver() {
        let raw = std::env::var("FRP_BRIDGE_BUF_KB").ok();
        assert_eq!(*BUFFER_SIZE, resolve_buffer_size(raw.as_deref()));
    }

    #[test]
    fn test_global_pool_works() {
        let buf = BUFFER_POOL.acquire();
        assert!(buf.capacity() >= *BUFFER_SIZE);
        BUFFER_POOL.release(buf);
    }
}
