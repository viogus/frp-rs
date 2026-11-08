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

/// Pooled buffer size in bytes.
///
/// Default: 32 KiB (32768), matching Go frp's `io.Copy` buffer and keeping the
/// per-bridge footprint at two 32 KiB buffers. This size is **also** the yamux
/// data-frame payload: `mux.rs` derives `split_send_size` from it, so in the
/// steady state one full bridge chunk travels as one frame — no second
/// 12-byte frame header, no second window-credit round trip, no second waker
/// hand-off per chunk. (Short chunks, a partly consumed send window, and the
/// encrypted path's separate IV write can still produce a second frame.) The
/// derived split is capped at 64 KiB, the largest frame the WebSocket
/// transport accepts.
///
/// Raising this to 64 KiB is the one tuning knob with a measured data-plane
/// win: on the mux path it is worth ~15% strictly ping-pong and ~10% less CPU
/// per byte, and ~3% on plain TCP (measurements:
/// `docs/archive/notes/2026-11-08-bridge-buffer-frame-match.md`). The gain is
/// the frame/payload match, not the buffer size on its own — a 64 KiB buffer
/// against a fixed 32 KiB frame split is level with the default. The price is per-bridge
/// memory: the plain and encrypted paths each hold one buffer per direction,
/// so the default costs 2x32 KiB per bridge and 64 KiB per bridge costs
/// 2x64 KiB. The default therefore stays at Go parity; operators who want the
/// mux win set `FRP_BRIDGE_BUF_KB=64`, which is why the split has to follow
/// this value (a hardcoded 32 KiB split made the knob do nothing).
///
/// Override via env `FRP_BRIDGE_BUF_KB` (valid range: 4–1024 KB,
/// i.e. 4 KiB – 1 MiB). Read once at process start via `LazyLock`.
///
/// This buffer size is used by the encrypted/compressed bridge data
/// path (`bridge.rs`), the V2 frame read path (`protocol.rs`), and —
/// via `copy_pooled`/`relay_plain_pooled` — the plain (unencrypted)
/// bridge path, so `FRP_BRIDGE_BUF_KB` applies uniformly.
pub static BUFFER_SIZE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("FRP_BRIDGE_BUF_KB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|kb| *kb >= 4 && *kb <= 1024)
        .map(|kb| kb * 1024)
        .unwrap_or(32768)
});

/// Maximum number of buffers to retain in the pool.
///
/// Default 128 (4 MiB of 32 KiB buffers); override via `FRP_BRIDGE_POOL_MAX`
/// (capped at 4096). 32 was too small under high connection churn — excess
/// buffers were dropped and re-allocated. The retained bytes therefore scale
/// with `FRP_BRIDGE_BUF_KB`: the default ceiling is 4 MiB, and a 1 MiB buffer
/// size reaches 128 MiB at the same buffer count.
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
    fn test_global_pool_works() {
        let buf = BUFFER_POOL.acquire();
        assert!(buf.capacity() >= *BUFFER_SIZE);
        BUFFER_POOL.release(buf);
    }
}
