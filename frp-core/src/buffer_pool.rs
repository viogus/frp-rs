//! Simple buffer pool to reduce per-connection allocation pressure.
//!
//! The bridge module allocates 32KB read buffers per direction per bridge
//! call. Under high proxy connection churn, this creates sustained allocator
//! pressure. This pool recycles those buffers.
//!
//! Thread-safe (std::sync::Mutex, not tokio — pool ops are sub-microsecond).
//! Fixed capacity: `MAX_POOLED_BUFFERS` (32). Excess buffers are dropped.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::LazyLock;

/// Pooled buffer size in bytes. Defaults to 32KB (matches Go frp io.Copy); override
/// for experiments via FRP_BRIDGE_BUF_KB (e.g. 256). Read once at process start.
pub static BUFFER_SIZE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("FRP_BRIDGE_BUF_KB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|kb| *kb >= 4 && *kb <= 1024)
        .map(|kb| kb * 1024)
        .unwrap_or(32768)
});

/// Maximum number of buffers to retain in the pool.
const MAX_POOLED_BUFFERS: usize = 32;

/// A pool of reusable `Vec<u8>` buffers.
///
/// # Example
/// ```ignore
/// let mut buf = BUFFER_POOL.acquire();
/// // use buf ...
/// BUFFER_POOL.release(buf);
/// ```
pub struct BufferPool {
    inner: Mutex<VecDeque<Vec<u8>>>,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
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
        let mut inner = self.inner.lock().expect("buffer pool lock poisoned");
        inner.pop_front().unwrap_or_else(|| Vec::with_capacity(*BUFFER_SIZE))
    }

    /// Return a buffer to the pool for reuse.
    ///
    /// If the pool is full, the buffer is dropped. Buffers are recycled
    /// preserving length and capacity — length is left untouched (PoolGuard
    /// buffers are always full BUFFER_SIZE length). Contents are stale, but
    /// callers always overwrite via read() before use and only read the
    /// [..n] prefix, so stale bytes are never observed.
    pub fn release(&self, buf: Vec<u8>) {
        let mut inner = self.inner.lock().expect("buffer pool lock poisoned");
        if inner.len() < MAX_POOLED_BUFFERS {
            inner.push_back(buf);
        }
        // else: pool full, buf dropped
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
    pub fn acquire() -> Self {
        let mut buf = BUFFER_POOL.acquire();
        // Only zero-fill on a freshly allocated (len 0) buffer. Recycled buffers
        // already have length BUFFER_SIZE, so skip the 64KB memset. read() fills
        // the slice and callers use only the [..n] prefix, so stale bytes are safe.
        if buf.len() < *BUFFER_SIZE {
            buf.resize(*BUFFER_SIZE, 0);
        }
        Self { buf }
    }

    /// Get a mutable byte slice for reading into.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Get an immutable slice over the buffered data.
    pub fn data(&self) -> &[u8] {
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
    /// so acquire() skips the 64KB zero-fill (the P2 optimization) and data()
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
        assert_eq!(g2.data().len(), *BUFFER_SIZE, "recycled buffer stays full length");
    }

    #[test]
    fn test_pool_does_not_grow_unbounded() {
        let pool = BufferPool::default();
        let bufs: Vec<Vec<u8>> = (0..MAX_POOLED_BUFFERS + 16)
            .map(|_| pool.acquire())
            .collect();
        // Release all — should not grow beyond MAX_POOLED_BUFFERS
        for b in bufs {
            pool.release(b);
        }
        // After releasing extras, pool size should be capped
        let inner = pool.inner.lock().unwrap();
        assert!(inner.len() <= MAX_POOLED_BUFFERS);
    }

    #[test]
    fn test_global_pool_works() {
        let buf = BUFFER_POOL.acquire();
        assert!(buf.capacity() >= *BUFFER_SIZE);
        BUFFER_POOL.release(buf);
    }
}
