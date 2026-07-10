//! Simple buffer pool to reduce per-connection allocation pressure.
//!
//! The bridge module allocates 64KB read buffers per direction per bridge
//! call. Under high proxy connection churn, this creates sustained allocator
//! pressure. This pool recycles those buffers.
//!
//! Thread-safe (std::sync::Mutex, not tokio — pool ops are sub-microsecond).
//! Fixed capacity: `MAX_POOLED_BUFFERS` (32). Excess buffers are dropped.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::LazyLock;

/// Default size for pooled buffers (64KB — matches bridge.rs read buffer).
pub const BUFFER_SIZE: usize = 65536;

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
    /// The returned buffer has capacity >= BUFFER_SIZE and length 0.
    pub fn acquire(&self) -> Vec<u8> {
        let mut inner = self.inner.lock().expect("buffer pool lock poisoned");
        inner.pop_front().unwrap_or_else(|| Vec::with_capacity(BUFFER_SIZE))
    }

    /// Return a buffer to the pool for reuse.
    ///
    /// If the pool is full, the buffer is dropped. The buffer is cleared
    /// before returning (preserving capacity).
    pub fn release(&self, mut buf: Vec<u8>) {
        buf.clear();
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
        // Buffer from pool has capacity >= BUFFER_SIZE but may have length 0
        // (Vec::with_capacity). Bridge code calls read(&mut buf) which needs
        // a non-empty mutable slice — ensure length matches capacity.
        buf.resize(BUFFER_SIZE, 0);
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
        assert!(buf.capacity() >= BUFFER_SIZE);
        assert_eq!(buf.len(), 0);
        pool.release(buf);
    }

    #[test]
    fn test_reuse_after_release() {
        let pool = BufferPool::default();
        let mut buf = pool.acquire();
        buf.push(42);
        pool.release(buf);

        let buf2 = pool.acquire();
        assert_eq!(buf2.len(), 0);
        assert!(buf2.capacity() >= BUFFER_SIZE);
        pool.release(buf2);
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
        assert!(buf.capacity() >= BUFFER_SIZE);
        BUFFER_POOL.release(buf);
    }
}
