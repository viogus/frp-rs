use std::time::Instant;

/// Token-bucket bandwidth limiter.
///
/// Tracks available bytes as a floating-point token count. Tokens refill
/// continuously at `rate` bytes per second. When `rate` is 0, `consume`
/// returns immediately (no limiting).
///
/// Each bridge direction gets its own limiter so read and write throttling
/// are independent.
pub struct BandwidthLimiter {
    /// Bytes per second. 0 = unlimited.
    rate: u64,
    /// Current token balance (can go negative when a large write consumes
    /// more than the bucket capacity).
    tokens: f64,
    /// Burst capacity — set to `rate` so 1 s of traffic bursts through
    /// without delay.
    max_tokens: f64,
    /// Timestamp of the last token refill.
    last: Instant,
}

impl BandwidthLimiter {
    /// Create a limiter with the given rate in **bytes per second**.
    /// Pass `0` for unlimited (no throttling).
    pub fn new(rate: u64) -> Self {
        Self {
            rate,
            tokens: rate as f64,
            max_tokens: rate as f64,
            last: Instant::now(),
        }
    }

    /// Create a limiter that never throttles.
    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Whether this limiter applies any throttling.
    pub fn is_active(&self) -> bool {
        self.rate > 0
    }

    /// Refill tokens based on elapsed wall-clock time.
    fn refill(&mut self) {
        if self.rate == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.max_tokens);
        self.last = now;
    }

    /// Wait until `n` bytes are available, then deduct them from the bucket.
    ///
    /// When the rate is 0 this is a no-op. When `n` exceeds the current token
    /// balance, the call sleeps for the time needed to accumulate the deficit
    /// and resets the bucket to zero.
    pub async fn consume(&mut self, n: usize) {
        if self.rate == 0 || n == 0 {
            return;
        }
        self.refill();
        let need = n as f64;
        if self.tokens >= need {
            self.tokens -= need;
            return;
        }
        // We don't have enough tokens. Sleep for the deficit.
        let deficit = need - self.tokens;
        self.tokens = 0.0;
        let wait = std::time::Duration::from_secs_f64(deficit / self.rate as f64);
        tokio::time::sleep(wait).await;
        self.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unlimited_is_noop() {
        let lim = BandwidthLimiter::unlimited();
        assert!(!lim.is_active());
        // consume should not panic or block (tested via tokio runtime below)
        assert_eq!(lim.rate, 0);
    }

    #[test]
    fn test_rate_is_active() {
        let lim = BandwidthLimiter::new(1024);
        assert!(lim.is_active());
    }

    #[tokio::test]
    async fn test_consume_unlimited_returns_immediately() {
        let mut lim = BandwidthLimiter::unlimited();
        let start = Instant::now();
        lim.consume(1_000_000).await; // huge consume, should be instant
        assert!(start.elapsed().as_millis() < 50);
    }

    #[tokio::test]
    async fn test_consume_small_amount() {
        let mut lim = BandwidthLimiter::new(1_000_000); // 1 MB/s
        let start = Instant::now();
        lim.consume(100).await; // well within burst capacity
        assert!(start.elapsed().as_millis() < 50);
    }

    #[tokio::test]
    async fn test_consume_large_amount_throttles() {
        // 1 KB/s — very slow. Consuming 2 KB should take ~2 seconds.
        let mut lim = BandwidthLimiter::new(1024);
        let start = Instant::now();
        lim.consume(1024).await; // first KB: uses burst (= 1 KB), instant
        lim.consume(1024).await; // second KB: bucket empty, must wait ~1 s
        let elapsed = start.elapsed().as_millis();
        // Allow wide tolerance for CI variance
        assert!(elapsed >= 500, "expected >= 500 ms, got {elapsed} ms");
        assert!(elapsed <= 2000, "expected <= 2000 ms, got {elapsed} ms");
    }

    #[tokio::test]
    async fn test_consume_zero_is_noop() {
        let mut lim = BandwidthLimiter::new(1024);
        lim.consume(0).await; // should not panic or alter state
    }
}
