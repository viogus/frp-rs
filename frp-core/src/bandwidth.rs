use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// A per-proxy shared bandwidth limiter: one token bucket covering BOTH
/// bridge directions and ALL concurrent connections of the proxy (Go frp
/// v0.71.0 `BaseProxy.limiter` semantics — a single `*rate.Limiter` wired
/// into both `limit.NewReader` and `limit.NewWriter`).
pub type SharedBandwidthLimiter = Arc<Mutex<BandwidthLimiter>>;

/// Token-bucket bandwidth limiter.
///
/// Tracks available bytes as a floating-point token count. Tokens refill
/// continuously at `rate` bytes per second. When `rate` is 0, `consume`
/// returns immediately (no limiting).
///
/// Standalone (unshared) limiters are used by tests; production bridges
/// share one limiter per proxy via [`SharedBandwidthLimiter`] so the rate
/// budget covers the combined traffic of both directions (Go parity).
#[derive(Debug)]
pub struct BandwidthLimiter {
    /// Bytes per second. 0 = unlimited.
    rate: u64,
    /// Current token balance. Negative = Go `rate.Limiter` reserveN debt:
    /// a consumer reserved more than the bucket held and is sleeping off the
    /// deficit; the next refill repays it before crediting anyone else.
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

    /// Build a per-proxy shared limiter (`Some`) when `rate > 0`, else `None`
    /// (Go `limit.NewBandwidthLimiter` returns nil for <= 0 — empty/unset
    /// rate stays unlimited). The mode gate deciding WHICH side creates it
    /// lives at the call sites (server: mode == "server"/"both"; client:
    /// mode == ""/"client"/"both" — Go `proxy.go` NewProxy gates).
    pub fn shared(rate: u64) -> Option<SharedBandwidthLimiter> {
        (rate > 0).then(|| Arc::new(Mutex::new(BandwidthLimiter::new(rate))))
    }

    /// Consume `n` bytes against a shared (per-proxy) limiter.
    ///
    /// The mutex serializes chunk accounting across both bridge directions
    /// and all concurrent connections of the proxy. The lock is held ONLY to
    /// reserve the tokens and compute the wait; the sleep itself happens
    /// outside the lock, so one throttled consumer (a 32 KiB chunk at
    /// 1 KiB/s waits ~32 s) cannot block every other connection of the
    /// proxy. The bucket keeps the Go-style negative balance while the
    /// consumer sleeps — a mid-sleep arrival's refill credits the elapsed
    /// interval and repays the debt first, so the combined budget still
    /// matches Go's single `rate.Limiter` shared by `NewReader` +
    /// `NewWriter` (bidirectional traffic shares one rate).
    pub async fn consume_shared(lim: &SharedBandwidthLimiter, n: usize) {
        let wait = {
            let mut l = lim.lock().await;
            l.reserve(n)
        };
        if let Some(wait) = wait {
            tokio::time::sleep(wait).await;
        }
    }

    /// Whether this limiter applies any throttling.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.rate > 0
    }

    /// Refill tokens based on elapsed wall-clock time.
    #[inline]
    fn refill(&mut self) {
        if self.rate == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.max_tokens);
        self.last = now;
    }

    /// Reserve `n` bytes against the bucket and return the wait needed to
    /// cover the reservation, if any.
    ///
    /// Go `rate.Limiter` `reserveN` semantics: when the balance is short the
    /// token count goes NEGATIVE — the deficit is owed, and the next refill
    /// (which credits the full elapsed interval, sleep included) repays the
    /// debt before crediting anyone else. The caller sleeps `wait` outside
    /// any lock and does not need to re-acquire on wake: the refill that
    /// credits this interval zeroes the balance exactly, so the following
    /// consumer starts from zero — byte-for-byte the schedule the old
    /// zero-and-discard model produced, without holding the lock across the
    /// sleep or discarding the accrual. A reservation cancelled mid-sleep
    /// leaves the debt in the bucket; the next consumer's refill pays it
    /// first (self-healing — bounded by the largest single reservation).
    fn reserve(&mut self, n: usize) -> Option<std::time::Duration> {
        if self.rate == 0 || n == 0 {
            return None;
        }
        self.refill();
        let need = n as f64;
        if self.tokens >= need {
            self.tokens -= need;
            return None;
        }
        self.tokens -= need;
        Some(std::time::Duration::from_secs_f64(
            -self.tokens / self.rate as f64,
        ))
    }

    /// Wait until `n` bytes are available, then deduct them from the bucket.
    ///
    /// When the rate is 0 this is a no-op. When `n` exceeds the current
    /// token balance, the call sleeps for the time needed to accumulate the
    /// deficit. The bucket holds a negative balance (Go `reserveN`
    /// semantics) while the caller waits; the next consumer's refill repays
    /// it from the credited sleep interval, so throttled consumers are
    /// serialized at exactly `rate` bytes per second.
    pub async fn consume(&mut self, n: usize) {
        if let Some(wait) = self.reserve(n) {
            tokio::time::sleep(wait).await;
        }
    }
}

/// Go frp v0.71.0 side-selection parity (F1/F2): `bandwidthLimitMode` names
/// the SIDE that owns the per-proxy shared limiter, not a direction. The
/// client creates it for "" (Go `EmptyOr("", "client")` — config/v1/
/// proxy.go:156), "client", or the frp-rs extension "both"; the server for
/// "server" or "both" (server/proxy/proxy.go:536-540). One limiter covers
/// both directions on the owning side; the other side creates none.
pub fn client_side_limiter(rate: u64, mode: &str) -> Option<SharedBandwidthLimiter> {
    let mode = if mode.is_empty() { "client" } else { mode };
    if rate > 0 && (mode == "client" || mode == "both") {
        BandwidthLimiter::shared(rate)
    } else {
        None
    }
}

/// Server-side gate: a limiter is created only when the server owns the
/// limiting (`"server"`, or the frp-rs extension `"both"`).
pub fn server_side_limiter(rate: u64, mode: &str) -> Option<SharedBandwidthLimiter> {
    if rate > 0 && (mode == "server" || mode == "both") {
        BandwidthLimiter::shared(rate)
    } else {
        None
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

    /// P3 pin: `consume_shared` must not hold the mutex across its sleep.
    ///
    /// Old code locked, then slept inside the lock — a 32 KiB chunk at
    /// 1 KiB/s blocked every other connection of the proxy for ~32 s. The
    /// sleep is now computed under the lock and executed outside it; the
    /// probe below (a second consumer arriving 100 ms into the sleeper's
    /// ~1 s wait) must acquire the lock immediately. RED on old code: the
    /// probe parks ~900 ms behind the sleeper's held lock.
    #[tokio::test]
    async fn shared_limiter_lock_not_held_across_sleep() {
        let lim = BandwidthLimiter::shared(1).unwrap(); // 1 B/s
                                                        // Reserve the burst (1 B) plus 4 B of debt: ~4 s wait, all of it
                                                        // spent inside the old code's critical section (round-3 review,
                                                        // audit round 8: consume(2) parked the probe only ~900 ms — a 2 s
                                                        // bound could not catch old code; 4 s of debt parks it ~3.9 s,
                                                        // comfortably past the bound, with the bound itself untouched so
                                                        // scheduler-noise tolerance is unchanged).
        let sleeper = {
            let lim = lim.clone();
            tokio::spawn(async move { BandwidthLimiter::consume_shared(&lim, 5).await })
        };
        // The sleeper runs first (this task yields); 100 ms in, it is
        // mid-wait. A second consumer must lock and reserve immediately.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let start = Instant::now();
        // n == 0 → reserve returns None right after acquiring the lock, so
        // the elapsed time below is a pure lock-acquisition measurement.
        BandwidthLimiter::consume_shared(&lim, 0).await;
        let elapsed = start.elapsed();
        // Lock acquisition post-fix is microseconds, but a cgroup-preempted
        // test task can stretch any wall-clock window; the property under
        // test is "not ~3.9s behind the sleeper's held lock", so 2s
        // separates that signal from scheduler noise.
        assert!(
            elapsed.as_millis() < 2000,
            "second consumer blocked for {elapsed:?}: the limiter mutex is held \
             across the first consumer's sleep"
        );
        sleeper.await.unwrap();
    }

    /// F1/F2 pin: mode names the SIDE that owns the shared limiter. The
    /// client owns it for "" (Go `EmptyOr("", "client")`), "client", and the
    /// frp-rs extension "both"; "server" → the client creates NONE (Go:
    /// client/proxy/proxy.go:66-71 NewProxy gate — the server throttles).
    #[test]
    fn client_side_limiter_follows_mode() {
        let assert_limited = |rate: u64, mode: &str, expected: bool| {
            let got = client_side_limiter(rate, mode).is_some();
            assert_eq!(
                got, expected,
                "client_side_limiter({rate}, {mode:?}): expected {expected}, got {got}"
            );
        };
        // Empty mode → "client" (Go EmptyOr default) → client owns it.
        assert_limited(4096, "", true);
        assert_limited(4096, "client", true);
        assert_limited(4096, "both", true);
        // Server owns it: client must NOT limit (was the old per-direction
        // apply_read gate — now the whole side is skipped).
        assert_limited(4096, "server", false);
        // Rate 0 (unset) → unlimited regardless of mode (Go nil limiter).
        assert_limited(0, "client", false);
        assert_limited(0, "server", false);
    }

    /// F1/F2 pin: the server creates the limiter only for "server" (Go
    /// server/proxy/proxy.go:536-540 gate) and "both". "client"/"" → the
    /// client owns it — the server must not double-limit (Go: the server's
    /// NewBandwidthLimiter runs ONLY under the "server" mode branch).
    #[test]
    fn server_side_limiter_follows_mode() {
        let assert_limited = |rate: u64, mode: &str, expected: bool| {
            let got = server_side_limiter(rate, mode).is_some();
            assert_eq!(
                got, expected,
                "server_side_limiter({rate}, {mode:?}): expected {expected}, got {got}"
            );
        };
        assert_limited(4096, "server", true);
        assert_limited(4096, "both", true);
        assert_limited(4096, "client", false);
        assert_limited(4096, "", false);
        assert_limited(0, "server", false);
    }
}
