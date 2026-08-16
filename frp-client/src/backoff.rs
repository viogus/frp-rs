//! Reconnect backoff helpers for the client session loop.
//!
//! Implements the Go frp dev two-phase fast-backoff used between session
//! reconnects, plus the heartbeat auth-scope union helper shared by the
//! control-loop ping path.

use std::time::Instant;

use rand::Rng;
use tokio::time::Duration;

/// Whether a HeartBeats ping must carry auth: union of the client's own
/// additional auth scopes and the server-advertised scopes. The server-side
/// union is a Rust-to-Rust extension (Go v0.70.1's SetPing checks only the
/// client's own additionalAuthScopes).
pub(crate) fn heartbeat_requires_auth(client_scopes: &[String], server_scopes: &[String]) -> bool {
    crate::work_conn::scope_requires_auth(client_scopes, server_scopes, "HeartBeats")
}

/// One session ended: bump the consecutive error count, record the retry
/// timestamp, and compute the next reconnect delay with the two-phase
/// fast-backoff.
pub(crate) fn reconnect_delay_after_session(
    consecutive_err_count: &mut u32,
    fast_retry_timestamps: &mut Vec<Instant>,
    previous_delay: Duration,
) -> Duration {
    *consecutive_err_count += 1;
    fast_retry_timestamps.push(Instant::now());
    let window_count = prune_fast_retry_count(fast_retry_timestamps);
    fast_backoff_delay(*consecutive_err_count, window_count, previous_delay)
}

/// Count errors in the 60s fast-retry sliding window, pruning expired timestamps.
/// Matches Go frp dev FastBackoffManager.FastRetryWindow = time.Minute.
pub(crate) fn prune_fast_retry_count(timestamps: &mut Vec<Instant>) -> u32 {
    let now = Instant::now();
    let cutoff = now - Duration::from_secs(60);
    timestamps.retain(|ts| *ts >= cutoff);
    timestamps.len() as u32
}

/// Compute reconnect delay with the Go frp dev two-phase fast-backoff.
/// Phase 1 (first 3 retries within 60s window): 200ms base × full jitter
/// (0.5-1.5), no cap.
/// Phase 2 (after that): 1s base, 2x factor, full jitter (0.5-1.5), cap 20s.
///
/// Matches Go frp dev wait.FastBackoffManager:
///   FastBackoffOptions{
///       Duration:        time.Second,
///       Factor:          2,
///       Jitter:          0.1,
///       MaxDuration:     20 * time.Second,
///       FastRetryCount:  3,
///       FastRetryDelay:  200 * time.Millisecond,
///       FastRetryJitter: 0.5,
///       FastRetryWindow: time.Minute,
///   }
///
/// # Architectural Note (Fix 10)
/// Go frp uses a **nested** backoff architecture: `loopLoginUntilSuccess` contains
/// its own `BackoffUntil` with a basic exponential (Duration=1s, Factor=2, MaxDuration=10s/20s),
/// while `keepControllerWorking` wraps it in an outer `BackoffUntil` with the full
/// two-phase FastBackoffManager. This means:
///   - Initial login: inner loop retries forever with 10s cap.
///   - Reconnection: outer loop adds fast-retry (200ms) and exponential (20s cap) BETWEEN
///     inner-loop invocations, while each inner-loop invocation itself has exponential backoff.
///
/// Rust's implementation uses a **combined** approach: a single reconnection loop with
/// the full two-phase backoff applied to each reconnect attempt. This is functionally
/// equivalent because Go's inner loop (loopLoginUntilSuccess) guarantees it returns
/// only on success, and the outer loop provides the error-aware backoff between retries.
pub(crate) fn fast_backoff_delay(
    consecutive_err_count: u32,
    counts_in_fast_retry_window: u32,
    previous_delay: Duration,
) -> Duration {
    let mut rng = rand::thread_rng();

    // Phase 1: fast retries
    if counts_in_fast_retry_window <= 3 {
        // Full jitter: 200ms × random(0.5, 1.5) → 100-300ms (mean 200ms).
        // Multiplicative jitter de-synchronizes clients restarting
        // together: additive jitter confined everyone to a 100ms-wide
        // window that re-clustered on every restart (thundering herd).
        let ms = 200.0 * rng.gen_range(0.5..=1.5);
        return Duration::from_millis(ms as u64);
    }

    // Phase 2: exponential backoff anchored to the PREVIOUS ACTUAL delay,
    // matching Go frp dev wait.FastBackoffImpl.Backoff():
    //   consecutiveErrCount==1 → InitDurationIfFail (1s)
    //   else → previousDuration (the last returned delay, jitter included)
    //   then × Factor(2) + Jitter(±10%) capped at MaxDuration (20s).
    // Anchoring to the previous (jittered) delay — instead of recomputing a
    // pure 1s·2^n sequence — makes the cap converge more slowly and keeps
    // consecutive delays consistent (Go semantics; previously ~5 retries hit
    // the 20s cap, Go takes longer because each step compounds the jittered
    // value rather than the theoretical base).
    let base = if consecutive_err_count == 1 || previous_delay.is_zero() {
        Duration::from_secs(1) // InitDurationIfFail
    } else {
        previous_delay
    };
    // Go fastBackoffImpl order: Factor(2) → Jitter(±10%) → MaxDuration cap.
    // (Jittering BEFORE the cap keeps the cap neighborhood spread; capping
    // first would pin the last step at exactly 20s with no jitter.)
    let duration = base.saturating_mul(2); // Factor = 2
    let jitter = rng.gen_range(0.9..=1.1);
    let ms = (duration.as_millis() as f64 * jitter) as u64;
    Duration::from_millis(ms.min(20_000))
}
