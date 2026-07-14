//! Exponential backoff utility with jitter and fast retry.
//!
//! Port of Go frp v0.69.1 `pkg/util/wait/backoff.go`.

use std::time::Duration;

use rand::Rng;
use tokio::sync::watch;
use tokio::time;

/// Computes the next delay given the previous duration and error state.
pub trait BackoffManager {
    fn backoff(&mut self, previous_duration: Duration, previous_condition_error: bool) -> Duration;
}

/// Configuration for exponential backoff with optional fast retry.
#[derive(Debug, Clone)]
pub struct FastBackoffOptions {
    /// Base delay returned after a successful attempt.
    pub duration: Duration,
    /// Multiplier applied on each consecutive error.
    pub factor: f64,
    /// Jitter factor [0.0, 1.0] — actual delay is duration..duration*(1+jitter).
    pub jitter: f64,
    /// Maximum delay cap. None = no cap.
    pub max_duration: Option<Duration>,
    /// Delay to use on the first error instead of base duration.
    pub init_duration_if_fail: Option<Duration>,
    /// Number of fast retries within the fast retry window.
    pub fast_retry_count: usize,
    /// Delay used during fast retry phase.
    pub fast_retry_delay: Duration,
    /// Jitter factor for fast retry delay.
    pub fast_retry_jitter: f64,
    /// Time window for fast retry counting.
    pub fast_retry_window: Duration,
}

impl Default for FastBackoffOptions {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(1),
            factor: 2.0,
            jitter: 0.1,
            max_duration: None,
            init_duration_if_fail: None,
            fast_retry_count: 0,
            fast_retry_delay: Duration::from_millis(100),
            fast_retry_jitter: 0.0,
            fast_retry_window: Duration::from_secs(60),
        }
    }
}

/// Exponential backoff manager implementing the Go frp fast-backoff algorithm.
pub struct FastBackoff {
    options: FastBackoffOptions,
    last_called: Option<tokio::time::Instant>,
    consecutive_err_count: u32,
    fast_retry_cutoff: Option<tokio::time::Instant>,
    counts_in_fast_retry_window: usize,
}

impl FastBackoff {
    pub fn new(options: FastBackoffOptions) -> Self {
        Self {
            options,
            last_called: None,
            consecutive_err_count: 0,
            fast_retry_cutoff: None,
            counts_in_fast_retry_window: 0,
        }
    }
}

impl BackoffManager for FastBackoff {
    fn backoff(&mut self, previous_duration: Duration, previous_condition_error: bool) -> Duration {
        let now = tokio::time::Instant::now();

        if self.last_called.is_none() {
            self.last_called = Some(now);
            return self.options.duration;
        }
        self.last_called = Some(now);

        if previous_condition_error {
            self.consecutive_err_count += 1;
        } else {
            self.consecutive_err_count = 0;
        }

        // Fast retry: within the fast_retry_window, first N errors use a short delay
        if self.options.fast_retry_count > 0 && previous_condition_error {
            self.counts_in_fast_retry_window += 1;
            if self.counts_in_fast_retry_window <= self.options.fast_retry_count {
                let d = if self.options.fast_retry_jitter > 0.0 {
                    jitter(
                        self.options.fast_retry_delay,
                        self.options.fast_retry_jitter,
                    )
                } else {
                    self.options.fast_retry_delay
                };
                return d;
            }
            if let Some(cutoff) = self.fast_retry_cutoff {
                if now > cutoff {
                    // reset — outside window
                    self.fast_retry_cutoff = Some(now + self.options.fast_retry_window);
                    self.counts_in_fast_retry_window = 0;
                }
            } else {
                self.fast_retry_cutoff = Some(now + self.options.fast_retry_window);
            }
        }

        if previous_condition_error {
            let mut duration = if self.consecutive_err_count == 1 {
                self.options
                    .init_duration_if_fail
                    .unwrap_or(previous_duration)
            } else {
                previous_duration
            };

            if duration.is_zero() {
                duration = Duration::from_secs(1);
            }
            if self.options.factor != 0.0 {
                duration = Duration::from_secs_f64(duration.as_secs_f64() * self.options.factor);
            }
            if self.options.jitter > 0.0 {
                duration = jitter(duration, self.options.jitter);
            }
            if let Some(max) = self.options.max_duration {
                if max > Duration::ZERO && duration > max {
                    duration = max;
                }
            }
            return duration;
        }

        self.options.duration
    }
}

/// Add random jitter: returns a duration in `[duration, duration * (1 + max_factor))`.
///
/// When `max_factor <= 0.0`, defaults to `1.0` (matching Go frp's `Jitter()`).
pub fn jitter(duration: Duration, max_factor: f64) -> Duration {
    let factor = if max_factor <= 0.0 { 1.0 } else { max_factor };
    let extra = rand::thread_rng().gen::<f64>() * factor * duration.as_secs_f64();
    duration + Duration::from_secs_f64(extra)
}

/// Run `f` repeatedly with backoff until it returns `Ok(true)` or stop is signaled.
///
/// `f` returns `Ok(true)` when done, `Ok(false)` to continue, `Err(_)` to
/// signal a condition error (which escalates the backoff).
///
/// If `sliding` is true, the backoff is recomputed after each attempt.
/// If `sliding` is false, the backoff is recomputed before each attempt.
pub async fn backoff_until<F>(
    mut f: F,
    backoff: &mut dyn BackoffManager,
    sliding: bool,
    mut stop: watch::Receiver<()>,
) where
    F: FnMut() -> Result<bool, anyhow::Error>,
{
    let mut delay = Duration::ZERO;
    let mut previous_error = false;

    loop {
        if !sliding {
            delay = backoff.backoff(delay, previous_error);
        }

        match f() {
            Ok(true) => return,
            Ok(false) => previous_error = false,
            Err(_) => previous_error = true,
        }

        if sliding {
            delay = backoff.backoff(delay, previous_error);
        }

        tokio::select! {
            _ = stop.changed() => return,
            _ = time::sleep(delay) => {},
        }
    }
}

/// Run `f` at a fixed interval until stop is signaled.
pub async fn until<F>(mut f: F, period: Duration, mut stop: watch::Receiver<()>)
where
    F: FnMut(),
{
    loop {
        f();
        tokio::select! {
            _ = stop.changed() => return,
            _ = time::sleep(period) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_range() {
        let base = Duration::from_secs(10);
        for _ in 0..100 {
            let j = jitter(base, 0.2);
            assert!(j >= base, "jittered {j:?} < base {base:?}");
            assert!(
                j < base + base / 5 + Duration::from_millis(1),
                "jittered {j:?} too large"
            );
        }
    }

    #[test]
    fn test_fast_backoff_basic() {
        let mut b = FastBackoff::new(FastBackoffOptions {
            duration: Duration::from_secs(2),
            factor: 2.0,
            jitter: 0.0,
            ..Default::default()
        });

        // First call: base duration
        let d1 = b.backoff(Duration::ZERO, false);
        assert_eq!(d1, Duration::from_secs(2));

        // Error: escalates
        let d2 = b.backoff(d1, true);
        assert!(d2 >= Duration::from_secs(4)); // 2 * 2.0 = 4

        // Second consecutive error
        let d3 = b.backoff(d2, true);
        assert!(d3 >= Duration::from_secs(8));
    }

    #[test]
    fn test_fast_backoff_reset_on_success() {
        let mut b = FastBackoff::new(FastBackoffOptions {
            duration: Duration::from_secs(2),
            factor: 2.0,
            jitter: 0.0,
            ..Default::default()
        });

        let d1 = b.backoff(Duration::ZERO, false);
        assert_eq!(d1, Duration::from_secs(2));

        // Error
        let d2 = b.backoff(d1, true);
        assert!(d2 > d1);

        // Success resets
        let d3 = b.backoff(d2, false);
        assert_eq!(d3, Duration::from_secs(2));
    }

    #[test]
    fn test_fast_backoff_max_cap() {
        let mut b = FastBackoff::new(FastBackoffOptions {
            duration: Duration::from_secs(1),
            factor: 10.0,
            jitter: 0.0,
            max_duration: Some(Duration::from_secs(5)),
            ..Default::default()
        });

        let d1 = b.backoff(Duration::ZERO, false);
        let d2 = b.backoff(d1, true);
        assert_eq!(d2, Duration::from_secs(5)); // capped at 5
    }

    #[test]
    fn test_fast_retry() {
        let mut b = FastBackoff::new(FastBackoffOptions {
            duration: Duration::from_secs(10),
            fast_retry_count: 3,
            fast_retry_delay: Duration::from_millis(50),
            fast_retry_jitter: 0.0,
            ..Default::default()
        });

        // First call always returns base duration (Go compat)
        let d0 = b.backoff(Duration::ZERO, true);
        assert_eq!(d0, Duration::from_secs(10));

        // Next 3 errors within fast_retry_window get fast_retry_delay
        let d1 = b.backoff(d0, true);
        assert_eq!(d1, Duration::from_millis(50));

        let d2 = b.backoff(d1, true);
        assert_eq!(d2, Duration::from_millis(50));

        let d3 = b.backoff(d2, true);
        assert_eq!(d3, Duration::from_millis(50));

        // 4th error (after first): normal backoff
        let d4 = b.backoff(d3, true);
        assert!(d4 > Duration::from_millis(50));
    }
}
