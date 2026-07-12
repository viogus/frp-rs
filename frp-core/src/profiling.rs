//! CPU profiling via pprof (gated behind `profiling` feature).
//!
//! Wraps `pprof::ProfilerGuard` for signal-based CPU sampling. The module
//! provides helpers for starting/stopping the profiler and generating
//! flamegraph output.
//!
//! OFF in all shipped builds — production binaries never include this
//! file (feature is opt-in and not in any default/tiny/micro set).

use std::path::Path;
use std::time::Duration;

/// Default sampling frequency: 100 Hz (every 10 ms).
pub const DEFAULT_FREQUENCY: i32 = 100;

/// Profiling result type.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Start CPU profiling with the given sampling frequency (samples/second).
///
/// Returns a guard that must be kept alive for the duration of the
/// profiling window. Dropping the guard stops the profiler.
///
/// # Example
///
/// ```ignore
/// let _guard = start(100)?; // 100 Hz
/// // ... do work ...
/// // guard dropped here → profile stops
/// ```
pub fn start(frequency: i32) -> Result<pprof::ProfilerGuard<'static>> {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(frequency)
        .build()?;
    Ok(guard)
}

/// Start CPU profiling with default frequency (100 Hz).
pub fn start_default() -> Result<pprof::ProfilerGuard<'static>> {
    start(DEFAULT_FREQUENCY)
}

/// Write a flamegraph SVG from the collected profile to `path`.
pub fn dump_flamegraph(guard: &pprof::ProfilerGuard, path: impl AsRef<Path>) -> Result<()> {
    let report = guard.report().build()?;
    let file = std::fs::File::create(path.as_ref())?;
    let mut writer = std::io::BufWriter::new(file);
    report.flamegraph(&mut writer)?;
    Ok(())
}

/// Profile a synchronous closure and return the report.
pub fn profile_sync<F>(freq: i32, duration: Duration, f: F) -> Result<pprof::Report>
where
    F: FnOnce(),
{
    let guard = start(freq)?;
    f();
    if duration > Duration::ZERO {
        std::thread::sleep(duration);
    }
    let report = guard.report().build()?;
    Ok(report)
}

/// Profile an async future and return the report.
pub async fn profile_async<F, T>(freq: i32, duration: Duration, f: F) -> Result<pprof::Report>
where
    F: std::future::Future<Output = T>,
{
    let guard = start(freq)?;
    f.await;
    if duration > Duration::ZERO {
        tokio::time::sleep(duration).await;
    }
    let report = guard.report().build()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::sync::LazyLock;
    use std::sync::Mutex;

    /// Serialize profiler access in tests — pprof installs a process-wide
    /// signal handler, so only one guard can be active at a time.
    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn start_stop_does_not_panic() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let guard = start(1).unwrap();
        drop(guard);
    }

    #[test]
    fn profile_sync_collects_samples() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let report = profile_sync(100, Duration::from_millis(100), || {
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_millis(80) {
                std::hint::spin_loop();
            }
        })
        .unwrap();
        let _ = report.data.len();
    }

    #[tokio::test]
    async fn profile_async_collects_samples() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let f = {
            let flag = flag.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                flag.store(true, Ordering::SeqCst);
            }
        };
        let report = profile_async(100, Duration::from_millis(100), f)
            .await
            .unwrap();
        assert!(flag.load(Ordering::SeqCst), "async fn completed");
        let _ = report.data.len();
    }
}
