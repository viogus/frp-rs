//! CPU profiling via pprof (gated behind `profiling` feature).
//!
//! Provides the primary `dump_cpu_profile` function: sample for a wall-clock
//! duration, write a flamegraph SVG, return the file path.
//!
//! OFF in all shipped builds — production binaries never include this
//! module (feature is opt-in and not in any default/tiny/micro set).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default sampling frequency: 99 Hz (matches pprof crate default).
const DEFAULT_FREQUENCY: i32 = 99;

/// Months (non-leap days), indexed 0 = January.
const MONTH_DAYS: &[u64] = &[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a CPU profile for `duration`, writing a flamegraph SVG to
/// `output_dir/{prefix}_{timestamp}.svg`.
///
/// The profiler samples at `DEFAULT_FREQUENCY` (99 Hz) using a per-process
/// `setitimer(ITIMER_PROF)` timer.  The calling thread is blocked for the
/// profiling window; in async contexts use `tokio::task::spawn_blocking`.
///
/// The output file name includes a human-readable UTC timestamp
/// (`YYYYMMDD_HHMMSS`) so multiple runs do not collide.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created, the profiler
/// cannot be started (e.g. another guard is already active), the flamegraph
/// cannot be written, etc.
pub fn dump_cpu_profile(
    duration: Duration,
    output_dir: &Path,
    prefix: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    let timestamp = format_timestamp(SystemTime::now());
    let filename = format!("{}_{}.svg", prefix, timestamp);
    let output_path = output_dir.join(&filename);

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(DEFAULT_FREQUENCY)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    // Block for the sampling window while the signal handler fires.
    std::thread::sleep(duration);

    let report = guard.report().build()?;
    let file = fs::File::create(&output_path)?;
    let mut writer = std::io::BufWriter::new(file);
    report.flamegraph(&mut writer)?;

    Ok(output_path)
}

// ---------------------------------------------------------------------------
// Timestamp formatting (no chrono dependency)
// ---------------------------------------------------------------------------

/// Format a `SystemTime` as `YYYYMMDD_HHMMSS` (UTC).
fn format_timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86400;
    let time_secs = secs % 86400;

    let hour = time_secs / 3600;
    let min = (time_secs / 60) % 60;
    let sec = time_secs % 60;

    let (year, month, day) = days_to_date(days);
    format!("{:04}{:02}{:02}_{:02}{:02}{:02}", year, month, day, hour, min, sec)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    // Find year.
    let mut year = 1970u64;
    loop {
        let year_len = if is_leap_year(year) { 366 } else { 365 };
        if days < year_len {
            break;
        }
        days -= year_len;
        year += 1;
    }

    // Find month.
    let leap = is_leap_year(year);
    for (i, &md) in MONTH_DAYS.iter().enumerate() {
        let mdays = if i == 1 && leap { 29 } else { md };
        if days < mdays {
            return (year, (i as u64) + 1, days + 1);
        }
        days -= mdays;
    }

    (year, 12, days + 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{LazyLock, Mutex};

    /// Serialize profiler access — pprof installs a process-wide signal
    /// handler, so only one guard can be active at a time.
    static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    // -- timestamp formatting -----------------------------------------------

    #[test]
    fn format_timestamp_epoch() {
        let s = format_timestamp(SystemTime::UNIX_EPOCH);
        assert_eq!(s, "19700101_000000");
    }

    #[test]
    fn format_timestamp_known_dates() {
        // 2024-01-01 00:00:00 UTC = 1704067200 → 19723 days
        let t1 = UNIX_EPOCH + Duration::from_secs(1704067200);
        assert_eq!(format_timestamp(t1), "20240101_000000");

        // 2024-02-29 12:34:56 UTC = 1709210096 → 19782 days + 45296 s
        let t2 = UNIX_EPOCH + Duration::from_secs(1709210096);
        assert_eq!(format_timestamp(t2), "20240229_123456");

        // 2025-01-01 00:00:00 UTC = 1735689600 → 20089 days
        let t3 = UNIX_EPOCH + Duration::from_secs(1735689600);
        assert_eq!(format_timestamp(t3), "20250101_000000");
    }

    #[test]
    fn is_leap_year_checks() {
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
    }

    // -- dump_cpu_profile ---------------------------------------------------

    #[test]
    fn dump_cpu_profile_creates_svg_file() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();

        // Spawn a busy thread so the per-process ITIMER_PROF fires during the
        // sampling window.
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            });

            let path = dump_cpu_profile(
                Duration::from_millis(200),
                dir.path(),
                "test_profile",
            )
            .expect("dump_cpu_profile should succeed");
            stop.store(true, std::sync::atomic::Ordering::Relaxed);

            assert!(
                path.exists(),
                "output SVG should exist at {:?}",
                path
            );
            assert_eq!(
                path.extension().and_then(|e| e.to_str()),
                Some("svg"),
                "extension should be .svg"
            );

            // Verify it is valid SVG (even if empty of samples).
            let meta = std::fs::metadata(&path).expect("metadata");
            assert!(meta.len() > 0, "SVG file should not be empty");
        });
    }

    #[test]
    fn dump_cpu_profile_non_existent_dir() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let sub = dir.path().join("nonexistent").join("deep");

        let path = dump_cpu_profile(Duration::from_millis(10), &sub, "test")
            .expect("should create parent dirs");
        assert!(path.exists());
    }

    #[test]
    fn dump_cpu_profile_concurrent_guard_returns_error() {
        let _lock = TEST_MUTEX.lock().unwrap();
        // Start a first guard.
        let g1 = pprof::ProfilerGuard::new(99).expect("first guard");
        let dir = tempfile::TempDir::new().unwrap();

        // A second dump_cpu_profile attempt should fail (only one guard
        // can be active at a time).
        let result = dump_cpu_profile(Duration::from_millis(10), dir.path(), "dup");
        assert!(result.is_err(), "concurrent profile should error");

        drop(g1);
    }
}
