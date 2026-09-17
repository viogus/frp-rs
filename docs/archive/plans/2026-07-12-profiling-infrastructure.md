# Profiling Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add on-demand CPU flamegraph profiling via pprof-rs behind a `profiling` feature flag, triggered by SIGUSR2 on frps and frpc.

**Architecture:** New `frp-core/src/profiling.rs` module with a single `dump_cpu_profile` function. SIGUSR2 handler in both binaries spawns a blocking task that samples CPU for a configurable duration, then writes flamegraph SVG and protobuf to disk. Follows existing `mem-profile` feature propagation pattern and frps SIGUSR1 signal handler pattern.

**Tech Stack:** pprof 0.14 (flamegraph feature, pulls inferno), std::time::SystemTime (no chrono dep)

## Global Constraints

- `profiling` feature is opt-in (NOT default), zero binary impact when off
- `cargo build --features profiling` must succeed on all platforms; SIGUSR2 handler is `#[cfg(unix)]`
- No new dependencies beyond `pprof` (optional, off by default)
- `cargo build` without `profiling` produces byte-identical binary to before
- Follow existing `mem-profile` feature propagation pattern: frp-core → frp-server/frp-client → frps/frpc
- Profile output: SVG flamegraph + protobuf, timestamped filenames, `FRP_PROFILE_DIR` and `FRP_PROFILE_SECS` env overrides
- Default profile duration: 30 seconds at 99 Hz
- Use `std::time::SystemTime` for timestamp formatting (chrono not a direct dep — no new dep for timestamp)

---

### Task 1: Add pprof dependency and feature flags

**Files:**
- Modify: `Cargo.toml` (workspace dependencies section)
- Modify: `frp-core/Cargo.toml` (features section, dependencies section)
- Modify: `frp-core/src/lib.rs` (module declarations)
- Modify: `frps/Cargo.toml` (features section)
- Modify: `frpc/Cargo.toml` (features section)

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `frp_core::profiling::dump_cpu_profile(duration: Duration, output_dir: &Path, prefix: &str) -> Result<PathBuf, Box<dyn Error>>` — public function available when `profiling` feature is enabled

- [ ] **Step 1: Add pprof to workspace dependencies**

Open `Cargo.toml`. Add after line 55 (`criterion = "0.5"`):

```toml
pprof = { version = "0.14", features = ["flamegraph"], optional = true }
```

- [ ] **Step 2: Add profiling feature to frp-core**

Open `frp-core/Cargo.toml`. Add after line 58 (`mem-profile = []`):

```toml
profiling = ["dep:pprof"]
```

In the same file, add pprof to `[dependencies]` section (the non-feature-gated deps block):

```toml
pprof = { workspace = true, optional = true }
```

- [ ] **Step 3: Add profiling module declaration to frp-core/src/lib.rs**

Open `frp-core/src/lib.rs`. Add after line 33 (`pub mod mem_profile;`):

```rust
#[cfg(feature = "profiling")]
pub mod profiling;
```

- [ ] **Step 4: Propagate profiling feature to frps**

Open `frps/Cargo.toml`. In the `[features]` section (after `mem-profile` line), add:

```toml
profiling = ["frp-server/profiling"]
```

Open `frp-server/Cargo.toml`. In the `[features]` section (after `mem-profile` line), add:

```toml
profiling = ["frp-core/profiling"]
```

- [ ] **Step 5: Propagate profiling feature to frpc**

Open `frpc/Cargo.toml`. In the `[features]` section (after `mem-profile` line), add:

```toml
profiling = ["frp-client/profiling"]
```

Open `frp-client/Cargo.toml`. In the `[features]` section (after `mem-profile` line), add:

```toml
profiling = ["frp-core/profiling"]
```

- [ ] **Step 6: Verify builds**

```bash
cargo build -p frp-core --features profiling 2>&1 | tail -5
```

Expected: Compiles without error. pprof crate and inferno pulled in.

```bash
cargo build -p frps 2>&1 | tail -3
```

Expected: Compiles without error. profiling NOT in default build.

```bash
cargo build -p frps --features profiling 2>&1 | tail -5
```

Expected: Compiles with profiling enabled.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml frp-core/Cargo.toml frp-core/src/lib.rs frps/Cargo.toml frpc/Cargo.toml frp-server/Cargo.toml frp-client/Cargo.toml
git commit -m "feat(profiling): add pprof dependency and feature flags

- Add pprof 0.14 (flamegraph feature) as optional workspace dep
- Add 'profiling' feature to frp-core (gates dep:pprof)
- Propagate through frp-server → frps and frp-client → frpc
- Module declaration in lib.rs behind #[cfg(feature = \"profiling\")]

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Implement dump_cpu_profile function

**Files:**
- Create: `frp-core/src/profiling.rs`

**Interfaces:**
- Consumes: `pprof` crate (from Task 1)
- Produces: `pub fn dump_cpu_profile(duration: Duration, output_dir: &Path, prefix: &str) -> Result<PathBuf, Box<dyn std::error::Error>>`

- [ ] **Step 1: Write the test file**

Create `frp-core/src/profiling.rs` with the test-first approach. Write a failing compile check first — Rust doesn't have a clean "test doesn't exist yet" pattern for new modules, so we write the test and the minimal stub together.

```rust
//! On-demand CPU profiling via pprof-rs.
//!
//! Produces flamegraph SVG and protobuf output files.
//! Enabled via the `profiling` feature flag (off by default).

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Sample CPU for `duration`, write flamegraph SVG and protobuf to `output_dir`.
///
/// Files are named `{prefix}_profile_{timestamp}.svg` and `.pb`.
/// Returns the path to the SVG file on success.
pub fn dump_cpu_profile(
    duration: Duration,
    output_dir: &Path,
    prefix: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Build the profiler guard — starts sampling immediately at 99 Hz.
    let guard = pprof::profiler::Builder::new()
        .frequency(99)
        .build()?;

    // Sample for the requested duration.
    std::thread::sleep(duration);

    // Build the report from collected samples.
    let report = guard.report().build()?;

    // Format timestamp: YYYY-MM-DDTHH_MM_SS
    let ts = format_system_time()?;

    let svg_path = output_dir.join(format!("{prefix}_profile_{ts}.svg"));
    let pb_path = output_dir.join(format!("{prefix}_profile_{ts}.pb"));

    // Write flamegraph SVG.
    let svg_file = std::fs::File::create(&svg_path)?;
    report.flamegraph(svg_file)?;

    // Write protobuf (for go tool pprof compatibility).
    let pb_file = std::fs::File::create(&pb_path)?;
    report.write_protobuf(pb_file)?;

    Ok(svg_path)
}

/// Format current system time as "YYYY-MM-DDTHH_MM_SS".
/// Avoids chrono dependency — std only.
fn format_system_time() -> Result<String, Box<dyn std::error::Error>> {
    use std::time::SystemTime;

    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| format!("system clock before unix epoch: {e}"))?;

    let secs = dur.as_secs();

    // Break down into date/time components manually.
    // days since epoch → year/month/day
    let days = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from days since Unix epoch.
    // Algorithm: start from 1970-01-01, account for leap years.
    let (year, month, day) = civil_from_days(days as i64);

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}_{minutes:02}_{seconds:02}"
    ))
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Handles leap years correctly.
fn civil_from_days(mut days: i64) -> (i64, u32, u32) {
    // Shift epoch to year 0 (there is no year 0 in Gregorian, but this
    // algorithm uses astronomical year numbering for the calculation).
    days += 719468; // days from 0000-03-01 to 1970-01-01

    // 400-year cycle = 146097 days.
    let era = if days >= 0 {
        days / 146097
    } else {
        (days - 146096) / 146097
    };
    let day_of_era = days - era * 146097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let year = if month <= 2 { year + 1 } else { year };

    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_dump_cpu_profile_writes_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = dump_cpu_profile(
            Duration::from_secs(1),
            dir.path(),
            "test",
        );
        assert!(result.is_ok(), "dump_cpu_profile failed: {:?}", result.err());
        let svg_path = result.unwrap();
        assert!(svg_path.exists(), "SVG file not created at {}", svg_path.display());
        assert!(svg_path.to_string_lossy().ends_with(".svg"), "wrong extension");

        // Verify protobuf also written.
        let pb_path = svg_path.with_extension("pb");
        assert!(pb_path.exists(), "protobuf file not created at {}", pb_path.display());

        // Verify SVG looks like a flamegraph (contains expected elements).
        let svg_content = std::fs::read_to_string(&svg_path).expect("read SVG");
        assert!(svg_content.contains("<svg"), "SVG missing <svg> tag");
        assert!(svg_content.contains("flamegraph"), "SVG missing 'flamegraph'");
    }

    #[test]
    fn test_format_system_time_format() {
        let ts = format_system_time().expect("format_system_time");
        // Should match: YYYY-MM-DDTHH_MM_SS
        assert_eq!(ts.len(), 19, "wrong length: {ts}");
        assert_eq!(&ts[4..5], "-", "year-month separator");
        assert_eq!(&ts[7..8], "-", "month-day separator");
        assert_eq!(&ts[10..11], "T", "date-time separator");
        assert_eq!(&ts[13..14], "_", "hour-minute separator");
        assert_eq!(&ts[16..17], "_", "minute-second separator");
    }
}
```

- [ ] **Step 2: Add tempfile dev-dependency for tests**

Check if tempfile is already in `frp-core/Cargo.toml` dev-dependencies:

```bash
grep -n 'tempfile' frp-core/Cargo.toml
```

If not present, add to `frp-core/Cargo.toml` `[dev-dependencies]`:

```toml
tempfile = "3"
```

The `[dev-dependencies]` section is at line 61:

```toml
[dev-dependencies]
tower = "0.5"
criterion.workspace = true
proptest = "1.6"
```

Add after `proptest`:

```toml
tempfile = "3"
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p frp-core --features profiling -- profiling 2>&1 | tail -20
```

Expected: 2 tests pass.

```
test profiling::tests::test_dump_cpu_profile_writes_files ... ok
test profiling::tests::test_format_system_time_format ... ok
```

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p frp-core --features profiling 2>&1 | tail -5
```

Expected: No warnings.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/profiling.rs frp-core/Cargo.toml
git commit -m "feat(profiling): implement dump_cpu_profile function

- pprof CPU sampling at 99 Hz for configurable duration
- Writes flamegraph SVG and protobuf (.pb) to output directory
- std::time timestamp formatting (no chrono dep)
- Unit tests for file output and timestamp format

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Wire SIGUSR2 handler in frps

**Files:**
- Modify: `frps/src/main.rs`

**Interfaces:**
- Consumes: `frp_core::profiling::dump_cpu_profile` (from Task 2)
- Produces: SIGUSR2 handler running as tokio background task in frps

- [ ] **Step 1: Add handler function**

Open `frps/src/main.rs`. The SIGUSR1 handler is at lines 278-297. Add the SIGUSR2 handler function immediately after it (before line 299 `if let Err(e) = service.run().await`).

Replace the existing block from line 278 to line 306:

```rust
    // SIGUSR1 reload handler (Unix only) — kill -USR1 <pid>
    #[cfg(unix)]
    let reload_handle = {
        let svc = service.clone();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
                Ok(mut sig) => {
                    tracing::info!(pid = %std::process::id(), "SIGUSR1 reload ready (pid={})", std::process::id());
                    loop {
                        sig.recv().await;
                        match svc.reload().await {
                            Ok(summary) => tracing::info!(summary = %summary, "SIGUSR1: {}", summary),
                            Err(e) => tracing::error!(error = %e, "SIGUSR1 reload: {}", e),
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR1 unavailable: {}", e),
            }
        })
    };

    // SIGUSR2 CPU profile handler (Unix + profiling feature)
    #[cfg(all(unix, feature = "profiling"))]
    let profile_handle = {
        let output_dir = std::env::var("FRP_PROFILE_DIR").unwrap_or_else(|_| ".".to_string());
        let secs: u64 = std::env::var("FRP_PROFILE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()) {
                Ok(mut sig) => {
                    tracing::info!(
                        pid = %std::process::id(),
                        seconds = secs,
                        dir = %output_dir,
                        "SIGUSR2 profiling ready (pid={}, kill -USR2 {})",
                        std::process::id(),
                        std::process::id(),
                    );
                    loop {
                        sig.recv().await;
                        let dir = std::path::PathBuf::from(&output_dir);
                        let dur = std::time::Duration::from_secs(secs);
                        match tokio::task::spawn_blocking(move || {
                            frp_core::profiling::dump_cpu_profile(dur, &dir, "frps")
                        }).await {
                            Ok(Ok(path)) => {
                                tracing::info!(path = %path.display(), "CPU profile written");
                            }
                            Ok(Err(e)) => {
                                tracing::error!(error = %e, "CPU profile failed");
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "profile spawn_blocking join error");
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "SIGUSR2 unavailable: {}", e),
            }
        })
    };

    if let Err(e) = service.run().await {
        tracing::error!(error = %e, "frps error: {}", e);
        process::exit(frp_core::EXIT_RUNTIME);
    }

    #[cfg(unix)]
    reload_handle.abort();
    #[cfg(all(unix, feature = "profiling"))]
    profile_handle.abort();
}
```

- [ ] **Step 2: Verify build without profiling feature**

```bash
cargo build -p frps 2>&1 | tail -3
```

Expected: `Compiling frps` success. No profiling code included.

- [ ] **Step 3: Verify build with profiling feature**

```bash
cargo build -p frps --features profiling 2>&1 | tail -5
```

Expected: `Compiling frps` success with profiling.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p frps --features profiling 2>&1 | tail -5
```

Expected: No warnings.

- [ ] **Step 5: Commit**

```bash
git add frps/src/main.rs
git commit -m "feat(profiling): wire SIGUSR2 handler in frps

- Unix-only, gated on profiling feature
- FRP_PROFILE_DIR and FRP_PROFILE_SECS env var overrides
- spawn_blocking for CPU sampling, default 30s at 99 Hz
- Follows SIGUSR1 reload handler pattern exactly

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Wire SIGUSR2 handler in frpc

**Files:**
- Modify: `frpc/src/main.rs`

**Interfaces:**
- Consumes: `frp_core::profiling::dump_cpu_profile` (from Task 2)
- Produces: SIGUSR2 handler running as tokio background task in frpc (run_normal path only)

- [ ] **Step 1: Add handler function**

Open `frpc/src/main.rs`. The existing SIGUSR1 handler is at lines 429-451. The SIGUSR2 handler goes after it, before `if let Err(e) = service.run().await` at line 453.

Add after line 451 (after the `}` closing the SIGUSR1 block):

```rust
    // SIGUSR2 CPU profile handler (Unix + profiling feature)
    #[cfg(all(unix, feature = "profiling"))]
    {
        #[cfg(target_os = "macos")]
        const SIGUSR2: std::os::raw::c_int = 31;
        #[cfg(not(target_os = "macos"))]
        const SIGUSR2: std::os::raw::c_int = 12;

        let output_dir = std::env::var("FRP_PROFILE_DIR").unwrap_or_else(|_| ".".to_string());
        let secs: u64 = std::env::var("FRP_PROFILE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        tokio::spawn(async move {
            let mut sig = match signal::unix::signal(signal::unix::SignalKind::from_raw(SIGUSR2)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SIGUSR2 handler init failed: {}", e);
                    return;
                }
            };
            tracing::info!(
                pid = %std::process::id(),
                seconds = secs,
                dir = %output_dir,
                "SIGUSR2 profiling ready (pid={}, kill -USR2 {})",
                std::process::id(),
                std::process::id(),
            );
            loop {
                sig.recv().await;
                let dir = std::path::PathBuf::from(&output_dir);
                let dur = std::time::Duration::from_secs(secs);
                match tokio::task::spawn_blocking(move || {
                    frp_core::profiling::dump_cpu_profile(dur, &dir, "frpc")
                }).await {
                    Ok(Ok(path)) => {
                        tracing::info!(path = %path.display(), "CPU profile written");
                    }
                    Ok(Err(e)) => {
                        tracing::error!(error = %e, "CPU profile failed");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "profile spawn_blocking join error");
                    }
                }
            }
        });
    }
```

Note: frpc uses the hardcoded signal number pattern (`from_raw(SIGUSR2)`) to match its existing SIGUSR1 handler style, while frps uses `SignalKind::user_defined1/2()`. This is intentional — each binary follows its own existing pattern.

- [ ] **Step 2: Verify build without profiling feature**

```bash
cargo build -p frpc 2>&1 | tail -3
```

Expected: `Compiling frpc` success.

- [ ] **Step 3: Verify build with profiling feature**

```bash
cargo build -p frpc --features profiling 2>&1 | tail -5
```

Expected: `Compiling frpc` success with profiling.

- [ ] **Step 4: Run clippy**

```bash
cargo clippy -p frpc --features profiling 2>&1 | tail -5
```

Expected: No warnings.

- [ ] **Step 5: Commit**

```bash
git add frpc/src/main.rs
git commit -m "feat(profiling): wire SIGUSR2 handler in frpc

- Unix-only, gated on profiling feature
- Follows frpc existing SIGUSR1 pattern (from_raw signal numbers)
- FRP_PROFILE_DIR and FRP_PROFILE_SECS env var overrides
- Only in run_normal path (not reload/status subcommands)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Build verification — full workspace

**Files:**
- None (verification only)

**Interfaces:**
- Consumes: Tasks 1-4 complete
- Produces: Verified builds across all feature combinations

- [ ] **Step 1: Default build (no profiling)**

```bash
cargo build --workspace 2>&1 | tail -5
```

Expected: All crates compile. Profiling code not included.

- [ ] **Step 2: Profiling build**

```bash
cargo build --workspace --features profiling 2>&1 | tail -5
```

Expected: All crates compile with profiling enabled.

- [ ] **Step 3: Micro build with profiling**

```bash
cargo build -p frps -p frpc --no-default-features --features micro,profiling 2>&1 | tail -5
```

Expected: frps-micro and frpc-micro compile with profiling. pprof/inferno pulled in.

- [ ] **Step 4: Run full test suite**

```bash
cargo test --workspace --features profiling 2>&1 | tail -20
```

Expected: All tests pass. Include profiling module tests.

```bash
cargo test --workspace 2>&1 | tail -10
```

Expected: All tests pass without profiling feature.

- [ ] **Step 5: Clippy all feature combinations**

```bash
cargo clippy --workspace --features profiling 2>&1 | tail -5
cargo clippy --workspace 2>&1 | tail -5
```

Expected: No warnings in either build.

- [ ] **Step 6: Commit (if any Cargo.lock changes)**

```bash
git add Cargo.lock
git commit -m "chore: update Cargo.lock for pprof dependency" || echo "no lock changes"
```
