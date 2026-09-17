# Memory Efficiency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a memory-measurement harness (in-process counting allocator behind a `mem-profile` feature + external RSS, over idle-hold and churn workloads), then reduce per-connection resident footprint and allocation churn, ordered by measured benefit.

**Architecture:** From `docs/superpowers/specs/2026-07-12-memory-efficiency-design.md`. Phase 1 adds a `CountingAlloc<System>` global allocator in `frp-core`, compiled only under a new `mem-profile` feature (off in all shipped builds → byte-identical production binaries), plus a reworked `frp-stress` memory scenario (idle-hold + churn) and a driver that samples allocator counters and `ps` RSS into a committed baseline. Phase 2 applies data-ordered optimizations: M1 per-connection bridge buffer size (throughput-gated), M2 cipher_stream per-chunk allocation reuse, M3/M4 control-plane + pool audits.

**Tech Stack:** Rust, std `GlobalAlloc`/`System` + `core::sync::atomic` (counting allocator — no new dep), tokio, the standalone `frp-stress` harness (clap, serde_json), `ps` for RSS.

## Global Constraints

- **No wire-protocol change.** No message/framing/encryption format change. `compat-test.sh` must stay green after any bridge/cipher change. Wire-identical to Go frp v0.69.1.
- **No new dependencies** (CLAUDE.md). Counting allocator is `std::alloc::{GlobalAlloc, System, Layout}` + `core::sync::atomic::AtomicUsize`. RSS is the `ps` CLI. Aggregation is arithmetic on a `Vec`. `frp-stress` already has `serde_json`, `clap`, `tokio`.
- **`mem-profile` is off in every shipped build** (full/tiny/micro). With it off, no allocator wrapper and no emitter code is compiled — production binaries are byte-identical to today. The feature exists only for the measurement build the driver produces.
- **`frp-stress` is a standalone workspace** under `scripts/frp-stress/` — NOT a root workspace member. Build with `(cd scripts/frp-stress && cargo build --release)`. Never add it to root `Cargo.toml` members (broke Docker + CI before).
- **Memory gate (primary):** allocator counters `live_per_conn` (idle-hold) and `total_alloc` (churn) from `memory-baseline.sh`. **RSS is directional only** (OS/allocator slack, does not shrink promptly) — never gate solely on RSS.
- **No-regression gates (secondary):** `throughput-baseline.sh` (any config >5% MB/s drop rejects) and `latency-baseline.sh` (steady p99 no regression). Memory changes must not undo the throughput/CPU/latency axes.
- **Process (CLAUDE.md):** each task in a git worktree, implemented by a subagent, task-reviewed. After any bridge/cipher/buffer change run `bash scripts/compat-test.sh --verbose` and verify the `RESULTS:` line shows 0 failures (a partial run with no RESULTS line is NOT a pass).

---

### Task 1: Memory harness — counting allocator + scenario + driver (Phase 1)

Add a feature-gated counting global allocator to `frp-core`, wire the `mem-profile` feature through `frp-server`/`frp-client`/`frps`/`frpc`, install the allocator + a 1 Hz stderr emitter in the binaries, rework the `frp-stress` memory scenario into idle-hold and churn modes, add a driver, and commit the pre-optimization baseline. No production behavior change (feature off = byte-identical).

**Files:**
- Create: `frp-core/src/mem_profile.rs`
- Modify: `frp-core/src/lib.rs` (gated `pub mod mem_profile;`)
- Modify: `frp-core/Cargo.toml`, `frp-server/Cargo.toml`, `frp-client/Cargo.toml`, `frps/Cargo.toml`, `frpc/Cargo.toml` (feature declarations)
- Modify: `frps/src/main.rs`, `frpc/src/main.rs` (gated `#[global_allocator]` + emitter spawn)
- Modify: `scripts/frp-stress/src/scenarios/memory.rs` (idle-hold + churn modes)
- Create: `scripts/memory-baseline.sh`
- Test: inline `#[cfg(test)]` in `mem_profile.rs`

**Interfaces:**
- Produces: `frp_core::mem_profile::CountingAlloc` (unit struct, `GlobalAlloc`); `frp_core::mem_profile::snapshot() -> (usize, usize, usize)` returning `(live_bytes, total_alloc, alloc_count)`; `frp_core::mem_profile::spawn_emitter()` (spawns a tokio task printing `MEMPROFILE live=<> total=<> allocs=<>` to stderr every second). All only exist under `feature = "mem-profile"`.
- Consumes: existing `Cli` fields `mode`, `msg_bytes`, `concurrency`, `duration`, `port`, `frps_addr` (all already present from the latency and stress work), the existing `echo` backend scenario.

- [ ] **Step 1: Create the counting allocator module**

Create `frp-core/src/mem_profile.rs`:

```rust
//! Measurement-only global allocator, compiled ONLY under `feature = "mem-profile"`.
//! Wraps the system allocator and tracks live + cumulative bytes via atomics.
//! Off in all shipped builds — production binaries never include this file.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::{GlobalAlloc, Layout, System};

pub static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
pub static TOTAL_ALLOC: AtomicUsize = AtomicUsize::new(0);
pub static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

/// System-allocator wrapper that counts allocations. Install as
/// `#[global_allocator]` in the binary crates under `mem-profile`.
pub struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            TOTAL_ALLOC.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let np = System.realloc(ptr, layout, new_size);
        if !np.is_null() {
            if new_size >= layout.size() {
                let d = new_size - layout.size();
                LIVE_BYTES.fetch_add(d, Ordering::Relaxed);
                TOTAL_ALLOC.fetch_add(d, Ordering::Relaxed);
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        np
    }
}

/// Current `(live_bytes, total_alloc, alloc_count)`.
pub fn snapshot() -> (usize, usize, usize) {
    (
        LIVE_BYTES.load(Ordering::Relaxed),
        TOTAL_ALLOC.load(Ordering::Relaxed),
        ALLOC_COUNT.load(Ordering::Relaxed),
    )
}

/// Spawn a 1 Hz emitter that prints a `MEMPROFILE` line to stderr. Call once
/// after the tokio runtime is up. The driver parses these lines.
pub fn spawn_emitter() {
    tokio::spawn(async {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let (live, total, allocs) = snapshot();
            eprintln!("MEMPROFILE live={live} total={total} allocs={allocs}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_monotonic_total() {
        // total_alloc is cumulative and never decreases across two snapshots.
        let (_, t0, _) = snapshot();
        let _v: Vec<u8> = Vec::with_capacity(4096);
        let (_, t1, _) = snapshot();
        assert!(t1 >= t0, "total_alloc must be monotonic: {t1} >= {t0}");
    }

    #[test]
    fn counting_alloc_tracks_live() {
        // Direct alloc/dealloc through the wrapper moves LIVE_BYTES by size.
        let before = LIVE_BYTES.load(Ordering::Relaxed);
        let layout = Layout::from_size_align(8192, 8).unwrap();
        unsafe {
            let p = CountingAlloc.alloc(layout);
            assert!(!p.is_null());
            let mid = LIVE_BYTES.load(Ordering::Relaxed);
            assert!(mid >= before + 8192, "live rose by >= size");
            CountingAlloc.dealloc(p, layout);
        }
        let after = LIVE_BYTES.load(Ordering::Relaxed);
        assert!(after <= before + 8192, "live fell back after dealloc");
    }
}
```

- [ ] **Step 2: Register the module (gated) in `frp-core/src/lib.rs`**

Add near the other `pub mod` declarations in `frp-core/src/lib.rs`:

```rust
#[cfg(feature = "mem-profile")]
pub mod mem_profile;
```

- [ ] **Step 3: Declare the `mem-profile` feature across crates**

In `frp-core/Cargo.toml`, under `[features]`, add:

```toml
mem-profile = []
```

In `frp-server/Cargo.toml`, under `[features]`, add:

```toml
mem-profile = ["frp-core/mem-profile"]
```

In `frp-client/Cargo.toml`, under `[features]`, add:

```toml
mem-profile = ["frp-core/mem-profile"]
```

In `frps/Cargo.toml`, under `[features]`, add:

```toml
mem-profile = ["frp-server/mem-profile"]
```

In `frpc/Cargo.toml`, under `[features]`, add:

```toml
mem-profile = ["frp-client/mem-profile"]
```

(Do NOT add `mem-profile` to any `default`/`full`/`tiny`/`micro` set — it stays opt-in.)

- [ ] **Step 4: Install the allocator + emitter in `frps/src/main.rs`**

At the top level of `frps/src/main.rs` (module scope, after the `use` lines), add the gated global allocator:

```rust
#[cfg(feature = "mem-profile")]
#[global_allocator]
static GLOBAL: frp_core::mem_profile::CountingAlloc = frp_core::mem_profile::CountingAlloc;
```

Then in `async fn main()`, immediately after `let cli = parse_frps_args();` and before `run(cli).await;`, add:

```rust
    #[cfg(feature = "mem-profile")]
    frp_core::mem_profile::spawn_emitter();
```

- [ ] **Step 5: Install the allocator + emitter in `frpc/src/main.rs`**

Do the same in `frpc/src/main.rs`: add the module-scope gated `#[global_allocator]` static (identical to Step 4), and after the CLI is parsed but before the client runs, add the gated `frp_core::mem_profile::spawn_emitter();`. (Read `frpc/src/main.rs` to place the spawn right after arg parsing, inside the async runtime, mirroring frps.)

- [ ] **Step 6: Build the measurement variant to confirm wiring**

Run: `cargo build -p frps -p frpc --features mem-profile 2>&1 | tail -5`
Expected: clean build. Then confirm the feature-off build is unaffected:
Run: `cargo build -p frps -p frpc 2>&1 | tail -3`
Expected: clean build, no allocator compiled.

- [ ] **Step 7: Run the allocator unit tests**

Run: `cargo test -p frp-core --features mem-profile mem_profile 2>&1 | tail -15`
Expected: `snapshot_monotonic_total` and `counting_alloc_tracks_live` PASS.

- [ ] **Step 8: Rework the memory scenario (idle-hold + churn)**

Replace the contents of `scripts/frp-stress/src/scenarios/memory.rs` with:

```rust
use crate::Cli;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    match cli.mode.as_str() {
        "idle_hold" => idle_hold(cli, &target).await,
        "churn" => churn(cli, &target).await,
        other => anyhow::bail!("unknown memory mode: {other} (expected idle_hold|churn)"),
    }
}

/// Open N proxy connections, send one small message on each (forcing the
/// server + client bridge to allocate their per-connection buffers), then hold
/// them idle. Targets resident footprint (the pinned-buffer cost).
async fn idle_hold(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let mut buf = vec![0u8; msg.len()];
    let mut streams = Vec::with_capacity(cli.concurrency);
    tracing::info!(n = cli.concurrency, "idle_hold: opening {} conns, 1 msg each", cli.concurrency);
    for i in 0..cli.concurrency {
        let mut s = TcpStream::connect(target)
            .await
            .with_context(|| format!("idle_hold connect {i}"))?;
        s.write_all(&msg).await?;
        s.read_exact(&mut buf).await?; // forces both bridge buffers to allocate
        streams.push(s);
    }
    tracing::info!("idle_hold: MARK ramped ({} conns)", streams.len());
    tokio::time::sleep(Duration::from_secs(cli.duration)).await;
    tracing::info!("idle_hold: MARK hold-end, draining {} conns", streams.len());
    drop(streams);
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(())
}

/// Repeatedly open -> send one message -> close, at fixed concurrency, for the
/// duration. Targets allocation rate (per-connection setup/teardown churn).
async fn churn(cli: &Cli, target: &str) -> Result<()> {
    let msg = vec![0xABu8; cli.msg_bytes.max(1)];
    let conc = cli.concurrency.max(1);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    tracing::info!(concurrency = conc, "churn: MARK start, open->1msg->close for {}s", cli.duration);
    let mut handles = Vec::with_capacity(conc);
    for _ in 0..conc {
        let target = target.to_string();
        let msg = msg.clone();
        handles.push(tokio::spawn(async move {
            let mut buf = vec![0u8; msg.len()];
            while tokio::time::Instant::now() < deadline {
                if let Ok(mut s) = TcpStream::connect(&target).await {
                    let _ = s.write_all(&msg).await;
                    let _ = s.read_exact(&mut buf).await;
                    drop(s);
                }
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    tracing::info!("churn: MARK end");
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
```

(`scenarios/mod.rs` already registers `pub mod memory;` and `main.rs` already dispatches `"memory"` — confirm both; if the `"memory"` match arm is absent, add `"memory" => scenarios::memory::run(&cli).await?,` after the `"latency"` arm.)

- [ ] **Step 9: Build the harness**

Run: `(cd scripts/frp-stress && cargo build --release 2>&1 | tail -3)`
Expected: clean build.

- [ ] **Step 10: Write the driver script**

Create `scripts/memory-baseline.sh`:

```bash
#!/usr/bin/env bash
# =============================================================================
# frp-rs memory baseline: per-connection footprint (idle-hold) + allocation
# churn, measured via the mem-profile counting allocator + ps RSS.
# Usage: bash scripts/memory-baseline.sh [connections]
# Output: scripts/frp-stress/baselines/memory-<hostname>.jsonl
#
# frps/frpc are built with --features mem-profile so they emit `MEMPROFILE
# live=.. total=.. allocs=..` to stderr every second. The driver parses those
# logs (allocator counters, the PRIMARY gate) and samples ps RSS (directional).
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

CONNS="${1:-500}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="memory-token"
OUT="scripts/frp-stress/baselines/memory-$(hostname -s).jsonl"

echo "=== Building mem-profile binaries + harness ==="
cargo build --release -p frps -p frpc --features mem-profile 2>&1 | tail -2
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

FRPS=./target/release/frps
FRPC=./target/release/frpc
STRESS=./scripts/frp-stress/target/release/frp-stress

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# Peak `live=` from a MEMPROFILE log, or 0 if none.
peak_live() { grep -o 'live=[0-9]*' "$1" 2>/dev/null | cut -d= -f2 | sort -n | tail -1 || echo 0; }
# First `live=` (near-startup baseline), or 0.
base_live() { grep -o 'live=[0-9]*' "$1" 2>/dev/null | head -1 | cut -d= -f2 || echo 0; }
# Max `total=` (cumulative allocations), or 0.
max_total() { grep -o 'total=[0-9]*' "$1" 2>/dev/null | cut -d= -f2 | sort -n | tail -1 || echo 0; }

# run_case <label> <mode> <encrypt:true|false>
run_case() {
  local label="$1" mode="$2" enc="$3"
  echo "=== case: $label ($mode, encrypt=$enc, conns=$CONNS) ==="
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""
    echo "[log]"; echo "level = \"error\""
  } > /tmp/mem-frps.toml
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "[[proxies]]"
    echo "name = \"mem-tcp\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
    echo "use_encryption = $enc"
  } > /tmp/mem-frpc.toml

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/mem-frps.toml 2>/tmp/mem-frps.log & local frps_pid=$!; PIDS+=($frps_pid)
  sleep 1
  "$FRPC" -c /tmp/mem-frpc.toml 2>/tmp/mem-frpc.log & local frpc_pid=$!; PIDS+=($frpc_pid)
  sleep 2

  # Background RSS sampler (directional cross-check).
  : > /tmp/mem-rss.log
  ( while true; do
      local rs; rs=$(ps -o rss= -p "$frps_pid" 2>/dev/null | tr -d ' ')
      local rc; rc=$(ps -o rss= -p "$frpc_pid" 2>/dev/null | tr -d ' ')
      echo "${rs:-0} ${rc:-0}" >> /tmp/mem-rss.log
      sleep 1
    done ) & local sampler=$!; PIDS+=($sampler)

  "$STRESS" --scenario memory --mode "$mode" --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --concurrency "$CONNS" \
    --duration 15 --msg-bytes 64 --label "$label" || \
    echo "WARNING: memory run '$label' failed" >&2

  sleep 2 # let the 1 Hz emitter capture the peak
  kill "$sampler" 2>/dev/null || true

  local live_idle live_peak total rss_s rss_c per_conn
  live_idle=$(base_live /tmp/mem-frps.log)
  live_peak=$(peak_live /tmp/mem-frps.log)
  total=$(max_total /tmp/mem-frps.log)
  rss_s=$(awk 'BEGIN{m=0}{if($1>m)m=$1}END{print m+0}' /tmp/mem-rss.log)
  rss_c=$(awk 'BEGIN{m=0}{if($2>m)m=$2}END{print m+0}' /tmp/mem-rss.log)
  if [ "$mode" = "idle_hold" ] && [ "$CONNS" -gt 0 ]; then
    per_conn=$(( (live_peak - live_idle) / CONNS ))
  else
    per_conn=0
  fi

  printf '{"label":"%s","mode":"%s","connections":%s,"encrypt":%s,"live_bytes_idle":%s,"live_bytes_peak":%s,"total_alloc":%s,"rss_kb_frps":%s,"rss_kb_frpc":%s,"live_per_conn":%s}\n' \
    "$label" "$mode" "$CONNS" "$enc" "$live_idle" "$live_peak" "$total" "$rss_s" "$rss_c" "$per_conn" >> "$OUT"

  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

#         label               mode        encrypt
run_case "idle_plain"        idle_hold   false
run_case "idle_encrypt"      idle_hold   true
run_case "churn_plain"       churn       false
run_case "churn_encrypt"     churn       true

echo "=== memory baseline written: $OUT ==="
cat "$OUT"
```

- [ ] **Step 11: Make the driver executable and run it for the pre-optimization baseline**

Run: `chmod +x scripts/memory-baseline.sh && bash scripts/memory-baseline.sh`
Expected: writes `scripts/frp-stress/baselines/memory-<host>.jsonl` with 4 records (idle_plain, idle_encrypt, churn_plain, churn_encrypt). Record the `live_per_conn` (idle rows) and `total_alloc` (churn rows) — the Phase-2 anchors. If a record shows `live_per_conn=0` on an idle row, the allocator or emitter is not wired (diagnose: is the binary built with `--features mem-profile`? does `/tmp/mem-frps.log` contain `MEMPROFILE` lines?) before committing.

- [ ] **Step 12: Commit**

```bash
git add frp-core/src/mem_profile.rs frp-core/src/lib.rs frp-core/Cargo.toml \
  frp-server/Cargo.toml frp-client/Cargo.toml frps/Cargo.toml frpc/Cargo.toml \
  frps/src/main.rs frpc/src/main.rs \
  scripts/frp-stress/src/scenarios/memory.rs scripts/memory-baseline.sh \
  scripts/frp-stress/baselines/ Cargo.lock
git commit -m "test(mem): memory harness — counting allocator + idle-hold/churn baseline

CountingAlloc<System> behind a new mem-profile feature (std GlobalAlloc +
AtomicUsize, off in all shipped builds => byte-identical production binaries),
1 Hz MEMPROFILE stderr emitter, reworked frp-stress memory scenario (idle-hold
+ churn), memory-baseline.sh driver sampling allocator counters + ps RSS,
committed pre-optimization baseline. No new dependency."
```

---

### Task 2: M1 — per-connection bridge buffer size (footprint, throughput-gated)

The fattest resident-footprint lever: each connection pins 2 × `BUFFER_SIZE` (64 KiB) buffers for its lifetime. Shrinking the default halves per-connection footprint uniformly. This is the concrete, low-complexity path; it is **kept only if it passes the throughput no-regression gate**. If shrinking regresses throughput, revert and report (adaptive idle-release is the escalation, see Step 7).

**Files:**
- Modify: `frp-core/src/buffer_pool.rs:16-23` (the `BUFFER_SIZE` default)
- Reference: `scripts/frp-stress/baselines/memory-<host>.jsonl`, `throughput-Mac.jsonl`

**Interfaces:**
- Consumes: `frp_core::buffer_pool::BUFFER_SIZE` (a `LazyLock<usize>`), the memory + throughput baselines.
- Produces: no signature change — a smaller default buffer size.

- [ ] **Step 1: Confirm the idle-hold footprint from the Task-1 baseline**

Read `scripts/frp-stress/baselines/memory-<host>.jsonl`. Note `live_per_conn` for `idle_plain`/`idle_encrypt`. If it is far below `2 * 65536` (≈131072), most per-conn footprint is NOT the bridge buffers — record that and treat M1 as low-value (the shrink may not be worth the throughput risk); still measure, but weight the decision toward "keep only if free". If it is near 2×64 KiB, the buffers dominate and the shrink is the right lever.

- [ ] **Step 2: Shrink the default buffer size**

In `frp-core/src/buffer_pool.rs`, change the `BUFFER_SIZE` default from 64 KiB to 32 KiB (matching Go frp's `io.Copy` 32 KiB). The env override stays. Change:

```rust
        .filter(|kb| *kb >= 4 && *kb <= 1024)
        .map(|kb| kb * 1024)
        .unwrap_or(65536)
```

to:

```rust
        .filter(|kb| *kb >= 4 && *kb <= 1024)
        .map(|kb| kb * 1024)
        .unwrap_or(32768)
```

Also update the doc comment two lines above from `Defaults to 64KB` to `Defaults to 32KB (matches Go frp io.Copy)`.

- [ ] **Step 3: Build and run the buffer-pool tests**

Run: `cargo test -p frp-core buffer_pool 2>&1 | tail -15`
Expected: PASS (the tests assert `capacity() >= *BUFFER_SIZE` and length behavior, which hold at 32 KiB).

- [ ] **Step 4: Re-run the memory baseline and confirm the footprint drop**

Run: `bash scripts/memory-baseline.sh`
Expected: `live_per_conn` on the idle rows drops by roughly one 32 KiB buffer per direction vs the Task-1 anchor (about −65 KiB/conn if the bridge buffers dominate). Record before/after.

- [ ] **Step 5: Throughput no-regression gate (decides keep vs revert)**

Run: `bash scripts/throughput-baseline.sh`
Expected: no config drops >5% MB/s vs the committed `throughput-Mac.jsonl`. The plain/compress/mux copy paths are the ones a smaller buffer could slow. If any exceeds −5% (beyond documented thermal noise on plain/tls/mux — confirm by checking whether encrypt/compress, which are less copy-bound, also moved), the shrink FAILS its gate: revert Step 2 (`git checkout frp-core/src/buffer_pool.rs`) and skip to Step 7.

- [ ] **Step 6: Latency no-regression + compat**

Run: `bash scripts/latency-baseline.sh`
Expected: steady p99 no worse than the committed latency baseline (buffer size is off the small-message path; expect no change).
Run: `bash scripts/compat-test.sh --verbose`
Expected: `RESULTS:` line with 0 failures (buffer size is wire-invisible). Verify the RESULTS line explicitly.

- [ ] **Step 7: Decide and commit (or revert + report)**

- If Steps 4–6 pass (footprint dropped, no throughput/latency regression, compat green): keep the change and commit:

```bash
git add frp-core/src/buffer_pool.rs scripts/frp-stress/baselines/
git commit -m "perf(mem): shrink default bridge buffer 64KB->32KB (Go frp parity)

Each connection pins 2 bridge buffers for its lifetime; halving the default
cuts per-connection resident footprint by ~64KB. Matches Go frp io.Copy 32KB.
Throughput no config >5% regress; latency unchanged; compat 57/0. Env override
FRP_BRIDGE_BUF_KB unchanged. Memory baseline refreshed."
```

- If the shrink failed the throughput gate: revert it, commit only the refreshed baseline note, and report **DONE_WITH_CONCERNS** recommending the adaptive idle-release alternative (keep 64 KiB for active connections, return the buffer to the pool after an idle interval, re-acquire on wakeup — a larger change scoped to `bridge.rs`'s read loops, to be planned separately with its own throughput gate). Do NOT implement adaptive idle-release unprompted; surface it as the next option with the measured numbers that justify it.

---

### Task 3: M2 — cipher_stream per-chunk allocation reuse (churn, encrypt path)

On the encrypted bridge, `CipherWriter::poll_write` allocates a fresh `Vec` per write chunk (`buf.to_vec()`), driving allocation churn under active encrypted traffic. Reuse a persistent scratch buffer on the hot (non-first, non-partial) write path so the common case allocates nothing. Wire-identical (same AES-128-CFB output).

**Files:**
- Modify: `frp-core/src/cipher_stream.rs` (the `CipherWriter` struct + its `poll_write` normal-write branch near line 334; add a `scratch: Vec<u8>` field and its initializer)
- Test: inline `#[cfg(test)]` in `frp-core/src/cipher_stream.rs` (round-trip through a reused scratch)

**Interfaces:**
- Consumes: the existing `CfbState::encrypt(&mut [u8])` (in-place), the `CipherWriter` partial-write state (`encrypted_buf: Option<Vec<u8>>`, `encrypted_write_pos`).
- Produces: no public signature change — an internal scratch buffer reducing per-chunk allocation on the encrypt path.

- [ ] **Step 1: Read the current normal-write branch**

Read `frp-core/src/cipher_stream.rs` around lines 332–360 (the branch after the pending-`encrypted_buf` drain: `let cfb = this.cfb.as_mut()...; let mut encrypted = buf.to_vec(); cfb.encrypt(&mut encrypted); match ... poll_write(cx, &encrypted)`). Identify the `CipherWriter` struct definition and its constructor to add the field.

- [ ] **Step 2: Add a `scratch` field to `CipherWriter`**

In the `CipherWriter` struct definition, add:

```rust
    /// Reused encrypt scratch — avoids a per-chunk `Vec` allocation on the hot
    /// write path. Moved out (via `mem::take`) only on the rare partial-write
    /// branch, then regrown on the next call.
    scratch: Vec<u8>,
```

Initialize `scratch: Vec::new(),` in the single constructor `CipherWriter::new` (`frp-core/src/cipher_stream.rs:227`, the `Self { ... }` literal at ~line 228). All tests construct via `CipherWriter::new(...)`, so this is the only struct-literal site — confirm by grepping `Self {` within the `impl ... CipherWriter` block (the `Self {` at ~line 500 belongs to a different type, do not touch it).

- [ ] **Step 3: Use the scratch on the normal-write branch**

Replace the normal-write branch body (the `let mut encrypted = buf.to_vec(); cfb.encrypt(&mut encrypted); match Pin::new(&mut this.inner).poll_write(cx, &encrypted) { ... }` block near line 334) with a scratch-reusing version:

```rust
        let cfb = this.cfb.as_mut().expect("IV must be sent before encrypting");
        this.scratch.clear();
        this.scratch.extend_from_slice(buf);
        cfb.encrypt(&mut this.scratch);
        match Pin::new(&mut this.inner).poll_write(cx, &this.scratch) {
            Poll::Ready(Ok(n)) if n >= this.scratch.len() => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Ok(n)) => {
                // Partial write: hand the un-written remainder to the pending
                // buffer (rare backpressure path — pays one alloc via take).
                this.encrypted_buf = Some(std::mem::take(&mut this.scratch));
                this.encrypted_write_pos = n;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                this.encrypted_buf = Some(std::mem::take(&mut this.scratch));
                this.encrypted_write_pos = 0;
                Poll::Pending
            }
        }
```

(Preserve whatever the current branch does on `Poll::Pending` / partial write — the key change is `this.scratch` replaces the per-call `encrypted` Vec on the full-write path, and `mem::take` moves it into `encrypted_buf` only on the partial/pending paths. If the current code's partial-write bookkeeping differs, keep its exact semantics and only swap the allocation source.)

- [ ] **Step 4: Add a round-trip test through the reused scratch**

Add to the `#[cfg(test)] mod tests` in `frp-core/src/cipher_stream.rs` a test that writes several chunks through one `CipherWriter` (so the scratch is reused across chunks) and decrypts them through the matching reader, asserting the plaintext round-trips. Model it on the existing multi-write cipher_stream tests (e.g. the one near line 936 that splits data across writes). Name it `cipher_writer_scratch_reuse_roundtrip`. Assert the decrypted output equals the input across at least 3 sequential writes.

- [ ] **Step 5: Run the cipher_stream tests**

Run: `cargo test -p frp-core cipher_stream 2>&1 | tail -20`
Expected: all cipher_stream tests PASS, including the new `cipher_writer_scratch_reuse_roundtrip` and the existing chunked/round-trip characterization tests (proving wire-identical behavior).

- [ ] **Step 6: Confirm the churn reduction + no throughput regression**

Run: `bash scripts/memory-baseline.sh`
Expected: `total_alloc` on the `churn_encrypt` row drops vs the Task-1/2 anchor (fewer per-chunk allocations); `churn_plain` unchanged (plain path untouched). Record before/after.
Run: `bash scripts/throughput-baseline.sh`
Expected: encrypt / encrypt_compress rows no >5% regress (scratch reuse should be neutral-to-positive). No plain-path change.

- [ ] **Step 7: Compat gate + commit**

Run: `bash scripts/compat-test.sh --verbose`
Expected: `RESULTS:` line with 0 failures (encryption output byte-identical). Verify explicitly.

```bash
git add frp-core/src/cipher_stream.rs scripts/frp-stress/baselines/
git commit -m "perf(mem): reuse cipher_stream encrypt scratch buffer

CipherWriter::poll_write allocated a fresh Vec per chunk (buf.to_vec()).
Reuse a persistent scratch on the hot full-write path; move it into the
pending buffer via mem::take only on the rare partial-write branch. Cuts
encrypt-path allocation churn; wire-identical AES-128-CFB (compat 57/0,
round-trip + chunked characterization tests green). Memory baseline refreshed."
```

---

### Task 4: M3 + M4 — control-plane + pool audits (data-gated, likely note-only)

Attribute the remaining per-connection live-bytes with the counting allocator and audit the buffer-pool retention. Act only where the data shows a material, low-risk win; otherwise record findings and change nothing (YAGNI).

**Files:**
- Create: `docs/superpowers/notes/2026-07-12-memory-control-plane-audit.md`
- Possibly modify (only if data justifies a clear, low-risk win): a single `Vec::with_capacity` / channel-bound / `MAX_POOLED_BUFFERS` site — otherwise no code change.

**Interfaces:** none (audit; optional micro-fix).

- [ ] **Step 1: Attribute per-connection live-bytes beyond bridge buffers**

From the post-M1/M2 `memory-<host>.jsonl`, compute the residual `live_per_conn` after the bridge-buffer contribution (idle rows). If residual per-conn is small (a few KiB), control-plane overhead is immaterial — record and skip to Step 3. If it is large, read the control-plane per-connection structures to find the contributor: in `frp-server/src/control.rs` (or `control/mod.rs`) the handler-task locals `work_pool`, `pending_requests`, and channel creation; in `frp-server/src/service.rs` the `AppState` maps. Note any obviously over-reserved allocation (e.g. a `Vec::with_capacity(N)` with large N per connection, or a large channel bound).

- [ ] **Step 2: Apply a fix ONLY if a clear, low-risk, Go-compatible win exists**

If Step 1 found a concrete over-allocation (e.g. an unnecessary large `with_capacity`, a needlessly large channel buffer), make the minimal change to right-size it, and note it. If nothing clearly wins, make NO code change (over-tuning control-plane allocations risks latency/throughput for marginal memory — YAGNI). Record the decision either way.

- [ ] **Step 3: Audit buffer-pool retention (M4)**

Read `frp-core/src/buffer_pool.rs`. Confirm `MAX_POOLED_BUFFERS = 32` is a sensible idle-retention cap given the measured active-buffer high-water mark (roughly `2 × peak concurrent connections` during idle-hold), and that the release/acquire length+capacity handling (the throughput axis's zero-fill-skip) is memory-correct (no unbounded growth — the existing `test_pool_does_not_grow_unbounded` covers this). Expected: no change or a one-line tuning note. Do not raise `MAX_POOLED_BUFFERS` unless idle-retention data plus Go-compat justify it (a larger pool trades idle memory for fewer allocs — usually the wrong direction for a memory axis).

- [ ] **Step 4: Write the audit note**

Create `docs/superpowers/notes/2026-07-12-memory-control-plane-audit.md` recording: the residual per-connection live-bytes after M1/M2; the control-plane structures examined (file:line) and their per-conn cost; the M3 decision (fix applied with numbers, or no-change with reason); the M4 pool-retention conclusion. If a fix was applied, include its before/after `live_per_conn`.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/notes/2026-07-12-memory-control-plane-audit.md frp-core/src/buffer_pool.rs frp-server/ scripts/frp-stress/baselines/ 2>/dev/null || git add docs/superpowers/notes/2026-07-12-memory-control-plane-audit.md
git commit -m "docs(mem): control-plane + pool retention audit

Attributed residual per-connection live-bytes after M1/M2; audited
control-plane per-conn structures and buffer-pool retention. <one line:
fix applied with numbers, or no-change YAGNI with reason>."
```

---

## Self-Review

- **Spec coverage:** Phase 1 harness (counting allocator + mem-profile feature + idle-hold/churn scenario + driver + baseline) → Task 1. M1 per-conn buffers → Task 2 (shrink, throughput-gated, adaptive-release as escalation). M2 cipher_stream churn → Task 3. M3 control-plane audit + M4 pool audit → Task 4. Memory primary gate (allocator counters) in Tasks 2/3 Steps; throughput + latency no-regress gates in Tasks 2/3; compat gate after every bridge/cipher change. All spec sections mapped.
- **Placeholders:** none — full code for the allocator, feature declarations per crate, both bin installs, the scenario, the driver, the buffer-size change, and the scratch-reuse branch; exact commands and commit messages. The data-gated tasks (2 decide-keep-vs-revert, 4 act-only-if-material) carry concrete code for the action path plus an explicit decision rule — they are gated, not vague.
- **Type consistency:** `snapshot() -> (usize, usize, usize)` used consistently between `mem_profile.rs` and the emitter; `CountingAlloc` unit struct referenced identically in both bin mains; `spawn_emitter()` signature matches its call sites; JSON keys (`live_per_conn`, `total_alloc`, …) match between the driver and the Phase-2 references; `BUFFER_SIZE` and `scratch` names consistent across tasks.
- **Constraint check:** no new deps (std `GlobalAlloc`/`AtomicUsize`, `ps`, existing `serde_json`); `mem-profile` never added to any shipped feature set (byte-identical production); `frp-stress` stays standalone (driver builds it separately); wire-invisible (compat gate confirms); allocator counters are the primary gate with RSS directional. Line numbers are approximate anchors — the implementer confirms exact positions at edit time.
