# Latency Efficiency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a latency harness (steady-state RTT + connection-setup percentiles), then eliminate the systemic missing-`TCP_NODELAY` defect across all TCP streams (Go-frp parity), and characterize connection-setup latency.

**Architecture:** From `docs/superpowers/specs/2026-07-12-latency-efficiency-design.md`. Phase 1 adds a `latency` scenario to the standalone `frp-stress` workspace plus a driver script. Phase 2: L1 sets `TCP_NODELAY` at every raw-`TcpStream` accept/connect site via one helper; L2 measures cold vs warm setup latency and documents guidance; L3 audits bridge flush behavior. No wire-protocol change — `TCP_NODELAY` is a socket option.

**Tech Stack:** Rust, tokio (`TcpStream::set_nodelay`), the `frp-stress` standalone harness (clap, serde_json), percentile math over a sorted `Vec` (no new deps).

## Global Constraints

- **No wire-protocol change.** `TCP_NODELAY` is a socket option, invisible on the wire. Message formats, framing, and encryption are untouched. Go frp already defaults nodelay on (`net.TCPConn`), so this is a parity fix, not a divergence.
- **No new dependencies** (CLAUDE.md). `set_nodelay` is on tokio's `TcpStream`; percentiles are arithmetic on a sorted `Vec`. `frp-stress` already depends on `serde_json`, `clap`, `tokio`.
- **`frp-stress` is a standalone workspace** under `scripts/frp-stress/` — NOT a member of the root workspace. Build it with `(cd scripts/frp-stress && cargo build --release)`. Do not add it to root `Cargo.toml` members (that broke Docker + CI before).
- **A failed socket option must not kill a connection.** `set_nodelay` errors are logged at debug and ignored.
- **Latency gate (primary):** the `latency-baseline.sh` percentiles (p50/p95/p99). **Throughput gate (secondary):** `throughput-baseline.sh` — any config dropping >5% MB/s rejects the change.
- **Compat (mandatory after L1):** `bash scripts/compat-test.sh --verbose` must print a RESULTS line with 0 failures. A partial run (no RESULTS line, e.g. stale frps/frpc jamming ports) is NOT a pass — verify the RESULTS line explicitly.
- **Process (CLAUDE.md):** each task in a git worktree, implemented by a subagent, task-reviewed.

---

### Task 1: Latency harness — scenario + CLI + driver (Phase 1)

Add a `latency` scenario to `frp-stress` with two modes and a driver script. No production code changes. Mirrors the existing `throughput` scenario structure.

**Files:**
- Create: `scripts/frp-stress/src/scenarios/latency.rs`
- Modify: `scripts/frp-stress/src/scenarios/mod.rs` (add `pub mod latency;`)
- Modify: `scripts/frp-stress/src/main.rs` (add `--mode`, `--samples`, `--msg-bytes` CLI args + `"latency"` dispatch arm)
- Create: `scripts/latency-baseline.sh`
- Test: inline `#[cfg(test)]` in `latency.rs` for the percentile helper

**Interfaces:**
- Consumes: `crate::Cli` (existing fields `port`, `frps_addr`, `duration`, `label`, `json_out`; new fields `mode`, `samples`, `msg_bytes`), the existing `echo` backend scenario.
- Produces: `scenarios::latency::run(&Cli) -> anyhow::Result<()>`; JSON records `{label, mode, samples, msg_bytes, p50_us, p95_us, p99_us, max_us, mean_us}` appended to `--json-out`.

- [ ] **Step 1: Add CLI args to `main.rs`**

In the `Cli` struct in `scripts/frp-stress/src/main.rs`, after the `no_floor` field, add:

```rust
    /// Latency mode: "steady" (persistent conn RTT) or "setup" (fresh-conn connect->first-byte)
    #[arg(long, default_value = "steady")]
    mode: String,

    /// Number of latency samples to collect
    #[arg(long, default_value = "2000")]
    samples: usize,

    /// Message size in bytes for latency probes
    #[arg(long, default_value = "64")]
    msg_bytes: usize,
```

Then in the `match cli.scenario.as_str()` block, after the `"echo"` arm, add:

```rust
        "latency" => scenarios::latency::run(&cli).await?,
```

- [ ] **Step 2: Register the module**

In `scripts/frp-stress/src/scenarios/mod.rs`, add to the top with the other `pub mod` lines:

```rust
pub mod latency;
```

(Do NOT add `latency` to the `run_all` array — it needs a running frps/frpc + echo backend, like `throughput`/`echo`, so it is driver-invoked only.)

- [ ] **Step 3: Write the latency scenario**

Create `scripts/frp-stress/src/scenarios/latency.rs`:

```rust
use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Percentiles (p50/p95/p99/max/mean) in microseconds from nanosecond samples.
/// Returns (p50, p95, p99, max, mean).
fn percentiles_us(mut samples_ns: Vec<u128>) -> (f64, f64, f64, f64, f64) {
    assert!(!samples_ns.is_empty(), "no latency samples");
    samples_ns.sort_unstable();
    let n = samples_ns.len();
    let pick = |p: f64| -> f64 {
        // nearest-rank; clamp index to the last element
        let idx = ((p * n as f64).ceil() as usize).saturating_sub(1).min(n - 1);
        samples_ns[idx] as f64 / 1000.0
    };
    let mean = samples_ns.iter().sum::<u128>() as f64 / n as f64 / 1000.0;
    let max = *samples_ns.last().unwrap() as f64 / 1000.0;
    (pick(0.50), pick(0.95), pick(0.99), max, mean)
}

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    let msg = vec![0xABu8; cli.msg_bytes];
    let mut buf = vec![0u8; cli.msg_bytes];
    let mut samples_ns: Vec<u128> = Vec::with_capacity(cli.samples);

    tracing::info!(
        label = %cli.label, mode = %cli.mode, samples = cli.samples, msg_bytes = cli.msg_bytes,
        "Latency [{}] mode={}: {} samples, {}B", cli.label, cli.mode, cli.samples, cli.msg_bytes
    );

    match cli.mode.as_str() {
        "steady" => {
            // One persistent connection; serialized ping-pong RTTs.
            let mut stream = TcpStream::connect(&target)
                .await
                .with_context(|| format!("steady connect to {target} failed"))?;
            // Warm-up: one untimed round-trip to establish the work-conn bridge.
            stream.write_all(&msg).await?;
            stream.read_exact(&mut buf).await?;
            for _ in 0..cli.samples {
                let t0 = std::time::Instant::now();
                stream.write_all(&msg).await?;
                stream.read_exact(&mut buf).await?;
                samples_ns.push(t0.elapsed().as_nanos());
            }
        }
        "setup" => {
            // Fresh connection each sample; measure connect->first-byte-echoed.
            for _ in 0..cli.samples {
                let t0 = std::time::Instant::now();
                let mut stream = TcpStream::connect(&target)
                    .await
                    .with_context(|| format!("setup connect to {target} failed"))?;
                stream.write_all(&msg).await?;
                stream.read_exact(&mut buf).await?;
                samples_ns.push(t0.elapsed().as_nanos());
                drop(stream);
            }
        }
        other => anyhow::bail!("unknown latency mode: {other} (expected steady|setup)"),
    }

    let (p50, p95, p99, max, mean) = percentiles_us(samples_ns);
    tracing::info!(
        label = %cli.label, mode = %cli.mode,
        p50_us = p50, p95_us = p95, p99_us = p99, max_us = max, mean_us = mean,
        "Latency [{}] mode={}: p50={:.1}us p95={:.1}us p99={:.1}us max={:.1}us mean={:.1}us",
        cli.label, cli.mode, p50, p95, p99, max, mean
    );

    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "mode": cli.mode,
            "samples": cli.samples,
            "msg_bytes": cli.msg_bytes,
            "p50_us": p50, "p95_us": p95, "p99_us": p99, "max_us": max, "mean_us": mean,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true).append(true).open(path)
            .with_context(|| format!("open json_out {path}"))?;
        writeln!(f, "{record}").context("write json_out")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::percentiles_us;

    #[test]
    fn percentiles_basic() {
        // 1..=100 microseconds (as ns). p50~50us, p99~99us, max=100us.
        let samples: Vec<u128> = (1..=100).map(|v| v as u128 * 1000).collect();
        let (p50, p95, p99, max, mean) = percentiles_us(samples);
        assert!((p50 - 50.0).abs() < 1.5, "p50={p50}");
        assert!((p95 - 95.0).abs() < 1.5, "p95={p95}");
        assert!((p99 - 99.0).abs() < 1.5, "p99={p99}");
        assert!((max - 100.0).abs() < 0.001, "max={max}");
        assert!((mean - 50.5).abs() < 0.001, "mean={mean}");
    }

    #[test]
    fn percentiles_single() {
        let (p50, p95, p99, max, mean) = percentiles_us(vec![7000]);
        assert_eq!((p50, p95, p99, max, mean), (7.0, 7.0, 7.0, 7.0, 7.0));
    }
}
```

- [ ] **Step 4: Build the harness and run the percentile unit tests**

Run: `(cd scripts/frp-stress && cargo test)`
Expected: PASS (`percentiles_basic`, `percentiles_single`), harness compiles.

- [ ] **Step 5: Write the driver script**

Create `scripts/latency-baseline.sh` (mirrors `scripts/throughput-baseline.sh` config emission; runs steady + setup modes, nodelay off/on distinguished by label, cold vs warm pool):

```bash
#!/usr/bin/env bash
# =============================================================================
# frp-rs latency baseline: steady-state RTT + connection-setup percentiles.
# Usage: bash scripts/latency-baseline.sh [samples]
# Output: scripts/frp-stress/baselines/latency-<hostname>.jsonl
#
# Numbers are host-specific. Regenerate before an L-item change and diff after;
# any config whose p99 regresses rejects the change. The nodelay win shows up
# as a large steady-mode p99/max drop once L1 lands.
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

SAMPLES="${1:-2000}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="latency-token"
OUT="scripts/frp-stress/baselines/latency-$(hostname -s).jsonl"

echo "=== Building release binaries ==="
cargo build --release -p frps -p frpc 2>&1 | tail -2
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

FRPS=./target/release/frps
FRPC=./target/release/frpc
STRESS=./scripts/frp-stress/target/release/frp-stress

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

# run_case <label> <mode> <pool_count>
run_case() {
  local label="$1" mode="$2" pool="$3"
  echo "=== case: $label ($mode, pool=$pool) ==="
  {
    echo "bind_addr = \"127.0.0.1\""
    echo "bind_port = $FRPS_PORT"
    echo "[auth]"; echo "method = \"token\""; echo "token = \"$TOKEN\""
    echo "[log]"; echo "level = \"warn\""
  } > /tmp/lat-frps.toml
  {
    echo "server_addr = \"127.0.0.1\""
    echo "server_port = $FRPS_PORT"
    echo "token = \"$TOKEN\""
    echo "login_fail_exit = true"
    echo "pool_count = $pool"
    echo "[[proxies]]"
    echo "name = \"lat-tcp\""
    echo "type = \"tcp\""
    echo "local_ip = \"127.0.0.1\""
    echo "local_port = $ECHO_PORT"
    echo "remote_port = $REMOTE_PORT"
  } > /tmp/lat-frpc.toml

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/lat-frps.toml & PIDS+=($!)
  sleep 1
  "$FRPC" -c /tmp/lat-frpc.toml & PIDS+=($!)
  sleep 2

  "$STRESS" --scenario latency --mode "$mode" --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --token "$TOKEN" \
    --samples "$SAMPLES" --msg-bytes 64 --label "$label" --json-out "$OUT" || true

  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

#         label              mode     pool
run_case "steady"           steady   1
run_case "setup_cold"       setup    0
run_case "setup_warm"       setup    4

echo "=== latency baseline written: $OUT ==="
cat "$OUT"
```

- [ ] **Step 6: Run the driver to produce the pre-L1 baseline**

Run: `bash scripts/latency-baseline.sh`
Expected: writes `scripts/frp-stress/baselines/latency-<host>.jsonl` with 3 records (steady, setup_cold, setup_warm). The `steady` p99/max will look high (Nagle active) — this is the anchor L1 must beat. Record the numbers.

- [ ] **Step 7: Commit**

```bash
git add scripts/frp-stress/src/scenarios/latency.rs scripts/frp-stress/src/scenarios/mod.rs scripts/frp-stress/src/main.rs scripts/latency-baseline.sh scripts/frp-stress/baselines/
git commit -m "test(stress): latency harness — steady-state RTT + setup percentiles

New latency scenario (steady ping-pong RTT + fresh-conn connect->first-byte
modes), --mode/--samples/--msg-bytes CLI args, latency-baseline.sh driver,
committed pre-optimization baseline. Standalone frp-stress workspace."
```

---

### Task 2: TCP_NODELAY on all TCP streams (L1) — the headline fix

Add one helper and call it at every raw-`TcpStream` accept/connect site. Go-frp parity; wire-invisible.

**Files:**
- Modify: `frp-core/src/transport.rs` (add `pub fn set_nodelay`; call it in `connect_direct` before returning, and on the `connect_via_proxy` result)
- Modify: `frp-server/src/service.rs` (accept loops that yield raw control/work/visitor conns: around lines 500, 967, 1293)
- Modify: `frp-server/src/control/proxy_ops.rs` (user-facing proxy listener accept, around line 471)
- Modify: `frp-server/src/vhost.rs` (accept sites around lines 277, 298)
- Modify: `frp-server/src/tcpmux.rs` (accept around line 115)
- Modify: `frp-client/src/proxy.rs` (local-service dial, around line 108) and `frp-client/src/service.rs` (local dials around lines 1134, 1244)

**Interfaces:**
- Produces: `pub fn frp_core::transport::set_nodelay(stream: &tokio::net::TcpStream)` — sets `TCP_NODELAY`, logs at debug on error, never panics/returns error.
- Consumes: called at each accept/connect site listed above.

- [ ] **Step 1: Record the pre-change latency baseline**

Run: `bash scripts/latency-baseline.sh` (if Task 1's committed baseline is current for this host, reuse it and skip). Note the `steady` p50/p95/p99/max — the numbers L1 must improve.

- [ ] **Step 2: Add the helper in `transport.rs`**

Add to `frp-core/src/transport.rs` (near the other free functions, e.g. after `connect_direct`):

```rust
/// Enable TCP_NODELAY (disable Nagle) on a stream, matching Go frp's default
/// (`net.TCPConn` sets NoDelay(true)). A failed socket option must not kill the
/// connection, so errors are logged at debug and ignored. Wire-invisible.
pub fn set_nodelay(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "set_nodelay failed (continuing with Nagle on)");
    }
}
```

- [ ] **Step 3: Apply in the client dial funnel (`connect_direct`)**

In `frp-core/src/transport.rs` `connect_direct`, immediately before `Ok(stream)` (after the keepalive block, around line 1408), add:

```rust
    crate::transport::set_nodelay(&stream);
```

This covers all client control/work dials routed through `dial_server`. Also apply to the raw stream returned by `connect_via_proxy` (find its `Ok(...)`/return of the tunneled `TcpStream` and call `set_nodelay` on it before returning).

- [ ] **Step 4: Apply at server accept sites**

For each accepted raw `TcpStream` in `frp-server/src/service.rs` (the control/work/visitor accept loops around lines 500, 967, 1293), immediately after the successful `accept()` yields `(stream, peer)`, call `frp_core::transport::set_nodelay(&stream)`. Do the same in:
- `frp-server/src/control/proxy_ops.rs` (the user-facing proxy listener accept, ~line 471) — this is the latency-critical remote-user connection.
- `frp-server/src/vhost.rs` (accepts ~lines 277, 298).
- `frp-server/src/tcpmux.rs` (accept ~line 115).

For streams that are subsequently TLS/mux-wrapped, set nodelay on the underlying `TcpStream` before wrapping. Skip WebSocket/QUIC/KCP accept paths (not raw TCP; KCP already sets nodelay).

- [ ] **Step 5: Apply at client local-service dials**

In `frp-client/src/proxy.rs` (~line 108) and `frp-client/src/service.rs` (~lines 1134, 1244), after the `TcpStream::connect(local)` succeeds, call `frp_core::transport::set_nodelay(&stream)` on the connected local-backend stream. (Health-check probe dials in `health.rs` are not on the data path — skip.)

- [ ] **Step 6: Build and grep for any missed raw-TCP site**

Run: `cargo build --workspace`
Then: `grep -rn "\.accept()\.await\|TcpStream::connect\|socket\.connect" frp-core/src frp-server/src frp-client/src | grep -v test`
Expected: clean build; every data-path raw-`TcpStream` accept/connect either calls `set_nodelay` or is deliberately excluded (health probe, WS/QUIC/KCP, dashboard admin listener). Note the exclusions in the task report.

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --workspace`
Expected: PASS. No behavior change beyond the socket option.

- [ ] **Step 8: Re-run the latency baseline and confirm the win**

Run: `bash scripts/latency-baseline.sh`
Expected: `steady` p99 and max drop substantially vs the Task-1 anchor (Nagle removed — the large improvement appears on small-message serialized RTT). `setup` modes improve modestly. If `steady` p99 does NOT improve, nodelay is not reaching the data path — diagnose (likely a missed accept/connect site or a wrapping order issue) before committing.

- [ ] **Step 9: Confirm no throughput regression**

Run: `bash scripts/throughput-baseline.sh`
Expected: no config drops >5% MB/s vs the committed throughput baseline. `nodelay` can marginally reduce bulk batching; confirm it is negligible at 64 KiB writes. (This host is latency/thermal-variable; if plain/tls/mux look low but encrypt/compress are stable, treat the copy-path dips as thermal noise as documented in the throughput baseline, not a regression.)

- [ ] **Step 10: Run the cross-compat suite**

Run: `bash scripts/compat-test.sh --verbose`
Expected: `RESULTS:` line with 0 failures. `TCP_NODELAY` is wire-invisible, so Go↔Rust compatibility is unchanged. Verify the RESULTS line explicitly; if the run stops early with no RESULTS line, kill stale `frps`/`frpc`, free the ports, and re-run.

- [ ] **Step 11: Refresh the committed latency baseline + commit**

```bash
git add frp-core/src/transport.rs frp-server/src/service.rs frp-server/src/control/proxy_ops.rs frp-server/src/vhost.rs frp-server/src/tcpmux.rs frp-client/src/proxy.rs frp-client/src/service.rs scripts/frp-stress/baselines/
git commit -m "perf(net): set TCP_NODELAY on all TCP streams (Go-frp parity)

Nagle was active on every plain-TCP stream (control/work/user/vhost/tcpmux
+ client dials), adding up to ~40ms/RTT on small messages. Go net.TCPConn
defaults NoDelay(true); match it via a shared set_nodelay helper at every
accept/connect site. Wire-invisible socket option; compat 57/0. Steady-state
RTT p99 <before>->? Refresh latency baseline."
```

---

### Task 3: Connection-setup latency — measure + document (L2)

Data-driven. Compare cold (`pool_count=0`) vs warm setup latency from the harness and document the tradeoff. Default expectation: audit + README guidance, no behavior change (keep the Go-compatible `pool_count=0` default).

**Files:**
- Modify: `README.md` (tuning guidance for `pool_count` / setup latency)
- Reference: `scripts/frp-stress/baselines/latency-<host>.jsonl` (`setup_cold` vs `setup_warm` records from Task 1/2)

**Interfaces:** none (measurement + docs).

- [ ] **Step 1: Extract the cold-vs-warm setup delta**

From the committed `latency-<host>.jsonl` (post-L1), compare the `setup_cold` (`pool_count=0`) and `setup_warm` (`pool_count=4`) p50/p95/p99. Record the delta in the task report. If a fresh run is needed: `bash scripts/latency-baseline.sh`.

- [ ] **Step 2: Decide (data gate)**

- If warm shows a large, consistent setup-latency reduction (the expected outcome — cold pays a `ReqWorkConn`→`StartWorkConn` round-trip before first byte): proceed to document it (Step 3). Do NOT change the `pool_count=0` default — it matches Go frp and non-zero has a standing-resource cost.
- If the delta is negligible: record that finding and make no doc change beyond a one-line note.
- Only if a clearly Go-compatible code-level win emerges (not merely raising the default) would a code change be warranted — in that case report DONE_WITH_CONCERNS with specifics rather than implementing unprompted.

- [ ] **Step 3: Add README tuning guidance**

In `README.md`, near the client/proxy configuration section, add a short "Latency tuning" note: explain that `pool_count` pre-warms work connections, that `pool_count=0` (the default, matching Go frp) makes each new user connection pay a control round-trip before first byte, and that latency-sensitive deployments should set `pool_count` to a small positive value (cite the measured `setup_cold` vs `setup_warm` p50/p99 from the baseline). Keep it factual and concise.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: pool_count latency tuning guidance

Cold pool (pool_count=0, Go-frp default) pays a ReqWorkConn round-trip
before first byte; measured setup p50/p99 cold vs warm from the latency
baseline. Recommend small positive pool_count for latency-sensitive use.
No default change (Go parity retained)."
```

---

### Task 4: Bridge flush latency audit (L3)

Confirm the bridge flush behavior introduces no interactive-data stall. Audit-only; expected zero code change.

**Files:**
- Create: `docs/superpowers/notes/2026-07-12-bridge-flush-latency-audit.md`

**Interfaces:** none (audit only).

- [ ] **Step 1: Trace the flush paths**

Read `frp-core/src/bridge.rs`. Confirm: `bridge_encrypted` flushes after each write (`~line 151`, low latency); `bridge_plain` flushes when a read returns `< buffer capacity` (`~lines 278, 328`) and always flushes at loop exit (`~lines 287, 335`). Confirm the throughput sub-project's batched-flush change only skips flush on a *full-capacity* read (i.e. when more data is imminent), so a short/interactive read still flushes immediately.

- [ ] **Step 2: Confirm the fast-path (copy_bidirectional) latency**

Check `frp-server/src/control/bridge.rs`: the plain fast path uses `tokio::io::copy_bidirectional`, which flushes when the read side is pending — appropriate for interactive traffic. Confirm no path buffers interactive data awaiting a full read.

- [ ] **Step 3: Write the audit note**

Create `docs/superpowers/notes/2026-07-12-bridge-flush-latency-audit.md` recording: each flush site and its trigger condition; the conclusion that current flush behavior is latency-appropriate (short reads flush immediately; only full-capacity reads defer, correctly, since more data is imminent); and the decision — no code change. If an actual stall is found instead, report it with file:line rather than writing a "clean" note.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/notes/2026-07-12-bridge-flush-latency-audit.md
git commit -m "docs(perf): bridge flush latency audit — no stall, no change

Encrypted bridge flushes per chunk; plain bridge flushes on short reads +
loop exit; fast path uses copy_bidirectional (flushes when read pending).
Short/interactive reads flush immediately; only full-capacity reads defer
(more data imminent). Latency-appropriate; no code change."
```

---

## Self-Review

- **Spec coverage:** Phase 1 harness → Task 1; L1 → Task 2; L2 → Task 3; L3 → Task 4. Latency gate (harness percentiles) in Task 2 Steps 1/8; throughput no-regression gate in Task 2 Step 9; compat in Task 2 Step 10. All spec targets mapped.
- **Placeholders:** none — full code for the latency scenario, percentile helper + unit tests, CLI args, driver script, the `set_nodelay` helper, and per-site application with cited line numbers; exact commands and commit messages.
- **Type consistency:** `percentiles_us(Vec<u128>) -> (f64,f64,f64,f64,f64)` used consistently; `set_nodelay(&tokio::net::TcpStream)` signature identical at every call site; JSON keys (`p50_us`…`mean_us`) match between the scenario and any downstream comparison.
- **Constraint check:** no new deps (tokio `set_nodelay`, sorted-`Vec` percentiles, existing `serde_json`); `frp-stress` stays a standalone workspace (driver builds it separately); wire-invisible (compat gate confirms). Line numbers are approximate anchors — the implementer confirms exact positions at edit time.
