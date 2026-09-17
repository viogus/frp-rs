# Throughput Baseline + Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible per-configuration throughput baseline for the frp-rs data plane, then apply and verify bridge throughput optimizations against it.

**Architecture:** Phase 1 extends the existing `frp-stress` harness with an echo backend, single-stream mode, and JSON output, plus a driver script that sweeps a bridge-configuration matrix and records a committed baseline. Phase 2 applies bridge optimizations (per-chunk flush removal, plain fast-path, buffer-size experiment) one at a time, each re-running the matrix and requiring no >5% regression on any configuration.

**Tech Stack:** Rust (tokio, clap, serde_json), bash, existing frps/frpc binaries.

## Global Constraints

- **Worktree per task** — create a git worktree via `superpowers:using-git-worktrees` before modifying files; never edit on `main` directly. (CLAUDE.md)
- **Subagent per task** — dispatch each task to a subagent; review between tasks. (CLAUDE.md)
- **Compat gate** — after ANY change to `frp-core/src/bridge.rs` or `frp-server/src/control/bridge.rs`, run `bash scripts/compat-test.sh --verbose` and confirm the RESULTS line shows 0 failures. (CLAUDE.md)
- **No new dependencies** without documented justification. `serde_json` is already a workspace dependency; reuse it. (CLAUDE.md Dependency Policy)
- **Regression threshold** — a Phase 2 change is rejected if any matrix configuration drops >5% MB/s vs the committed baseline. (spec §Verification)
- **No wire-protocol changes.** (spec §Goals)
- Commit messages end with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

## File Structure

**Phase 1 (harness, no production code):**
- Modify `scripts/frp-stress/src/main.rs` — add CLI flags `--streams`, `--json-out`, `--label`, `--no-floor`; register `echo` scenario.
- Create `scripts/frp-stress/src/scenarios/echo.rs` — TCP echo backend (self-contained, no external tool).
- Modify `scripts/frp-stress/src/scenarios/mod.rs` — declare `pub mod echo;`.
- Modify `scripts/frp-stress/src/scenarios/throughput.rs` — single-stream mode, structured JSON emission, optional floor.
- Create `scripts/throughput-baseline.sh` — matrix driver.
- Create `scripts/frp-stress/baselines/README.md` — explains baseline JSON is host-specific.

**Phase 2 (production bridge code):**
- Modify `frp-core/src/bridge.rs` — remove per-chunk flush (T1); buffer-size env override (T2).
- Modify `frp-core/src/bridge.rs` tests — flush-count unit test.
- Modify `frp-server/src/control/bridge.rs` — plain fast-path `copy_bidirectional` (T3).

---

## Task 1: Echo backend scenario + CLI flags

**Files:**
- Modify: `scripts/frp-stress/src/main.rs:11-37` (Cli struct), `:48-57` (dispatch)
- Create: `scripts/frp-stress/src/scenarios/echo.rs`
- Modify: `scripts/frp-stress/src/scenarios/mod.rs:1-6`

**Interfaces:**
- Produces: `scenarios::echo::run(cli: &Cli) -> anyhow::Result<()>` — binds `127.0.0.1:{cli.port}`, echoes every byte back until killed.
- Produces: `Cli` gains `streams: usize`, `json_out: Option<String>`, `label: String`, `no_floor: bool`.

- [ ] **Step 1: Add CLI fields to `main.rs`**

Add to the `Cli` struct (after the `port` field, line 36):

```rust
    /// Single-stream count override for throughput (defaults to --concurrency)
    #[arg(long, default_value = "0")]
    streams: usize,

    /// Write structured JSON result to this path (append mode)
    #[arg(long)]
    json_out: Option<String>,

    /// Configuration label recorded in JSON output (e.g. "plain", "tls")
    #[arg(long, default_value = "unlabeled")]
    label: String,

    /// Disable the throughput pass/fail floor (baseline measurement mode)
    #[arg(long, default_value = "false")]
    no_floor: bool,
```

- [ ] **Step 2: Register echo in dispatch + mod**

In `main.rs`, add to the `match cli.scenario.as_str()` block (after the `mixed` arm, line 54):

```rust
        "echo" => scenarios::echo::run(&cli).await?,
```

In `scenarios/mod.rs`, add after line 6:

```rust
pub mod echo;
```

- [ ] **Step 3: Write the echo scenario**

Create `scripts/frp-stress/src/scenarios/echo.rs`:

```rust
use crate::Cli;
use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// TCP echo backend: binds 127.0.0.1:{port}, echoes bytes until process killed.
/// Used as the throughput-baseline backend so the bridge relays real traffic.
pub async fn run(cli: &Cli) -> Result<()> {
    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("echo backend bind {} failed", addr))?;
    tracing::info!("echo backend listening on {}", addr);

    loop {
        let (mut sock, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            tracing::debug!("echo conn {} closed", peer);
        });
    }
}
```

- [ ] **Step 4: Build and smoke-test the echo backend**

Run:
```bash
cd scripts/frp-stress && cargo build --release 2>&1 | tail -3
./target/release/frp-stress --scenario echo --port 19999 &
ECHO_PID=$!
sleep 1
printf 'ping' | timeout 2 nc 127.0.0.1 19999 | head -c 4
kill $ECHO_PID
```
Expected: prints `ping` (echoed back). If `nc` is unavailable, substitute `python3 -c "import socket;s=socket.create_connection(('127.0.0.1',19999));s.sendall(b'ping');print(s.recv(4))"` — expected `b'ping'`.

- [ ] **Step 5: Commit**

```bash
git add scripts/frp-stress/src/main.rs scripts/frp-stress/src/scenarios/echo.rs scripts/frp-stress/src/scenarios/mod.rs
git commit -m "$(cat <<'EOF'
feat(stress): add echo backend scenario and baseline CLI flags

Adds a self-contained TCP echo backend so throughput baselines relay
real traffic, plus --streams/--json-out/--label/--no-floor flags for
per-config baseline runs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Throughput scenario — single-stream mode + JSON output

**Files:**
- Modify: `scripts/frp-stress/src/scenarios/throughput.rs` (full rewrite of `run`)

**Interfaces:**
- Consumes: `Cli.streams`, `Cli.json_out`, `Cli.label`, `Cli.no_floor` (from Task 1).
- Produces: appends one JSON object per run to `Cli.json_out` when set: `{"label": String, "streams": usize, "duration_s": u64, "total_bytes": u64, "mbps": f64}`.

- [ ] **Step 1: Rewrite `throughput.rs` run**

Replace the entire body of `scripts/frp-stress/src/scenarios/throughput.rs` with:

```rust
use crate::Cli;
use anyhow::{Context, Result};
use std::io::Write;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PAYLOAD_SIZE: usize = 1024 * 64; // 64 KiB chunks

pub async fn run(cli: &Cli) -> Result<()> {
    let target = format!(
        "{}:{}",
        cli.frps_addr.split(':').next().unwrap_or("127.0.0.1"),
        cli.port
    );
    // streams == 0 means "use --concurrency" (back-compat); >0 overrides.
    let streams = if cli.streams > 0 { cli.streams } else { cli.concurrency };
    let payload = vec![0xABu8; PAYLOAD_SIZE];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cli.duration);
    let mut total_bytes: u64 = 0;

    tracing::info!(
        label = %cli.label,
        streams = %streams,
        "Throughput [{}]: {}s, {} streams",
        cli.label,
        cli.duration,
        streams
    );

    let mut handles = Vec::with_capacity(streams);
    for i in 0..streams {
        let target = target.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(&target)
                .await
                .with_context(|| format!("stream {} connect failed", i))?;
            let mut bytes = 0u64;
            let mut buf = vec![0u8; PAYLOAD_SIZE];
            while tokio::time::Instant::now() < deadline {
                stream.write_all(&payload).await?;
                stream.read_exact(&mut buf).await?;
                bytes += (PAYLOAD_SIZE * 2) as u64; // sent + received
            }
            Ok::<u64, anyhow::Error>(bytes)
        }));
    }

    for h in handles {
        match h.await {
            Ok(Ok(bytes)) => total_bytes += bytes,
            Ok(Err(e)) => tracing::error!(error = ?e, "Throughput stream failed: {:#}", e),
            Err(e) => tracing::error!(error = %e, "Throughput task panicked: {}", e),
        }
    }

    let mbps = (total_bytes as f64 / (1024.0 * 1024.0)) / cli.duration as f64;
    tracing::info!(
        label = %cli.label,
        total_bytes = %total_bytes,
        mbps = %mbps,
        "Throughput [{}]: {} total bytes, {:.2} MB/s",
        cli.label,
        total_bytes,
        mbps
    );

    if let Some(path) = &cli.json_out {
        let record = serde_json::json!({
            "label": cli.label,
            "streams": streams,
            "duration_s": cli.duration,
            "total_bytes": total_bytes,
            "mbps": mbps,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open json_out {}", path))?;
        writeln!(f, "{}", record).context("write json_out")?;
    }

    if !cli.no_floor && mbps < 1.0 {
        anyhow::bail!("Throughput too low: {:.2} MB/s (minimum 1.0 MB/s)", mbps);
    }
    Ok(())
}
```

- [ ] **Step 2: Ensure `serde_json` is a dependency of frp-stress**

Run:
```bash
grep -q 'serde_json' scripts/frp-stress/Cargo.toml && echo "present" || echo "MISSING"
```
Expected: `present`. If `MISSING`, add under `[dependencies]` in `scripts/frp-stress/Cargo.toml`:
```toml
serde_json = "1"
```

- [ ] **Step 3: Build**

Run:
```bash
cd scripts/frp-stress && cargo build --release 2>&1 | tail -3
```
Expected: `Finished` with no errors.

- [ ] **Step 4: Verify JSON emission (against echo backend directly, no bridge)**

Run:
```bash
cd scripts/frp-stress
./target/release/frp-stress --scenario echo --port 19998 & E=$!
sleep 1
rm -f /tmp/tp.jsonl
./target/release/frp-stress --scenario throughput --port 19998 --frps-addr 127.0.0.1:0 \
    --streams 1 --duration 2 --label smoke --no-floor --json-out /tmp/tp.jsonl
kill $E
cat /tmp/tp.jsonl
```
Expected: one JSON line containing `"label":"smoke"`, `"streams":1`, and a positive `"mbps"`.

- [ ] **Step 5: Commit**

```bash
git add scripts/frp-stress/src/scenarios/throughput.rs scripts/frp-stress/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(stress): throughput single-stream mode and JSON output

Adds --streams override, per-run JSON records (label/streams/mbps), and
--no-floor for baseline measurement without the 1 MB/s pass/fail gate.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Matrix driver script + baseline

**Files:**
- Create: `scripts/throughput-baseline.sh`
- Create: `scripts/frp-stress/baselines/README.md`

**Interfaces:**
- Consumes: the `echo` and `throughput` scenarios and CLI flags from Tasks 1–2.
- Produces: `scripts/frp-stress/baselines/throughput-<hostname>.jsonl` — one JSON line per matrix configuration.

- [ ] **Step 1: Write the driver**

Create `scripts/throughput-baseline.sh`:

```bash
#!/usr/bin/env bash
# =============================================================================
# frp-rs throughput baseline: sweep bridge-config matrix, record MB/s per config.
#   plain | encrypt | compress | encrypt+compress | tls | mux
# Usage: bash scripts/throughput-baseline.sh [duration_s] [streams]
# Output: scripts/frp-stress/baselines/throughput-<hostname>.jsonl
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

DURATION="${1:-10}"
STREAMS="${2:-1}"
FRPS_PORT=18000
REMOTE_PORT=18001
ECHO_PORT=18002
TOKEN="baseline-token"
OUT="scripts/frp-stress/baselines/throughput-$(hostname -s).jsonl"
CERT=/tmp/baseline-cert.pem
KEY=/tmp/baseline-key.pem

echo "=== Building release binaries ==="
cargo build --release --bin frps --bin frpc 2>&1 | tail -2
(cd scripts/frp-stress && cargo build --release 2>&1 | tail -2)

FRPS=./target/release/frps
FRPC=./target/release/frpc
STRESS=./scripts/frp-stress/target/release/frp-stress

# Self-signed cert for the TLS row (frps needs a cert to accept TLS).
if [[ ! -f "$CERT" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
fi

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

rm -f "$OUT"
mkdir -p "$(dirname "$OUT")"

# run_config <label> <frpc-transport-toml> <proxy-extra-toml> <frps-extra-toml>
run_config() {
  local label="$1" transport="$2" proxy_extra="$3" frps_extra="$4"
  echo "=== config: $label ==="
  cat > /tmp/bl-frps.toml <<EOF
bind_port = $FRPS_PORT
$frps_extra
[auth]
method = "token"
token = "$TOKEN"
[log]
level = "warn"
EOF
  cat > /tmp/bl-frpc.toml <<EOF
server_addr = "127.0.0.1"
server_port = $FRPS_PORT
token = "$TOKEN"
login_fail_exit = true
$transport
[[proxies]]
name = "bl-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = $ECHO_PORT
remote_port = $REMOTE_PORT
$proxy_extra
EOF

  "$STRESS" --scenario echo --port "$ECHO_PORT" & PIDS+=($!)
  sleep 1
  "$FRPS" -c /tmp/bl-frps.toml & PIDS+=($!)
  sleep 1
  "$FRPC" -c /tmp/bl-frpc.toml & PIDS+=($!)
  sleep 2

  "$STRESS" --scenario throughput --port "$REMOTE_PORT" \
    --frps-addr "127.0.0.1:$FRPS_PORT" --streams "$STREAMS" \
    --duration "$DURATION" --label "$label" --no-floor --json-out "$OUT" || true

  # Tear down this config's processes before the next row.
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 1
}

run_config "plain"       'tcp_mux = false'                                 ""                                    ""
run_config "encrypt"     'tcp_mux = false'                                 'use_encryption = true'               ""
run_config "compress"    'tcp_mux = false'                                 'use_compression = true'              ""
run_config "encrypt_compress" 'tcp_mux = false'                            'use_encryption = true'$'\n''use_compression = true' ""
run_config "mux"         'tcp_mux = true'                                  ""                                    ""
run_config "tls"         'tcp_mux = false'$'\n''[transport.tls]'$'\n''enable = true'$'\n''disable_custom_first_byte = false' "" 'transport_tls_cert_file = "'"$CERT"'"'$'\n''transport_tls_key_file = "'"$KEY"'"'

echo "=== baseline written: $OUT ==="
cat "$OUT"
```

- [ ] **Step 2: Make executable and validate TLS config keys against the codebase**

Run:
```bash
chmod +x scripts/throughput-baseline.sh
rg -n "transport_tls_cert_file|tls\]|disable_custom_first_byte|use_encryption|use_compression" frp-core/src/config.rs | head
```
Expected: confirms the TLS cert key name and the `[transport.tls]`/`use_encryption`/`use_compression` field names the driver emits. If any key name differs, update the driver's heredoc to match the actual config field names before running.

- [ ] **Step 3: Run the baseline (short duration for validation)**

Run:
```bash
bash scripts/throughput-baseline.sh 5 1
```
Expected: prints `=== config: plain ===` … through `=== config: tls ===`, then a baseline file with 6 JSON lines (labels plain, encrypt, compress, encrypt_compress, mux, tls), each with positive `mbps`. If a row shows `mbps: 0`, that config's frpc failed to connect — inspect the config keys from Step 2.

- [ ] **Step 4: Write the baselines README**

Create `scripts/frp-stress/baselines/README.md`:

```markdown
# Throughput baselines

`throughput-<hostname>.jsonl` records MB/s per bridge configuration,
produced by `scripts/throughput-baseline.sh`. Numbers are **host-specific**
(CPU, kernel, NIC) — compare a change only against a baseline captured on
the SAME host. Regenerate the baseline before starting a Phase 2 change,
then re-run after and diff: any config dropping >5% MB/s rejects the change.
```

- [ ] **Step 5: Commit (script + README + your host's baseline)**

```bash
git add scripts/throughput-baseline.sh scripts/frp-stress/baselines/
git commit -m "$(cat <<'EOF'
feat(stress): throughput baseline matrix driver

Sweeps plain/encrypt/compress/encrypt+compress/mux/tls bridge configs,
records per-config MB/s to a host-specific baseline JSONL used as the
Phase 2 regression anchor.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: T1 — Remove per-chunk flush in `bridge_plain`

**Files:**
- Modify: `frp-core/src/bridge.rs` — `user_to_work` loop (~line 269-273) and `work_to_user` loop (~line 319-322)
- Test: `frp-core/src/bridge.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: existing `bridge_plain(user_r, user_w, work_r, work_w, use_compression, pre_read, metrics)` signature — unchanged.
- Produces: identical bytes delivered; flush occurs at most once per drained burst instead of once per chunk.

- [ ] **Step 1: Write the failing test (flush count)**

Add to the tests module in `frp-core/src/bridge.rs`:

```rust
#[tokio::test]
async fn bridge_plain_batches_flushes_on_full_reads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWrite, AsyncRead, ReadBuf};

    // Writer that counts flush() calls and discards data.
    struct CountingWriter(Arc<AtomicUsize>);
    impl AsyncWrite for CountingWriter {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    // Reader that yields two full-capacity chunks then EOF.
    struct TwoFullChunks(usize);
    impl AsyncRead for TwoFullChunks {
        fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
            if self.0 == 0 { return Poll::Ready(Ok(())); } // EOF
            self.0 -= 1;
            let n = buf.remaining();
            buf.initialize_unfilled_to(n);
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    let flushes = Arc::new(AtomicUsize::new(0));
    let user_r = TwoFullChunks(2);
    let work_w = CountingWriter(flushes.clone());
    // work_r EOFs immediately; user_w sinks.
    let work_r = TwoFullChunks(0);
    let user_w = CountingWriter(Arc::new(AtomicUsize::new(0)));

    bridge_plain(user_r, user_w, work_r, work_w, false, Vec::new(), None).await;

    // Two full-capacity reads => no per-chunk flush; exactly one final flush.
    assert_eq!(flushes.load(Ordering::SeqCst), 1, "expected batched flush, got per-chunk");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cargo test -p frp-core bridge_plain_batches_flushes_on_full_reads 2>&1 | tail -15
```
Expected: FAIL — asserts `2 == 1` (current code flushes once per chunk).

- [ ] **Step 3: Implement batched flush in `user_to_work`**

In `frp-core/src/bridge.rs`, capture the buffer capacity once before the loop and change the write/flush block. Replace the `user_to_work` write section:

```rust
            if work_w.write_all(processed.as_ref()).await.is_err() {
                tracing::warn!(len = processed.len(), "bridge_plain: work_w write_all failed");
                break;
            }
            if work_w.flush().await.is_err() {
                tracing::warn!("bridge_plain: work_w flush failed");
                break;
            }
```

with (add `let cap = buf.as_mut_slice().len();` immediately after `let mut buf = PoolGuard::acquire();` in this branch):

```rust
            if work_w.write_all(processed.as_ref()).await.is_err() {
                tracing::warn!(len = processed.len(), "bridge_plain: work_w write_all failed");
                break;
            }
            // Flush only when the read drained the source (short read) — a
            // full-capacity read means more is likely queued, so batch it.
            if n < cap && work_w.flush().await.is_err() {
                tracing::warn!("bridge_plain: work_w flush failed");
                break;
            }
```

Then add a final flush before the `if !had_pre_read` shutdown block:

```rust
        let _ = work_w.flush().await;
        if !had_pre_read {
```

- [ ] **Step 4: Implement the symmetric change in `work_to_user`**

Add `let cap = buf.as_mut_slice().len();` after `let mut buf = PoolGuard::acquire();` in the `work_to_user` branch, and replace:

```rust
                if user_w.flush().await.is_err() {
                    tracing::warn!("bridge_plain: user_w flush failed");
                    break;
                }
```

with:

```rust
                if n < cap && user_w.flush().await.is_err() {
                    tracing::warn!("bridge_plain: user_w flush failed");
                    break;
                }
```

Then add a final flush after the loop (before the branch's closing), mirroring `user_to_work`:

```rust
        let _ = user_w.flush().await;
```

- [ ] **Step 5: Run the test to verify it passes**

Run:
```bash
cargo test -p frp-core bridge_plain 2>&1 | tail -15
```
Expected: PASS. Also run the full bridge test module: `cargo test -p frp-core bridge 2>&1 | tail -20` — all existing bridge tests still pass.

- [ ] **Step 6: Compat gate**

Run:
```bash
bash scripts/compat-test.sh --verbose 2>&1 | tail -5
```
Expected: RESULTS line with 0 failures. (Verify the RESULTS line explicitly appears — a partial run can exit 0 without it.)

- [ ] **Step 7: Re-run baseline and check no regression**

Run:
```bash
bash scripts/throughput-baseline.sh 10 1
```
Expected: `tls`, `mux`, `compress`, `encrypt_compress` MB/s improve or hold; `plain` within ±5%. Compare against the committed baseline from Task 3.

- [ ] **Step 8: Commit**

```bash
git add frp-core/src/bridge.rs
git commit -m "$(cat <<'EOF'
perf(bridge): batch flushes in bridge_plain instead of per-chunk

Flush the work/user writer only after a short read (source drained) plus
once at stream end, instead of after every chunk. No-op on raw TCP;
improves TLS/mux/compression throughput where per-chunk flush forced
small-packet writes. Bytes delivered are unchanged.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: T3 — Plain fast-path via `copy_bidirectional`

**Files:**
- Modify: `frp-server/src/control/bridge.rs:452-462` (the non-XTCP `else` branch)

**Interfaces:**
- Consumes: existing `req` fields — `use_compression` (`comp_key`), `pre_read` (`bridge_pre_read`), `response_headers`, `proxy_type`, `user_conn`, `work_conn`.
- Produces: identical relay behavior; uses `copy_bidirectional` when no compression, no pre-read, and no response-header injection are needed.

- [ ] **Step 1: Add the fast-path branch**

In `frp-server/src/control/bridge.rs`, the non-XTCP plain branch currently starts at line 452 (`} else {` under `if proxy_type == "xtcp"`). Replace the plain-bridge block:

```rust
            } else {
                // Plain bridge with optional compression.
                let (u_r, u_w) = req.user_conn.into_split();
                let (w_r, w_w) = work_conn.into_split();
                if !req.response_headers.is_empty() && req.proxy_type.starts_with("http") {
                    let injector = ResponseHeaderInjector::new(w_r, req.response_headers);
                    frp_core::bridge::bridge_plain(u_r, u_w, injector, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                } else {
                    frp_core::bridge::bridge_plain(u_r, u_w, w_r, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                }
            }
```

with:

```rust
            } else if !comp_key
                && bridge_pre_read.is_empty()
                && req.response_headers.is_empty()
            {
                // Fast path: pure plain relay with no compression, no VHost
                // pre-read, and no header injection. copy_bidirectional uses
                // an internal buffer and avoids bridge_plain's per-chunk
                // compress/flush indirection. Bytes relayed are identical.
                let mut user_conn = req.user_conn;
                match tokio::io::copy_bidirectional(&mut user_conn, &mut work_conn).await {
                    Ok((a, b)) => {
                        metrics.bytes_in.fetch_add(a, Ordering::Relaxed);
                        metrics.bytes_out.fetch_add(b, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!(error = %e, "plain fast-path bridge closed: {}", e);
                    }
                }
            } else {
                // Slow path: compression, VHost pre-read, or header injection.
                let (u_r, u_w) = req.user_conn.into_split();
                let (w_r, w_w) = work_conn.into_split();
                if !req.response_headers.is_empty() && req.proxy_type.starts_with("http") {
                    let injector = ResponseHeaderInjector::new(w_r, req.response_headers);
                    frp_core::bridge::bridge_plain(u_r, u_w, injector, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                } else {
                    frp_core::bridge::bridge_plain(u_r, u_w, w_r, w_w, comp_key, bridge_pre_read, Some(metrics.clone())).await;
                }
            }
```

- [ ] **Step 2: Build**

Run:
```bash
cargo build -p frp-server 2>&1 | tail -5
```
Expected: `Finished`, no errors. (`work_conn` must be `mut` — it already is in this scope via the XTCP arm above; if the compiler complains, add `mut` to the binding.)

- [ ] **Step 3: Compat gate (correctness across transports)**

Run:
```bash
bash scripts/compat-test.sh --verbose 2>&1 | tail -5
```
Expected: RESULTS line, 0 failures. This exercises plain TCP g2r/r2g, HTTP (pre_read path → slow path), and compression (→ slow path), confirming both branches route correctly.

- [ ] **Step 4: Re-run baseline and check no regression**

Run:
```bash
bash scripts/throughput-baseline.sh 10 1
```
Expected: `plain` and `mux` configs improve or hold; `compress`/`encrypt*` unchanged (they take other paths). No config drops >5%.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/control/bridge.rs
git commit -m "$(cat <<'EOF'
perf(server): copy_bidirectional fast-path for pure plain relay

When a TCP proxy has no compression, no VHost pre-read, and no response
header injection, relay via copy_bidirectional instead of the hand-written
bridge_plain loop. Compression/pre-read/header paths keep bridge_plain.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: T2 — Buffer size experiment

**Files:**
- Modify: `frp-core/src/buffer_pool.rs:14-15` (BUFFER_SIZE + env override)

**Interfaces:**
- Consumes: nothing new.
- Produces: `BUFFER_SIZE` becomes a runtime value read once from `FRP_BRIDGE_BUF_KB` (default 64), so a baseline sweep can compare buffer sizes without recompiling.

This task is measurement-driven: it adds the knob, sweeps 64KB vs 256KB, and KEEPS the larger default only if the baseline shows a clear win. Otherwise revert the default and delete the knob.

- [ ] **Step 1: Add the env-overridable buffer size**

In `frp-core/src/buffer_pool.rs`, replace:

```rust
/// Default size for pooled buffers (64KB — matches bridge.rs read buffer).
pub const BUFFER_SIZE: usize = 65536;
```

with:

```rust
use std::sync::LazyLock;

/// Pooled buffer size in bytes. Defaults to 64KB; override for experiments
/// via FRP_BRIDGE_BUF_KB (e.g. 256). Read once at process start.
pub static BUFFER_SIZE: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("FRP_BRIDGE_BUF_KB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|kb| *kb >= 4 && *kb <= 1024)
        .map(|kb| kb * 1024)
        .unwrap_or(65536)
});
```

- [ ] **Step 2: Fix all `BUFFER_SIZE` usages (const → static deref)**

Run:
```bash
rg -n "BUFFER_SIZE" frp-core/src/
```
Expected: shows each use site. For each usage of `BUFFER_SIZE` as a value (e.g. `vec![0u8; BUFFER_SIZE]`, `Vec::with_capacity(BUFFER_SIZE)`), change it to `*BUFFER_SIZE`. Then build:
```bash
cargo build -p frp-core 2>&1 | tail -5
```
Expected: `Finished`, no errors. Fix any remaining `BUFFER_SIZE` that needs a `*` deref.

- [ ] **Step 3: Run existing buffer_pool tests**

Run:
```bash
cargo test -p frp-core buffer_pool 2>&1 | tail -15
```
Expected: PASS (capacity assertions now compare against `*BUFFER_SIZE`).

- [ ] **Step 4: Sweep 64KB vs 256KB**

Run:
```bash
FRP_BRIDGE_BUF_KB=64  bash scripts/throughput-baseline.sh 10 1
mv scripts/frp-stress/baselines/throughput-$(hostname -s).jsonl /tmp/buf64.jsonl
FRP_BRIDGE_BUF_KB=256 bash scripts/throughput-baseline.sh 10 1
mv scripts/frp-stress/baselines/throughput-$(hostname -s).jsonl /tmp/buf256.jsonl
echo "--- 64KB ---"; cat /tmp/buf64.jsonl
echo "--- 256KB ---"; cat /tmp/buf256.jsonl
```
Note: `scripts/throughput-baseline.sh` must pass `FRP_BRIDGE_BUF_KB` to the frps/frpc it launches — since it launches them in the same shell, the exported env propagates. Confirm by checking both binaries inherit the variable (they do, being child processes of the script).

- [ ] **Step 5: Decide and finalize**

- If 256KB improves aggregate MB/s by >5% with no memory concern for this axis: change the `unwrap_or(65536)` default to `unwrap_or(262144)` and note it.
- If not: keep `unwrap_or(65536)`. Either way, the `FRP_BRIDGE_BUF_KB` knob stays (useful for the later memory axis).

- [ ] **Step 6: Compat gate + commit**

```bash
bash scripts/compat-test.sh --verbose 2>&1 | tail -5
```
Expected: RESULTS, 0 failures.

```bash
git add frp-core/src/buffer_pool.rs
git commit -m "$(cat <<'EOF'
perf(core): make bridge buffer size env-overridable (FRP_BRIDGE_BUF_KB)

Adds a runtime knob for the pooled buffer size (default 64KB) to support
throughput/memory experiments without recompiling. <decision from Step 5>.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Deferred: T4 — Linux `splice(2)` zero-copy

Not implemented in this plan. Revisit only if the Task 3–5 baselines show user-space copy is the dominant cost on the `plain`/`mux` rows. If pursued, it becomes its own spec: Linux-only, `unsafe` FD handling, feature-gated, with a non-splice fallback — and must pass the full compat matrix.

---

## Self-Review

**Spec coverage:**
- Phase 1 baseline matrix (plain/encrypt/compress/enc+compress/TLS/mux) → Tasks 1–3 ✓
- Single-stream mode → Task 2 ✓
- Structured baseline JSON committed → Tasks 2–3 ✓
- Driver script → Task 3 ✓
- T1 flush removal → Task 4 ✓
- T2 buffer experiment → Task 6 ✓
- T3 plain fast-path audit + impl → Task 5 ✓
- T4 splice deferred → Deferred section ✓
- Regression gate >5%, worktree/subagent/compat discipline → Global Constraints + per-task compat steps ✓

**Placeholder scan:** No TBD/TODO. Task 6 Step 5/commit intentionally leaves a data-driven decision — the branch conditions and both outcomes are spelled out, not deferred.

**Type consistency:** `Cli.streams/json_out/label/no_floor` defined in Task 1, consumed in Task 2. `scenarios::echo::run` defined Task 1, used by driver Task 3. JSON record shape fixed in Task 2, consumed by human/diff in later tasks. `comp_key`/`bridge_pre_read`/`response_headers` names match the current `frp-server/src/control/bridge.rs`.
