# Memory Efficiency — Design

**Date:** 2026-07-12
**Status:** Approved (brainstorming), pending implementation plan
**Scope:** Sub-project 4 of 4 in a performance program (throughput → CPU → latency → **memory**). Throughput, CPU, and latency sub-projects are complete. This spec covers **memory only** — the final axis.

## Problem

The proxy has reproducible throughput, CPU, and latency baselines, but **no memory measurement at all**, and a per-connection footprint that scales poorly with fan-out:

1. **Pinned bridge buffers.** Each active proxy connection runs a bridge loop that holds **two 64 KiB buffers** (`PoolGuard::acquire()` per direction, `frp-core/src/bridge.rs`) for the connection's entire lifetime — whether the connection is saturated or idle. At 1000 concurrent connections that is ~128 MiB resident in bridge buffers alone, independent of traffic. The buffer *pool* caps retained (idle) buffers at `MAX_POOLED_BUFFERS = 32`, but **active** buffers are uncapped — one live pair per connection.

2. **Per-chunk allocation churn on the encrypted path.** `frp-core/src/cipher_stream.rs` allocates per write chunk (`buf.to_vec()` copy + `Vec::with_capacity(16 + len)` output, plus `tmp = vec![0u8; needed]` scratch). Under active encrypted traffic this is sustained allocator pressure — a churn cost, distinct from resident footprint.

3. **Control-plane per-connection structures.** Each control connection spawns a handler task with its own `work_pool`, `pending_requests`, and channel buffers, plus `AppState` map entries (`run_id_to_ctl_tx`, `sk_index`, etc.). Per-connection overhead that may or may not be material — unmeasured today.

There is no in-repo way to see which of these dominates, or to prove a change helped without regressing another axis.

## Goals

1. A reproducible memory baseline — **exact live-bytes and total-allocated** (in-process counting allocator) plus **process RSS** (external sanity check) — under two workloads: many idle/low-traffic connections held open, and rapid connect-disconnect churn. Committed as a regression anchor.
2. Reduce per-connection **resident footprint** and per-connection **allocation churn**, ordered by measured benefit ("both, data-ordered").
3. Every change wire-identical to Go frp and non-regressing on throughput/latency/CPU.

Non-goal: throughput, CPU, latency (complete). **Non-goal: wire-protocol changes.** **Non-goal: new dependencies** — the counting allocator is std `GlobalAlloc` + `AtomicUsize`; RSS is `ps`.

## Architecture — Two Phases

### Phase 1: Memory harness (measurement, feature-gated — no production behavior change)

**Counting global allocator (Approach A).** Add a `CountingAlloc<System>` wrapper in `frp-core` that tracks `live_bytes` (current) and `total_alloc` (cumulative) via two `AtomicUsize`, installed as `#[global_allocator]` **only** when a new `mem-profile` feature is enabled on the crate. With the feature **off** (all shipped builds — full/tiny/micro), no allocator wrapper is compiled and the binary is byte-identical to today: **zero production overhead**.

- **Counter exposure:** when `mem-profile` is on, frps/frpc spawn a lightweight task that emits one line per second to stderr: `MEMPROFILE live=<bytes> total=<bytes> allocs=<count>`. The driver reads the log and takes the sample nearest each phase boundary. (A one-shot dump also fires at shutdown.) This avoids signal-portability concerns and is deterministic to parse.
- **No new dependency:** `std::alloc::{GlobalAlloc, System, Layout}` + `core::sync::atomic`.

**Harness scenario upgrade.** Rework `scripts/frp-stress/src/scenarios/memory.rs` (currently opens N idle connections, holds, logs "no leaks" without measuring) into two measured modes:
- **idle-hold mode**: ramp to N proxy connections, each having sent one small message to force the bridge to allocate its buffer pair, then hold them idle for the hold window. Targets resident footprint (the pinned-buffer cost).
- **churn mode**: repeatedly open → send one message → close, at a fixed concurrency, for the duration. Targets allocation rate (setup/teardown churn, cipher_stream per-chunk allocs when encryption is on).

**Driver:** `bash scripts/memory-baseline.sh [connections]` builds frps/frpc with `--features mem-profile`, runs the matrix serially (idle-hold and churn, each plain vs encrypt), samples the `MEMPROFILE` counters at phase boundaries plus `ps -o rss= -p <frps_pid>` / `<frpc_pid>`, and appends one JSON record per config to `scripts/frp-stress/baselines/memory-<host>.jsonl`:
`{label, mode, connections, encrypt, live_bytes_idle, live_bytes_peak, total_alloc, rss_kb_frps, rss_kb_frpc, live_per_conn}`. Committed as the regression anchor.

Deliverable: a current memory table — the yardstick every Phase 2 change is validated against, and the data that decides which levers are worth pulling.

### Phase 2: Optimizations (baseline-anchored, one at a time, data-ordered)

Each item: change → re-run the memory matrix → keep only if the targeted metric improves and neither the other memory metric nor throughput/latency regresses. **Which items ship, and in what order, is decided by the Phase-1 numbers** — the largest measured contributor goes first. Below are the candidate levers, ordered by expected benefit/risk; the spec deliberately does not pre-commit the buffer strategy (see M1).

## Optimization Targets (Phase 2, candidates — data selects and orders)

### M1 — Per-connection bridge buffers (highest expected benefit; touches throughput) — DATA DECIDES

The 2 × 64 KiB pinned per connection is the fattest resident-footprint lever. Two candidate strategies, **chosen by Phase-1 data plus a throughput no-regress check** (not pre-committed):

- **(a) Shrink the default buffer** (e.g. 64 KiB → 32 KiB, matching Go frp's `io.Copy` 32 KiB). Uniform ~50% cut to per-conn footprint, one constant (`BUFFER_SIZE`). Risk: fewer bytes per write may reduce bulk batching — **must pass the throughput no-regress gate (>5% MB/s drop rejects)**; revert if it regresses.
- **(b) Adaptive idle-release**: keep 64 KiB for active connections, but return the buffer to the pool when a connection is idle (no data for an interval) and re-acquire on wakeup. Maximum win for idle-heavy fan-out, zero throughput impact on active connections. Risk: idle-detection complexity, pool-thrash under medium traffic.

Decision rule: if idle-hold footprint dominates and the traffic pattern is fan-out-idle, prefer (b); if the cut is wanted uniformly and throughput holds at the smaller size, (a) is simpler. If neither clears its gate, ship neither and document why.

### M2 — cipher_stream per-chunk allocation churn (moderate benefit, encrypt path only)

On the encrypted bridge, reuse a scratch buffer held in the cipher-stream state instead of `buf.to_vec()` + fresh `Vec::with_capacity` + `vec![0u8; needed]` per write chunk. Cuts allocation *rate* under active encrypted traffic (a churn win, not a resident-footprint win). Must stay wire-identical (same AES-128-CFB + Snappy framing — the throughput/CPU compat guards already cover this) and not regress encrypt throughput.

### M3 — Control-plane per-connection structures (audit; act only if material)

Use the counting allocator to attribute per-connection live-bytes to control-plane structures (handler-task stacks, `work_pool`/`pending_requests` Vec capacities, channel buffer sizes, `AppState` map entries). Act only where the data shows a material, low-risk win (e.g. an over-reserved `Vec::with_capacity`, an oversized channel bound). Default expectation: audit + note; change only what measurement justifies. YAGNI gate.

### M4 — Buffer-pool retention review (audit, likely small)

Confirm `MAX_POOLED_BUFFERS = 32` is a reasonable idle-retention cap given the measured active-buffer high-water mark, and that release/acquire length/capacity handling (the throughput axis's zero-fill-skip) is memory-correct. Expected: no change or a one-line tuning note. YAGNI gate.

## Data Flow (measurement loop)

```
frp-stress client → frpc (local port) → [bridge] → frps → echo backend
   │ idle-hold: N conns, 1 msg each, then hold           │ echo
   │ churn:     open→1 msg→close, repeat                  │
   └── driver samples: MEMPROFILE live/total (both procs) ┘
                     + ps RSS (both procs), per phase
```

## Verification + Regression Gate

- **Per-item verification:** `memory-baseline.sh` runs the matrix and compares against the committed baseline. The **memory metrics are the primary gate** — `live_per_conn` and `total_alloc` (allocator, precise) lead; RSS is the real-world cross-check (noisier — OS/allocator slack, does not shrink promptly, so gate on the allocator counters and treat RSS as directional). **Secondary no-regression gates:** `throughput-baseline.sh` (any config >5% MB/s drop rejects) and `latency-baseline.sh` (p99 no regression) — memory changes must not undo the prior three axes.
- **Process discipline (CLAUDE.md, mandatory):** each M-item in a git worktree, implemented by a subagent, task-reviewed. Any change to bridge/cipher/buffer paths is followed by `bash scripts/compat-test.sh --verbose` — verify the `RESULTS:` line shows 0 failures (a partial run is not a pass).
- **No new dependencies (CLAUDE.md):** counting allocator is std `GlobalAlloc` + `AtomicUsize`; RSS is `ps`; percentile/aggregate math is arithmetic on a `Vec`. `frp-stress` already has `serde_json`, `clap`, `tokio`.
- **Production untouched by measurement:** the `mem-profile` feature is off in all shipped builds (full/tiny/micro), so the counting allocator adds zero overhead and the binaries are byte-identical to today. CI's existing feature-matrix build proves the feature-off path; the memory script runs manually (like throughput/latency), not as a blocking PR gate.
- **Wire-identical:** no message/framing/encryption change. `compat-test.sh` stays green.

## Out of Scope / Follow-up

- Throughput, CPU, latency axes — complete (separate specs).
- Protocol/wire changes — none.
- Switching the global allocator in production (jemalloc/mimalloc) — a dependency and a policy change; out of scope. The counting allocator wraps `System` and is measurement-only.
- Raising `MAX_POOLED_BUFFERS` or the `pool_count` default — pool retention is an audit (M4), not a default change, unless data plus Go-compat clearly justify it.
