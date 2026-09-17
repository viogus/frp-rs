# Throughput Baseline + Optimization — Design

**Date:** 2026-07-11
**Status:** Approved (brainstorming), pending implementation plan
**Scope:** Sub-project 1 of a 4-axis performance program (throughput → latency → memory → CPU). This spec covers **throughput only**. Latency, memory, and CPU each get their own spec/plan/implementation cycle later.

## Problem

"Optimize program performance" is too broad for one spec. Decomposed into four independent axes; this document is the first: **data-plane throughput** (bytes/sec through the proxy bridge).

Optimizing throughput without a repeatable baseline is guesswork and risks silent regressions. The codebase already has component-level criterion benches (`frp-core/benches/crypto_bridge.rs`) and a load/churn stress harness (`scripts/frp-stress/`, gated `STRESS_TEST=1`), but **no comparable end-to-end throughput number per bridge configuration**. The existing `scenarios/throughput.rs` reports a single aggregate MB/s with a 1 MB/s pass/fail floor, mixes concurrency into one number, and covers only one configuration.

## Goals

1. A reproducible throughput baseline matrix across bridge configurations, committed as a regression anchor.
2. A prioritized set of throughput optimizations, each independently verified against that baseline.

Non-goal: latency, memory footprint, CPU efficiency (separate sub-projects). Non-goal: changing the wire protocol.

## Architecture — Two Phases

### Phase 1: Baseline (no production code changes)

Extend `scripts/frp-stress/src/scenarios/throughput.rs` and add a driver script:

- **Configuration matrix**: `plain`, `encrypt`, `compress`, `encrypt+compress`, `TLS`, `mux`. Each configuration run separately, each reports its own MB/s.
- **Single-stream mode**: `--streams 1` yields a stable single-connection number (current harness mixes concurrency, adding noise). Multi-stream retained for aggregate throughput.
- **Structured output**: export `scripts/frp-stress/baselines/throughput-<host>.json` — payload size, configuration, MB/s, process CPU%. Committed to the repo as the regression anchor.
- **Driver**: `bash scripts/throughput-baseline.sh` runs the full matrix one-shot (serial, to avoid cross-run interference).

Deliverable: a "current throughput table", one number per configuration. This is the yardstick every Phase 2 change is validated against.

### Phase 2: Optimizations (baseline-anchored, one at a time)

Each item: change → re-run baseline matrix → keep only if the targeted configuration improves and no other configuration regresses.

## Data Flow (measurement loop)

```
frp-stress client → frpc (local port) → [bridge] → frps → echo backend
        │ write payload for N seconds                          │ echo
        └───────────────── count sent+received bytes ──────────┘
```

Per configuration: start `frps`+`frpc` with the matching transport/enc/compress flags → run for a fixed duration → collect `total_bytes` + process CPU → compute MB/s. Matrix runs serially.

## Optimization Targets (Phase 2, ordered by benefit/risk)

### T1 — Remove per-chunk `flush().await` in `bridge_plain` (low risk, medium benefit)

`frp-core/src/bridge.rs`: the `user_to_work` and `work_to_user` loops call `work_w.flush().await` after every `write_all`. On a raw `TcpStream` this is a no-op, but through TLS (`tokio-rustls`), mux (`yamux`), or the compression bridge, per-chunk flush forces small-packet flushing and caps throughput.

Change: flush only when the read side would block (next `read` is pending) or rely on `write_all` plus a flush on shutdown, batching writes between reads.

Verify: TLS / mux / compress configurations improve; plain unchanged. Add a unit test asserting flush behavior and that `pre_read` semantics are unchanged.

### T2 — Buffer size experiment (low risk, data-driven)

`buffer_pool::BUFFER_SIZE` is fixed at 64KB. Add a 256KB variant to the matrix; keep the change only if high-BDP throughput improves measurably. No blind change — data decides.

### T3 — Confirm plain path uses `copy_bidirectional` (audit, possibly zero change)

CLAUDE.md states the plain path uses `tokio::io::copy_bidirectional`, but `bridge_plain` is a hand-written loop (needed for compression). Audit `assign_work_to_proxy` in `frp-server/src/control/bridge.rs`: when `!compress && !encrypt`, does it bypass the hand-written loop for `copy_bidirectional` (better internal buffering)? If not, add the fast path.

### T4 — Linux `splice(2)` zero-copy (high benefit, high complexity, feature-gated) — DEFERRED

For pure relay (no enc/compress), forward via `splice` in kernel space, avoiding user-space copies. Largest potential win for bulk transfer.

Cost: Linux-only, `unsafe` FD operations, feature gate, fallback path. Evaluated only at the end of Phase 2, and only if the baseline shows user-space copy is a real bottleneck. **YAGNI: not done by default.**

## Verification + Regression Gate

- **Per-item verification**: `throughput-baseline.sh` runs the full matrix and diffs against the committed baseline JSON. Regression threshold: any configuration dropping >5% fails the change.
- **Process discipline** (CLAUDE.md, mandatory): each T-item done in a git worktree, implemented by a subagent, and — since bridge changes touch the transport/protocol plane — followed by `bash scripts/compat-test.sh` to confirm Go↔Rust compatibility.
- **CI**: the baseline script runs manually / weekly (like the `STRESS_TEST=1` stress job), not as a blocking PR gate (too slow, environment-sensitive). Baseline JSON is committed for manual comparison.
- **Tests**: bridge changes get unit tests (flush behavior, `pre_read` invariance).

## Out of Scope / Follow-up

- Latency, memory, CPU axes — separate specs.
- Protocol/wire changes — none.
- T4 splice — deferred pending baseline evidence.
