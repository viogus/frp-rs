# Latency Efficiency — Design

**Date:** 2026-07-12
**Status:** Approved (brainstorming), pending implementation plan
**Scope:** Sub-project 3 of a 4-axis performance program (throughput → **latency** → memory → CPU). Throughput and CPU sub-projects are complete. This spec covers **latency only**. The memory axis gets its own spec/plan/implementation cycle after this.

## Problem

The proxy's data plane has a repeatable throughput baseline and a fixed CPU cliff (both resolved), but **no latency measurement at all** and one systemic latency defect: **no TCP stream in the codebase sets `TCP_NODELAY`**. `set_nodelay` is called exactly once — for KCP (`frp-core/src/kcp/session.rs:96`). Every plain-TCP connection (control, work, user-facing proxy listener, vhost, tcpmux) runs with Nagle's algorithm active.

For a reverse proxy carrying interactive / request-response traffic (SSH, RPC, HTTP keep-alive with small bodies), Nagle interacting with delayed-ACK adds up to ~40 ms per round-trip on small messages. This is also a **Go-frp parity gap**: Go's `net.TCPConn` defaults `SetNoDelay(true)`, while tokio's `TcpStream` leaves Nagle on. frp-rs is therefore both slower and behaviorally divergent from Go frp on latency-sensitive workloads.

A second, smaller lever is **connection-setup latency**. `pool_count` defaults to 0 (`frp-core/src/config.rs:727`), so the work-connection pool is empty by default. Each user connection then triggers a `ReqWorkConn` → the client dials a fresh work conn → `StartWorkConn` handshake, adding a control round-trip before the first byte reaches the user.

## Goals

1. A reproducible latency baseline (steady-state RTT percentiles + connection-setup latency), committed as a regression anchor.
2. Eliminate the `TCP_NODELAY` defect across all TCP streams (Go-frp parity), verified against that baseline.
3. Characterize connection-setup latency and act only where data justifies it.

Non-goal: throughput, CPU, memory (separate sub-projects). **Non-goal: wire-protocol changes** — `TCP_NODELAY` is a socket option, invisible on the wire; no message format changes.

## Architecture — Two Phases

### Phase 1: Latency harness (no production code changes)

Add `scripts/frp-stress/src/scenarios/latency.rs` with two measurement modes and a driver script. `frp-stress` is a standalone workspace under `scripts/` (kept out of the shipped release lock) — the same harness used for throughput.

- **steady-state RTT mode**: open one persistent TCP connection through the proxy to an echo backend; send N small fixed-size messages (default 64 bytes) strictly serialized (send → await echo → repeat); record per-round-trip nanoseconds; report p50/p95/p99/max and mean. This is the mode Nagle dominates.
- **setup latency mode**: repeat M times — open a *fresh* TCP connection to the proxy's remote port, send one small message, measure connect→first-byte-echoed nanoseconds, close; report p50/p95/p99/max. This is the mode the cold work-conn pool dominates.
- **Structured output**: append one JSON record per config to `scripts/frp-stress/baselines/latency-<host>.jsonl` — `{label, mode, samples, msg_bytes, p50_us, p95_us, p99_us, max_us, mean_us}`. Committed as the regression anchor.
- **Driver**: `bash scripts/latency-baseline.sh [samples]` runs the matrix serially: steady-state and setup modes, each with nodelay off (current) vs on (post-L1), and setup mode with cold pool (`pool_count=0`) vs warm (`pool_count=4`). Reuses the throughput driver's config-emission approach (correct TLS/tcp_mux/proxy keys) and the `echo` backend scenario.

Deliverable: a current latency table (percentiles per config) — the yardstick every Phase 2 change is validated against.

### Phase 2: Optimizations (baseline-anchored, one at a time)

Each item: change → re-run the latency matrix → keep only if the targeted mode improves and neither the other latency mode nor throughput regresses.

## Data Flow (measurement loop)

```
frp-stress client → frpc (local port) → [bridge] → frps → echo backend
   │ send small msg, await echo, timestamp RTT              │ echo
   └──────────── record per-round-trip / connect→first-byte ┘
```

## Optimization Targets (Phase 2, ordered by benefit/risk)

### L1 — TCP_NODELAY on all TCP streams (high benefit, low risk) — the headline fix

Set `TCP_NODELAY` on every `TcpStream` the proxy uses, matching Go frp's default. Add a small helper (e.g. `fn set_tcp_nodelay(&TcpStream)` that calls `stream.set_nodelay(true)` and logs at debug on error — a failed socket option must not kill the connection) and call it at each site:

- **Server accept sites**: main control/work/visitor accept loop (`frp-server/src/service.rs`), user-facing proxy listeners (the per-proxy `TcpListener` accept), vhost listeners (`frp-server/src/vhost.rs`), tcpmux listener (`frp-server/src/tcpmux.rs`).
- **Client connect sites**: control dial, work-conn dial, local-service dial (`frp-client`), and the proxy-target `TcpStream::connect` (`frp-core/src/transport.rs:1428`).

Scope: plain `TcpStream` only. KCP already sets nodelay; QUIC/WebSocket are not raw TCP (their own framing governs latency). TLS/mux wrap a `TcpStream` — set nodelay on the underlying socket before wrapping.

Verify: steady-state RTT p99 drops sharply (Nagle removed) for small messages; setup latency improves modestly; **no throughput regression >5%** (nodelay can marginally reduce bulk batching, expected negligible at 64 KiB writes — confirm via throughput-baseline). Wire-invisible, so `compat-test.sh` stays green. Add a unit/integration check that a bridged connection has nodelay set where practically testable.

### L2 — Connection-setup latency (data-driven) — DATA DECIDES

Measure setup latency cold (`pool_count=0`) vs warm (`pool_count>0`) with the harness. The empty-pool default forces a `ReqWorkConn`→`StartWorkConn` round-trip before first byte.

Do **not** change the `pool_count=0` default blindly — it matches Go frp and a non-zero default has resource cost. Options, chosen by data: (a) if cold-vs-warm shows a large, consistent gap, document the latency/resource tradeoff and recommended `pool_count` in the README's tuning guidance; (b) only if a code-level win is clear and Go-compatible, implement it. Default expectation: **audit + documentation**, no behavior change.

Verify: setup-latency numbers recorded warm vs cold; any doc/guidance added; no regression to steady-state or throughput.

### L3 — Per-chunk flush review (audit, likely zero change) — YAGNI GATE

Audit the bridge flush behavior for latency stalls. The encrypted bridge flushes per chunk (`bridge.rs:151`, low latency); the plain bridge flushes when a read returns less than the buffer capacity (`bridge.rs:278`), which flushes trailing/partial data. Confirm no path leaves interactive data buffered waiting for a full read. Expected finding: current flush behavior is latency-appropriate (the throughput sub-project's T4 batched flush only skips flush on *full-capacity* reads, i.e. when more data is imminent). If confirmed, record the conclusion and make **zero change**.

Verify: written audit conclusion; no code change unless an actual stall is found.

## Verification + Regression Gate

- **Per-item verification**: `latency-baseline.sh` runs the matrix and compares against the committed baseline. The latency percentiles are the primary gate; `throughput-baseline.sh` is the secondary no-regression gate (any config >5% MB/s drop rejects). Because latency is noise-sensitive, use percentiles (p50/p95/p99) over means and take enough samples for stability.
- **Process discipline (CLAUDE.md, mandatory)**: each L-item in a git worktree, implemented by a subagent, task-reviewed. L1 touches connection setup across server and client, so follow with `bash scripts/compat-test.sh --verbose` (verify the RESULTS line shows 0 failures — a partial run is not a pass) to confirm Go↔Rust compatibility.
- **No new dependencies** (CLAUDE.md): `set_nodelay` is on tokio's `TcpStream`; percentile math is arithmetic on a sorted `Vec`.
- **CI**: the latency script runs manually (like throughput), not as a blocking PR gate (too environment-sensitive). Baseline JSON committed for manual comparison.

## Out of Scope / Follow-up

- Throughput, CPU, memory axes — separate specs (throughput + CPU done; memory next).
- Protocol/wire changes — none. `TCP_NODELAY` is socket-only.
- Changing the `pool_count` default — only if L2 data plus Go-compat clearly justify it; otherwise documentation.
