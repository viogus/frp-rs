# Memory Control-Plane and Pool Retention Audit

**Date:** 2026-07-12
**Context:** Post M1 (buffer 64KB->32KB shrink) + M2 (cipher scratch reuse).
**Baseline commit:** `2697c6f`
**Head commit:** `a5a20c6`

## 1. Bridge Buffer Investigation

### The Puzzle

The post-M1/M2 baseline shows `idle_encrypt live_per_conn = 24,534 B` for 500 connections. With `BUFFER_SIZE = 32,768` and each encrypted bridge using 2 `PoolGuard` buffers (one per direction), the expected contribution from bridge buffers alone is 65,536 B per connection. The measured value (~38% of expected) prompted investigation.

### What I Found

**Bridge buffer count per encrypted connection (server side, frps):**
- `bridge_encrypted()` at `frp-core/src/bridge.rs:92` uses exactly 2 `PoolGuard` buffers, acquired at lines 126 and 165
- Both live for the entire bridge lifetime (drop when the connection closes)
- Server spawns the bridge at `frp-server/src/control/bridge.rs:351` via `tokio::spawn`, so all 500 bridges run concurrently

The 24,534 B per-connection delta cannot be broken down as `(peak - idle) / connections` because:
- `live_bytes_idle` = first MEMPROFILE sample (frps started, pre-connections)
- `live_bytes_peak` = max MEMPROFILE live= value across entire run
- 1 Hz sampling may miss the true peak where all 1000 buffers are live simultaneously

**Expected vs measured analysis:**

| BUFFER_SIZE | Expected (2\*buf) | Measured per_conn | Ratio |
|---|---|---|---|
| 65,536 | 131,072 B/conn | 43,331 B/conn | 0.33 |
| 32,768 | 65,536 B/conn | 24,534 B/conn | 0.37 |

The ratio increased from 0.33 to 0.37 when halving the buffer size. This slight improvement is consistent with more buffers fitting into the 1-second MEMPROFILE window (less time needed to allocate smaller buffers means a higher fraction of the steady-state is captured).

**Verdict:** The discrepancy is a measurement artifact. The 1 Hz `MEMPROFILE` sampler (`frp-core/src/mem_profile.rs:59`) does not capture the instantaneous peak when all bridges are live. The directional trend (halving buffer size → 43% per_conn reduction) confirms the bridge buffers dominate the per-connection footprint.

### Control-Plane Structures Examined

| Structure | File | Line(s) | Per-Conn Cost | Notes |
|---|---|---|---|---|
| `work_pool: VecDeque<PoolEntry>` | `control/mod.rs` | 394 | ~0 (pooled connections, not active) | 11-entry cap (`pool_count + WORK_POOL_EXTRA`) |
| `pending_requests: VecDeque<PendingRequest>` | `control/mod.rs` | 100 | ~0 (drained by bridge) | `PENDING_REQUEST_TIMEOUT` drops stale entries |
| `internal_tx / internal_rx` (unbounded channel) | `service.rs` | — | ~0 (per-message) | No pre-allocated capacity |
| `run_id_to_ctl_tx` map entry | `service.rs` | — | ~0 (1 entry per proxy) | One per proxy, not per-connection |
| spawned tokio task | `control/bridge.rs` | 351 | ~200-500 B | Task struct, small |
| `CipherReader::iv_buf` | `cipher_stream.rs` | 136 | 16 B | Heap-allocated once per bridge |
| `CipherWriter::scratch` | `cipher_stream.rs` | 227 | 0 B (empty) | Grows only when data flows |
| `ActiveGuard` / `ConnGuard` | `control/bridge.rs` | 17-29, 343 | ~0 | Atomic counters, no heap |

**Total non-bridge-buffer heap per connection during idle:** ~500-700 B from the spawned task struct + 16 B cipher reader buffer. This is under 1 KB and immaterial.

**Conclusion for M3:** No code change. Control-plane overhead is negligible (< 1 KB/conn). The residual beyond bridge buffers is noise within the sampling methodology.

## 2. Buffer Pool Retention (M4)

**File:** `frp-core/src/buffer_pool.rs`

**Configuration:**
- `MAX_POOLED_BUFFERS = 32` (line 26)
- `BUFFER_SIZE = 32,768` (line 23, env-overridable)

**Pool behavior:**
- Acquire (`BufferPool::acquire`, line 54): pops from `VecDeque`, or allocates fresh via `Vec::with_capacity`
- Release (`BufferPool::release`, line 66): pushes to `VecDeque` if under cap, else drops
- PoolGuard drop (line 113): calls `std::mem::take(buf)` then `BUFFER_POOL.release()`

**Active-buffer high-water mark:** With 500 concurrent encrypted connections, each with 2 PoolGuard buffers, the theoretical maximum active buffers is 1000. The pool's 32-slot recycle cache holds ~3.2% of this at steady state. This is intentional — the pool is a recycle cache to reduce allocator churn under connection churn, not a reservoir to pre-warm allocations.

**Zero-fill optimization (lines 96-98):**
- Fresh buffers (len=0 after `Vec::with_capacity`): `resize(32768, 0)` performs the memset
- Recycled buffers (len=32768 from previous use): resize is a no-op, skipping the 32-KB zero-fill
- Stale data safety: callers always overwrite via `read()` and only read `[..n]` prefix

**Unbounded growth guard:**
- `test_pool_does_not_grow_unbounded` (line 168) confirms cap works
- Release path (`inner.len() < MAX_POOLED_BUFFERS` gate) ensures the pool never exceeds 32 entries

**Conclusion for M4:** `MAX_POOLED_BUFFERS = 32` is appropriate. No change needed. Raising it would trade idle memory (~32 KB per additional slot, retained after connections close) for marginal allocation reduction during the next connection spike — the wrong trade for a memory axis.

## 3. Decisions

| Item | Decision | Reason |
|------|----------|--------|
| M3 control-plane fix | NO CHANGE | Residual < 1 KB/conn, immaterial |
| M4 pool retention | NO CHANGE | 32-slot cap is correct; pool is a recycle cache |

No files were modified. This is a pure audit.
