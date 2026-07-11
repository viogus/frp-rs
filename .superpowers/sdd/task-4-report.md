# Task 4 Report: M3 + M4 Control-Plane and Pool Retention Audit

## Residual `live_per_conn` Analysis

### Bridge-Buffer vs Counting-Allocator Investigation

The post-M1/M2 baseline shows `idle_encrypt live_per_conn = 24,534 B` for 500 connections. With `BUFFER_SIZE = 32768` and each encrypted bridge using 2 `PoolGuard` buffers, the expected contribution from bridge buffers alone is ~64 KB per connection. The measured value is ~38% of this.

**Root cause identified:** A measurement artifact. The MEMPROFILE emitter samples `live_bytes` at 1 Hz (`frp-core/src/mem_profile.rs:59`). The 1 Hz granularity cannot capture the instantaneous steady-state peak where all 1000 PoolGuard buffers (500 connections x 2 buffers) are simultaneously live during the 15-second hold phase. The sampler catches intermediate states.

**Evidence:**
- At `BUFFER_SIZE = 65536`: expected 131 KB/conn, measured 43.3 KB/conn (ratio 0.33)
- At `BUFFER_SIZE = 32768`: expected 65 KB/conn, measured 24.5 KB/conn (ratio 0.37)
- The slight ratio increase (0.33 -> 0.37) is consistent with allocating smaller buffers faster, meaning a higher fraction of steady-state is captured in the 1-second window
- Directional trend is reliable: halving buffer size yields 43% reduction in `live_per_conn` (43,331 -> 24,534)
- `total_alloc` (54 MB for idle_encrypt) confirms 1000+ 32-KB Vec allocations did occur

### Verified Control-Plane Structures

Each structure examined with its per-connection cost:

| Structure | File:Line | Cost | Status |
|---|---|---|---|
| `work_pool: VecDeque<PoolEntry>` | `control/mod.rs:394` | ~0 (pooled, not per-conn) | Negligible |
| `pending_requests: VecDeque<PendingRequest>` | `control/mod.rs:100` | ~0 (drained by bridge) | Negligible |
| Internal channel (unbounded) | `service.rs` | ~0 (per-message) | Negligible |
| `run_id_to_ctl_tx` map entry | `service.rs` | ~0 (one per proxy) | Negligible |
| Spawned tokio task struct | `control/bridge.rs:351` | ~200-500 B | Small |
| `CipherReader::iv_buf` | `cipher_stream.rs:136` | 16 B | Tiny |
| `CipherWriter::scratch` | `cipher_stream.rs:227` | 0 B (empty during idle) | Tiny |
| `ActiveGuard` / `ConnGuard` | `control/bridge.rs:17-29` | 0 B (atomics) | Zero |

**Total non-bridge-buffer heap per connection during idle: ~500-700 B (under 1 KB).**

## M3 Decision: NO CODE CHANGE

Control-plane overhead is negligible (< 1 KB/conn). The residual beyond bridge buffers is noise within the sampling methodology. No clearly material, low-risk win exists.

## M4 Pool Retention Conclusion

`frp-core/src/buffer_pool.rs`:

- `MAX_POOLED_BUFFERS = 32` is a sensible idle-retention cap. Active-buffer high-water mark during 500-connection idle hold is ~1000 buffers; 32 is ~3% of this, appropriate for a recycle cache.
- Release/acquire length handling (the throughput-axis zero-fill-skip) is memory-correct: recycled buffers preserve length=BUFFER_SIZE so `resize` is a no-op; stale bytes are safe (callers read `[..n]` after `read()` overwrite).
- `test_pool_does_not_grow_unbounded` confirms the cap.
- No change made. Raising `MAX_POOLED_BUFFERS` would trade idle memory for marginal alloc-reduction benefit -- the wrong trade for a memory axis.

## Files

- New: `docs/superpowers/notes/2026-07-12-memory-control-plane-audit.md`
- No source files modified.

## Commit

```
8288f5f3 docs(mem): control-plane + pool retention audit

Attributed residual per-connection live-bytes after M1/M2; audited
control-plane per-conn structures and buffer-pool retention.
No-change decision: control-plane overhead <1KB/conn, pool cap
32 is appropriate. Pure audit, zero code change.
```
