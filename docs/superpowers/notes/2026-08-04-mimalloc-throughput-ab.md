# mimalloc Throughput A/B Audit

**Date:** 2026-08-04
**Context:** Evaluate whether `--features mimalloc` should move from opt-in to default for `frps`/`frpc`. The feature's own doc comment claims "~10-20% throughput gain for network workloads" (mimalloc's generic benchmark figure).
**Decision:** **Keep mimalloc opt-in.** No consistent, reproducible ≥5% throughput gain was measured; the claim does not transfer to frp's data plane.
**Head commit:** `263bbf8`

## 1. Method

- 6 bridge configurations: `plain`, `encrypt`, `compress`, `encrypt_compress`, `mux`, `tls`
- 10 s per run, 1 stream, loopback (127.0.0.1), frp-stress `throughput` scenario
- 3 rounds per allocator, median comparison; system allocator vs mimalloc 0.1.52
- Binary identity verified by size after each build (system `frps` 8,920,816 B / mimalloc 9,006,464 B, +85 KB; `frpc` 7,510,896 / 7,613,040, +102 KB)
- Load window kept < 3 (load-average drift invalidated three earlier attempts; see §4)

## 2. Results (MB/s, median of 3 rounds)

| config | system (rounds) | mimalloc (rounds) | delta% |
|---|---|---|---|
| compress | 244.2 [244,244,244] | 244.1 [247,244,244] | **-0.0%** |
| encrypt_compress | 239.9 [239,241,240] | 241.5 [241,242,242] | +0.7% |
| encrypt | 123.5 [125,124,120] | 126.7 [125,127,127] | +2.5% |
| tls | 142.2 [148,129,142] | 131.8 [164,132,127] | -7.3% |
| mux | 92.4 [92,92,110] | 83.1 [83,90,80] | -10.0% |
| plain | 133.9 [134,134,122] | 152.8 [163,153,138] | +14.1% |

### Reading the numbers

- **Direction is mixed**: `plain` +14.1% vs `mux` -10.0% contradict each other on the same bridge path — mimalloc cannot simultaneously speed one bridge config up 14% and slow another down 10%. These are load-drift artifacts, not allocator signal (round-level values show the drift: system `plain` round 3 = 122 anomalously low; mimalloc `plain` 163→138 monotonically decreasing as load climbed).
- **Most trustworthy rows are the zero-variance ones**: `compress` system rounds were identical (244/244/244) → **-0.0%**; `encrypt_compress` → +0.7%. The real allocator effect sits inside ±3%.
- An earlier stable-window run showed `plain` +8.3% (96.4 → 104.3 MB/s) which did not reproduce; the ±7-14% swings across runs bracket pure environment noise.

### Cost side

- Binary size: `frps` +85 KB, `frpc` +102 KB (+1.0-1.4%), all shipped tiers.
- Long-lived process behavior (RSS, fragmentation) unmeasured — mimalloc typically holds more arena than glibc/malloc.

## 3. Why the claim doesn't transfer

frp's data plane was already optimized to be allocation-free on the hot path (see prior audit `2026-07-12-memory-control-plane-audit.md` and CLAUDE.md):

- bridge `compress_chunk`/`decompress_chunk` reuse buffers (zero alloc per iteration)
- `CipherWriter` shared scratch reuse; AEAD read scratch pre-allocated across frames
- KCP packet pool + FEC fast-path; `buffer_pool::PoolGuard` for bridge buffers
- plain path uses `tokio::io::copy_bidirectional` internal buffers

Global allocator traffic is limited to the control plane (login, proxy register, connection setup) — a small fraction of runtime work. mimalloc's generic malloc/free benchmark gain does not apply.

## 4. Test tooling fixes this audit surfaced (commit `263bbf8`)

Three measurement defects had to be fixed in `frp-stress` before any number was trustworthy:

1. **Infinite hang**: `write_all`/`read_exact` had no timeout — a stalled bridge blocked forever (observed twice). Fixed: per-op `clamp(2,5)s` timeout; run bails rc=1.
2. **0-byte fake success**: all-streams-failed runs returned rc=0 with 0-byte JSON rows. Fixed: `bail!` when 0 bytes moved and streams failed, even under `--no-floor`.
3. **JSON append pollution**: `--json-out` appends; stale rows from prior runs stacked into one file. Fixed: `--json-truncate` flag (append stays default for back-compat); JSON row written before bail so "measured 0" ≠ "config never ran".

Operational findings during the audit:

- `yamux::frame::io` logs at INFO **per frame** — a 10 MB+ stderr flood that throttles the bridge when stderr is a pipe. Run baselines with `RUST_LOG=warn`.
- Background (nohup/pipe) runs of the baseline hung; foreground execution was reliable.
- The `throughput-baseline.sh` probe-port readiness check (18001 connectable = proxy registered) is load-bearing: without it, `plain` produced 0-byte rows when the client beat proxy registration.

## 5. Baseline staleness concern (open)

`scripts/frp-stress/baselines/throughput-Mac.jsonl` records `plain` 1114.7 MB/s (and `mux` 640.9, `tls` 712.0). The same machine at load < 2 reproduces only ~140 MB/s `plain` today, while a direct (no-frp) echo benchmark hits 869 MB/s — the machine's network stack is not the limit. The historical file is suspected to come from a different machine or measurement method (or pre-dates a data-path change) and **should be re-baselined before it is trusted as a gate reference**. Re-baselining requires a dedicated idle machine; do not block on it.
