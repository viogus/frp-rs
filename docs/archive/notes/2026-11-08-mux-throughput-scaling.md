# tcpMux Throughput: Where the Gap Actually Is

**Date:** 2026-11-08
**Context:** The `release-perf` A/B (same day) left one unexplained row: the `mux`
throughput cell moved only +15% under `-O3` while the encrypted/compressed cells
moved +19-40%, and a single-window pairing had shown `mux` at 43% below `plain`.
That suggested a structural cost in the mux data path worth finding.
**Decision:** **No code change.** The mux penalty is real but concurrency-shaped,
it is not CPU-limited, and the one structural lever (more sessions per client) is
blocked by Go-compat login semantics. Numbers recorded here so the next round does
not re-derive them.
**Head commit:** `602910a5`

## 1. Method

- `frp-stress` `throughput` scenario: per iteration one 64 KiB write + a 64 KiB
  echoed read, i.e. strict ping-pong, over loopback (127.0.0.1); echo backend is
  `frp-stress --scenario echo`. This measures **round-trip cost per chunk**, not
  a streaming rate — every added hop shows up directly.
- frp-rs binaries: `cargo build --release` with `CARGO_PROFILE_RELEASE_STRIP=false
  CARGO_PROFILE_RELEASE_DEBUG=1` into `target/prof` (both arms identical; the
  profile only affects symbolisation).
- Reference implementation: Go frp v0.72.0 (`scripts/download-go-frp.sh`), same
  configs (token auth, one tcp proxy, ports 18900/18901, echo on 18902).
- 10-12 s per run, arms **interleaved** and order-rotated; a run's absolute rate
  on this host moves by ~1.7x between windows (see §5), so only same-window
  ratios are meaningful.
- CPU is `ps -o cputime` for the two frp processes at the end of each run.
- Unit: the harness prints "MB/s" but computes bytes / 1024 / 1024 / duration,
  i.e. **MiB/s** (`scripts/frp-stress/src/scenarios/throughput.rs:107`).

## 2. Concurrency sweep (frp-rs, one window, 10 s each)

| streams | plain MiB/s | mux MiB/s | mux/plain | plain CPU-s | mux CPU-s |
|---|---|---|---|---|---|
| 1 | 364.1 | 290.0 | 0.80 | 9.6 | 10.8 |
| 2 | 539.9 | 420.5 | 0.78 | 15.5 | 16.4 |
| 4 | 668.5 | 486.0 | 0.73 | 30.4 | 22.9 |
| 8 | 779.7 | 516.3 | 0.66 | 38.1 | 27.2 |

Reading:

- **The penalty is not a constant percentage.** It is ~20% at one stream and
  ~34% at eight, because `plain` keeps scaling with streams and `mux` does not.
- **`mux` plateaus at ~490-520 MiB/s** between 4 and 8 streams while its CPU
  spend continues to rise (22.9 s → 27.2 s per 10 s wall). It is not
  CPU-saturated: 2.3-2.7 of 8 cores. `plain` reaches 3.0-3.8 cores and 780 MiB/s.
- At low concurrency `mux` costs *more* CPU per byte than `plain` (10.8 vs 9.6 s
  for less data) — framing and copies. At high concurrency it costs *less*
  total CPU while delivering much less — it is waiting, not computing.

## 3. Against Go frp v0.72.0 (interleaved)

| run | go plain | go mux | rs plain | rs mux |
|---|---|---|---|---|
| 1 | 768.3 | 580.4 | 748.8 | 485.7 |
| 2 | 749.1 | 573.8 | 622.6 | 336.1 (noise spike) |

Dedicated mux-only rounds (10 s, order rotated), with CPU for the pair:

| round | go mux | go CPU-s | rs mux | rs CPU-s |
|---|---|---|---|---|
| 1 | 581.7 | 36.3 | 462.5 | 23.1 |
| 2 | 521.3 | 36.0 | 444.1 | 23.1 |
| 3 | 517.1 | 35.8 | 433.1 | 23.2 |

- `plain` is at parity (frp-rs within 2-4% of Go).
- `mux` is ~15% behind Go (median 521 vs 444), but frp-rs burns ~36% less CPU
  doing it (23 s vs 36 s per 10 s run). Go is pushing more bytes through the same
  single-session shape by spending more cores, not by a cheaper algorithm.
- Go's own mux penalty vs its own plain is 0.75, i.e. the same order as frp-rs's
  0.73 at 4 streams. **tcpMux costing ~25% is protocol shape, not an frp-rs
  defect.**

## 4. Per-RTT cost (steady latency, 2000 samples, p50/mean µs)

| payload | rs plain | rs mux | delta | go plain | go mux | delta |
|---|---|---|---|---|---|---|
| 1 KiB | 182.9 / 205.0 | 219.4 / 231.9 | +36.5 / +26.9 | 179.4 / 195.9 | 206.6 / 221.1 | +27.2 / +25.2 |
| 16 KiB | 239.0 / 260.0 | 263.3 / 280.0 | +24.3 / +20.0 | — | — | — |
| 64 KiB | 345.6 / 362.3 | 435.8 / 457.3 | +90.1 / +95.0 | — | — | — |

A fixed ~25-35 µs per round trip — the same magnitude Go pays — plus a
data-proportional term that is where frp-rs spends its extra. At 64 KiB the mux
adds ~90 µs to a 346 µs round trip.

## 5. Refuted experiment: bigger frames

`cfg.set_split_send_size(32 * 1024)` (`frp-core/src/mux.rs:484`) splits one 64 KiB
bridge chunk into two DATA frames. Raising it to 64 KiB (one frame per chunk)
was measured interleaved, 12 s, 4 streams:

| round | 32 KiB (baseline) | 64 KiB |
|---|---|---|
| 1 | 483.0 | 489.6 |
| 2 | 485.9 | 485.8 |
| 3 | 483.2 | 486.4 |

No signal. Frame *count* is not the limiter; per-byte work inside the session is.
The experiment was reverted, not landed.

## 6. Why more sessions is not available as a fix

Four streams split over two independent frpc logins (two yamux sessions, 2+2
streams), 10 s:

| shape | MiB/s |
|---|---|
| 1 session, 4 streams, 1 client process | 486.1 / 486.1 |
| 1 session, 4 streams, 2 client processes (2+2) | 486.4 / 485.6 |
| 2 sessions, 2+2 streams | 570.2 / 569.8 / 567.3 |

The control proves the gain is the session, not client-process parallelism
(+0% for a split client on the same session, +17% for a second session). So the
ceiling is per session — one connection driver task plus its copies.

That is nevertheless **not** a lever we can pull today: a second login for the
same `run_id` supersedes the first (Go frp v0.72.0 `#5596`; frp-rs implements the
same supersession — see the `IncomingStreams::force_close_tx` doc comment in
`frp-core/src/mux.rs`), so pooling work conns across sessions needs a protocol
change and a Go-side story. Not a cheap win.

## 7. Consequences

- The earlier "mux is 43% below plain" figure came from one noisy window at one
  stream count. The defensible statement is the sweep in §2: **0.80 at one
  stream, 0.73 at four, 0.66 at eight**.
- Do not chase the mux row with compiler flags: `-O3` bought +15% there because
  the path waits; it bought +19-40% on the CPU-bound cipher/compression rows.
- If mux throughput ever becomes a priority, the only two honest levers are
  (a) a cheaper per-byte frame copy in the vendored yamux send/recv path, or
  (b) multiple sessions per client, which is a protocol change.
- Absolute rates on this host are not comparable across days — same bench,
  different windows: `plain` 148 → 1114 MiB/s over the archive
  (`docs/archive/notes/2026-08-04-mimalloc-throughput-ab.md` §4). Ratios measured
  in one interleaved window are the only usable signal.

## 8. Reproduce

```bash
cargo build --release -p frps -p frpc    # frp-stress is built separately:
cargo build --release --manifest-path scripts/frp-stress/Cargo.toml

# echo backend, then frps + frpc (tcp_mux = true) on ports 18900/18901/18902,
# then, per stream count N:
scripts/frp-stress/target/release/frp-stress --scenario throughput \
  --port 18901 --streams N --duration 10

bash scripts/download-go-frp.sh          # then the same command against Go's frps/frpc
```

`--streams` is the only knob that matters: `scripts/throughput-baseline.sh` runs
the matrix at one stream count and cannot show the §2 curve.

`scripts/throughput-baseline.sh` measures the 6 bridge rows at one stream count
only; it cannot show a scaling curve, so it would not have caught §2.
