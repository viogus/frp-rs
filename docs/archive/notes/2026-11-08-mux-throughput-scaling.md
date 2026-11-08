# tcpMux Throughput: Where the Gap Actually Is

**Date:** 2026-11-08
**Context:** The `release-perf` A/B (same day) left one unexplained row: the `mux`
throughput cell moved only +15% under `-O3` while the encrypted/compressed cells
moved +19-40%, and a single-window pairing had shown `mux` at 43% below `plain`.
That suggested a structural cost in the mux data path worth finding.
**Decision:** **No code change in this commit.** The mux penalty is real but
concurrency-shaped and it is not CPU-limited; the one structural lever (more
sessions per client) is blocked by Go-compat login semantics. §5 does identify a
measured lever — a 64 KiB bridge buffer *and* a 64 KiB yamux split, together
+13% — which is left as a follow-up because it changes the memory floor and needs
Go cross-compat coverage. Numbers recorded here so the next round does not
re-derive them.
**Measured tree:** `602910a5` (branch tip at measurement time; docs-only since)

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
- Host: Apple M2 / macOS arm64, 8 cores.
- 10-12 s per run, arms **interleaved** and order-rotated; a run's absolute rate
  on this host moves by up to ~1.4x between runs in the same day (§3) and 7.5x
  across the archive (§7), so only same-window ratios are meaningful.
- Rates count **both directions**: each loopback round trip is 64 KiB written
  plus 64 KiB echoed back (`scripts/frp-stress/src/scenarios/throughput.rs:77-78`
  adds `PAYLOAD_SIZE * 2`), so a "486 MiB/s" cell is ~243 MiB/s of one-way
  payload.
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
- **`mux` plateaus at ~485-520 MiB/s** between 4 and 8 streams while its CPU
  spend continues to rise (22.9 s → 27.2 s per 10 s wall). It is not
  CPU-saturated: 2.3-2.7 of 8 cores. `plain` reaches 3.0-3.8 cores and 780 MiB/s.
- At low concurrency `mux` costs *more* CPU per byte than `plain` (10.8 vs 9.6 s
  for less data) — framing and copies. At high concurrency it costs *less*
  total CPU while delivering much less — it is waiting, not computing.

## 3. Against Go frp v0.72.0 (4 streams, 10 s, interleaved)

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

- `plain` is at parity in run 1 (748.8 vs 768.3, -2.5%); run 2's rs `plain` cell
  (622.6) is a low outlier, so parity is a run-1 statement, not a median.
- These two runs are a *different window* from §2 (rs `plain` here reads 748.8,
  above §2's 668.5) — the table is for cross-implementation ratios only.
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
| 64 KiB | 345.6 / 362.3 | 435.8 / 457.3 | +90.2 / +95.0 | — | — | — |

The defensible reading is the 64 KiB row: the mux adds ~90 µs to a 346 µs round
trip (p50), the same order as the ~27 µs Go pays at 1 KiB. The 1 KiB and 16 KiB
deltas are noise-dominated — the 16 KiB mean delta (20.0 µs) is *below* the 1 KiB
one (26.9 µs) — so no fixed-cost-plus-data-term model is fitted here.

## 5. Frame count only matters once chunks are 64 KiB

The first version of this section tested `split_send_size` 32 KiB vs 64 KiB at
the shipped buffer size and concluded "frame count is not the limiter". **That
experiment was inert** and the conclusion is withdrawn:

- The bridge never hands yamux 64 KiB. `copy_pooled` writes a
  `frp-core/src/buffer_pool.rs` buffer, and `BUFFER_SIZE` defaults to **32768**
  (`frp-core/src/buffer_pool.rs:27-34`); 64 KiB is the *harness payload*, not a
  bridge chunk.
- `cfg.set_split_send_size(32 * 1024)` (`frp-core/src/mux.rs:486`) therefore
  already emits exactly **one** frame per 32 KiB write, and 64 KiB emits one
  frame too (`k = min(len, split_send_size)`). Both arms had identical wire
  behaviour, so the measured +0.7% was noise.

Re-run as a 2x2 over {bridge buffer 32/64 KiB} x {split 32/64 KiB} — buffer via
`FRP_BRIDGE_BUF_KB`, split via a one-line rebuild — 3 interleaved reps, 12 s,
4 streams:

| arm | buffer | split | frames per 64 KiB | r1 | r2 | r3 | mean |
|---|---|---|---|---|---|---|---|
| A | 32 KiB | 32 KiB | 2 (two 32 KiB writes) | 479.85 | 424.00 | 410.85 | 438.2 |
| B | 64 KiB | 32 KiB | 2 | 461.33 | 418.02 | 420.01 | 433.1 |
| C | 64 KiB | 64 KiB | 1 | 505.07 | 484.46 | 481.03 | 490.2 |
| D | 32 KiB | 64 KiB | 2 (same wire as A) | 428.00 | 415.67 | 408.43 | 417.4 |

Mean CPU-seconds per 12 s run (frps / frpc): A 13.65/14.27, B 13.27/13.58,
C 12.36/12.61, D 13.66/14.22.

Reading:

- **C beats B in every rep** (+9.5%, +15.9%, +14.5%; mean +13.2%) with ~7% less
  CPU. At a fixed 64 KiB chunk, one frame instead of two *is* the win — the
  original hypothesis was right, the experiment was wrong.
- **D vs A is inert** (-4.8%, the same noise band as the withdrawn experiment),
  confirming `split_send_size` does nothing below the buffer size.
- **B vs A is flat** (-1.2%): enlarging chunks while keeping 2 frames buys
  nothing, so the gain needs both halves of the change.
- C vs the shipped A is +11.9% at 4 streams.

Not landed here: it raises the retained-buffer ceiling (128 x 64 KiB = 8 MiB vs
4 MiB, `frp-core/src/buffer_pool.rs:36-48`) and costs +64 KiB per live bridge
(unpriced); it touches the plain and encrypted paths too (`BUFFER_SIZE` is
shared); and it needs frp-rs<->Go mux interop re-checked, since it changes the
yamux frame size on the wire. Follow-up: land as a two-knob change
behind the existing env defaults, then run `scripts/compat-test.sh` and
`scripts/protocol-matrix.sh`.

## 6. Why more sessions is not available as a fix

Four streams split over two independent frpc logins (two yamux sessions, 2+2
streams), 10 s:

| shape | MiB/s |
|---|---|
| 1 session, 4 streams, 1 client process | 486.1 / 486.1 |
| 2 sessions (two logins), 2+2 streams | 570.2 / 569.8 / 567.3 |

An earlier draft also listed "1 session, 2 client processes (2+2)" at 486.4/485.6
as proof that client-process parallelism does not help. That row is withdrawn: it
is unreachable by construction — a second frpc login for the same `run_id` closes
the first session (`frp-server/src/control/login.rs:605-615`), so the first
process's streams die rather than run alongside. The +17% for a second session is
supported by the two rows above plus §2's 2-stream point.

So the ceiling is per session — one connection driver task plus its copies.

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
  different windows: the archive recorded `plain` at 1114.7 MiB/s, which
  reproduces today at ~148 MiB/s, a 7.5x drop
  (`docs/archive/notes/2026-08-04-mimalloc-throughput-ab.md` §5
  "Baseline re-baselined"). Ratios measured in one interleaved window are the
  only usable signal.

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

`--streams` is the only knob that matters: `scripts/throughput-baseline.sh`
measures the 6 bridge rows at one stream count only, so it cannot show the §2
curve.

For §5, the same bring-up with `FRP_BRIDGE_BUF_KB=64` on both frp processes and a
`frp-core/src/mux.rs:486` rebuild at `64 * 1024` gives the C arm; `=32` / `32 *
1024` gives A.
