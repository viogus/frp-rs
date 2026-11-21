# Does a yamux task change the one-worker penalty?

Scope: the open half of the `TODO.md` § P2 item *"One session's pipeline migrates
between runtime workers"* — "whether bridge/yamux tasks should follow the [KCP]
driver [onto a private runtime]". This note measures the one shape that question
turns on: the same eight client connections with and without `tcpMux`, at one
client worker and at the default pool.

## Method

- Host: macOS arm64, 8 cores (4 performance + 4 efficiency), loopback only, ports
  18700-18702, nothing else running.
- Binaries: this tree's `target/release/{frps,frpc}` (built from `edfbd3e1`,
  default features) and `scripts/frp-stress/target/release/frp-stress`.
- Configs: `frps` at its defaults except `tcp_mux`; `frpc` adds
  `[transport] worker_threads = N`, `pool_count = 1`, one `tcp` proxy to the
  stress echo sink. `frps` kept its default pool in every arm — only the client
  side is varied, because that is the side the item's trigger is stated on.
- Load: `frp-stress --scenario throughput --streams {1,8} --duration 10`, which
  counts **bytes both ways** (sent + echoed), so every level below is twice a
  one-way rate. Ratios are what carry across harnesses; levels are not
  comparable with the one-way `abbench` figures.
- Reps: three per arm at eight connections, two per arm at one connection.

## Result

MiB/s as the harness reports them (both directions), eight connections:

| `tcp_mux` | `worker_threads = 1` | `worker_threads = 8` (default) | one / pool |
|---|---|---|---|
| `false` | 661.4, 620.3, 636.9 (mean **639.5**) | 802.3, 780.9, 799.4 (mean **794.2**) | **0.81×** |
| `true` | 523.0, 525.1, 521.4 (mean **523.2**) | 494.1, 485.9, 507.6 (mean **495.9**) | **1.06×** |

One connection, same host, same harness:

| `tcp_mux` | `worker_threads = 1` | `worker_threads = 8` | one / pool |
|---|---|---|---|
| `false` | 313.8, 326.1 (mean 320.0) | 322.9, 323.4 (mean 323.2) | 0.99× |
| `true` | 292.6, 291.5 (mean 292.1) | 294.6, 296.2 (mean 295.4) | 0.99× |

The three per-arm samples do not overlap in either eight-connection row, so the
direction of each effect is outside this host's rep-to-rep spread (~3%).

## What it says

1. **The one-worker deficit is real and reproduces without `tcpMux`**: 0.81×,
   matching the 77-79% recorded in
   [`2026-11-21-worker-fan-in-macos.md`](2026-11-21-worker-fan-in-macos.md) on the
   same shape. A single runtime thread serialises eight independent bridge
   pipelines and loses about a fifth of the aggregate.
2. **A yamux task in the path removes the benefit of the extra workers, and then
   some**: with `tcpMux` on, one worker carries **1.06×** what the pool carries.
   The eight sessions multiplex onto one connection, so per-session parallelism
   is already inside that connection; spreading its tasks across workers buys
   nothing and costs a little (524 → 496, about 5%).
3. **One connection is flat at every worker count in both modes** (0.99× both),
   which is what makes (1) and (2) statements about *fan-in*, not about the
   runtime being slow.

## What it cannot say

- **It does not separate yamux from the bridge halves.** `tcpMux` adds a yamux
  stream *and* a yamux connection task, and folds eight work connections into
  one, so 1.06× could be "the yamux task does not want to migrate", "one work
  connection is cheaper than eight", or both. Pinning only bridge tasks onto a
  private runtime — the change the item actually contemplates — is not measured
  here.
- **It is the client side only.** `frps` ran its default pool throughout; a
  server-side arm could differ, and the item's trigger was originally stated on a
  four-vCPU Linux host.
- **`tcpMux` is also just slower here** (496-523 against 639-794 at eight
  connections), so the 1.06× is a ratio inside a different throughput regime, not
  a like-for-like comparison of the same work.
- Ten-second reps measure steady state, not tail latency; nothing here says
  anything about p99 under fan-in.

## What it means for the item

The question "should bridge/yamux tasks follow the KCP driver onto a private
runtime" is answered **no for the yamux half**: with a yamux task present, the
default pool is already ~5% slower than one worker, so there is no deficit for
pinning to recover. The bridge half is where the 0.81× lives, and the fix for
that is *more* workers, not fewer — which is what the pool does.

This does not close the item: the 0.81× is still an observation without a
mechanism, and the trigger it re-opens on is unchanged.

## Reproducing

```bash
cargo build --release -p frps -p frpc
(cd scripts/frp-stress && cargo build --release)
bash scripts/worker-fan-in-probe.sh 8 3 10   # eight connections, three reps, 10 s
bash scripts/worker-fan-in-probe.sh 1 2 10   # the flat-at-one-connection control
```

The probe writes each rep's JSON to `/tmp/disc-<mux>-<workers>-<rep>.json`; the
`mbps` field is the harness's both-directions figure. Delete `/tmp/disc-*.json`
between runs so a stale rep cannot be read as a fresh one.
