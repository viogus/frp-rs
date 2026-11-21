# Does a yamux task change the one-worker fan-in penalty?

Answers the yamux half of the question left open in
[`TODO.md`](../../../TODO.md) § P2 "One session's pipeline migrates between runtime
workers": *should bridge/yamux tasks follow the KCP driver onto a private runtime?*
The KCP half was answered on the Linux VPS (the driver writes from its own poll
thread, so it must not also be asked to run the session's tasks). This note is the
`tcpMux` half, measured on the macOS arm64 development host.

Probe: [`scripts/worker-fan-in-probe.sh`](../../../scripts/worker-fan-in-probe.sh).
Harness: `scripts/frp-stress` `throughput` scenario, both directions, 64 KiB
write→`read_exact` ping-pong, MiB/s as reported in its `mbps` field.

## Method

Four arms: `tcp_mux ∈ {false, true}` × `frpc` `[transport] worker_threads ∈ {1, 8}`.
`frps` keeps its defaults except the bind address/port, a token and `warn`
logging; the client runs `pool_count = 1` and one `tcp` proxy so the arms differ
only in the knobs named above.

The arms are **interleaved**: each rep runs the two mux values back to back, and
the order flips every rep. This matters — the first version of this probe ran
each arm three times in a block, and on a host whose load drifted during the run
that put the whole drift on whichever arm came last (see *Corrections*).

## Result

Interleaved, five reps per cell, ten-second reps, eight connections, on a host
under heavy background load (load average 27 on 8 cores during the run):

| `tcp_mux` | `worker_threads = 1` | `worker_threads = 8` (default) | one / pool, per rep | mean | median |
|---|---|---|---|---|---|
| `false` | 393.0, 432.5, 445.5, 457.5, 459.5 | 477.8, 501.2, 505.7, 547.1, 572.1 | 0.855, 0.962, 0.814, 0.687, 0.913 | **0.84×** | **0.88×** |
| `true` | 342.9, 350.2, 367.8, 382.4, 391.4 | 376.6, 388.8, 389.2, 398.1, 400.3 | 0.983, 0.983, 0.857, 0.977, 0.901 | **0.94×** | **0.95×** |

One connection, same probe, default `worker_threads` only (two reps each):

| `tcp_mux` | `worker_threads = 1` | `worker_threads = 8` | one / pool |
|---|---|---|---|
| `false` | 313.8, 326.1 (mean 320.0) | 322.9, 323.4 (mean 323.2) | 0.99× |
| `true` | 292.6, 291.5 (mean 292.1) | 294.6, 296.2 (mean 295.4) | 0.99× |

**Absolute levels are not comparable across runs.** The same committed probe
measured `0.81×` and `1.06×` earlier on this host at 639.5/794.2 and
523.2/495.9 MiB/s; this run's levels are 25-30% lower throughout, because the host
was loaded. What survives a change of host state is the ratio **inside** one rep,
which is why every rep above reports its own ratio.

## What it says

1. **Without `tcpMux` the one-worker deficit is real and reproduces**: the
   per-rep ratio is below 1 in all five reps (0.69-0.96, mean 0.84, median 0.88),
   and the earlier paired-shape note
   ([`2026-11-21-worker-fan-in-macos.md`](2026-11-21-worker-fan-in-macos.md))
   recorded 0.776 on the same shape. A single runtime thread serialises eight
   independent bridge pipelines.
2. **A yamux task in the path shrinks that deficit to a few percent, and does not
   reverse it**: with `tcpMux` on, one worker carries 0.94× (mean) / 0.95×
   (median) of what the pool carries — three of five reps sit at 0.98, and the
   first two runs from another host measured 0.930 and 0.934 with an
   order-alternating design. One worker is **never faster than the pool** here.
3. **One connection is flat at every worker count in both modes** (0.99×), which
   makes (1) and (2) statements about *fan-in*, not about the runtime being slow.

## Corrections to the first version of this note

The first draft of this note claimed `1.06×` for the `tcpMux` arm — that one
worker carries *more* than the pool. That number does not reproduce, and it was
produced by two measurement faults, both fixed in the committed probe:

- **Blocked arm order.** `mux`→`workers`→`rep` nesting put every `w=1` rep next
  to a `w=8` rep from the same block, so a load change during the run lands on
  one worker count.
- **The one-worker arm is the load-sensitive one.** Across three independent runs
  the pool arm read 495.9 / 504.0 / 498.5 MiB/s (1.6% spread) while the one-worker
  arm read 523.2 / 469.0 / 465.5 (12% spread). A single-runnable-thread arm loses
  its whole timeslice to any background runnable task, so on a contended host a
  five-percent effect changes sign — which is exactly what the `1.06×` was.
- **The probe did not honour its own arguments.** `REPS` was never read from
  `$2` (so `8 2 10` silently ran three reps), and `--json-out` *appends*, so a
  stale `/tmp/disc-*.json` made a rerun read the first document and report no
  numbers at all for every rep. Both are fixed: the probe truncates each rep's
  file before writing it, waits on the ports it needs instead of sleeping, and
  fails the rep when `failed_streams > 0`.

The inference "the three samples do not overlap, so the effect is outside the
rep-to-rep spread" was wrong for the same reason: it compared ranges drawn from
an arm whose own spread is several times the effect.

## What it cannot say

- **It does not separate yamux from the connection fold.** `tcpMux` adds a yamux
  stream and a yamux connection task *and* folds eight work connections into one,
  so "the yamux task does not want to migrate" and "one work connection is
  cheaper than eight" both explain 0.94×. An exploratory `tcpMux = true,
  pool_count = 8` arm (fold neutralised by dialling eight multiplexed
  connections) kept the curve flat with the pool ahead in 4/4 reps — consistent
  with the yamux reading, not proof of it, and it was run while the host drifted
  from 520 to 385 MiB/s. A clean rerun of that arm is the discriminating
  experiment; until then this note says only that **the mux path as a whole has
  no yamux-side deficit worth recovering**.
- **It is the client side only.** `frps` ran its default pool throughout; the
  item's trigger was originally stated on a four-vCPU Linux host.
- **`worker_threads` is not only the bridge path.** It sizes frpc's whole
  runtime, so control, accept and handshake tasks are included in the arm.
- **The load is ping-pong, not bulk.** 64 KiB write→read_exact per connection
  makes wake-up latency matter more than it does for a bulk transfer.
- **`tcpMux` costs throughput by itself** (interleaved at `w=8`: 658.3 against
  470.9 in the clean run, about 28%), so the `tcpMux` ratios live in a different
  throughput regime.
- Ten-second reps measure steady state, not tail latency; nothing here says
  anything about p99 under fan-in. Ratios on a loaded host carry bounds of
  several percent; the one-worker arm's own spread is 13-15% in this run.

## What it means for the item

The question "should bridge/yamux tasks follow the KCP driver onto a private
runtime" is answered **no for the yamux half**: with a yamux task in the path the
pool is ahead by only 5-6%, and one worker is never ahead, so there is no
yamux-side deficit for a private runtime to recover — and the defect such a split
would introduce (a session's stages on two runtimes, which is what the item
records) buys nothing.

The residue is the 0.84× on the path *without* yamux: eight independent bridge
pipelines on one thread. The remedy that measurement points at is **more**
workers on the pool — which is what the pool already does, and what "migrate the
pipeline" would move in the opposite direction. That residue has no mechanism
yet, so `TODO.md` § P2's item **stays open** and its re-open trigger is unchanged.

## Reproducing

```bash
cargo build --release -p frps -p frpc
(cd scripts/frp-stress && cargo build --release)
bash scripts/worker-fan-in-probe.sh 8 5 10   # eight connections, five interleaved reps, 10 s
bash scripts/worker-fan-in-probe.sh 1 2 10   # the flat-at-one-connection control
```

The probe writes each rep's JSON under a `mktemp -d` work directory and truncates
it per rep, so no stale file can be read as a fresh one. `mbps` is the harness's
both-directions figure; `failed_streams` must be `0` in every rep or the probe
reports the rep as failed.
