# Client worker count and fan-in, on a macOS host

**Status (2026-11-21, re-measured on Linux 2026-11-25): measurement only.** Recorded for
[`TODO.md`](../../../TODO.md)'s "One session's pipeline migrates between runtime
workers" item, whose reopen trigger could not be read on this host. No code
change.

## What was asked

That item's remaining question is whether bridge/yamux tasks should follow the
KCP driver onto a private runtime. Its trigger is a ratio: "eight `tcp` sessions
at one worker drop below 2.5× the one-flow rate". This run measures the worker
curve behind that ratio, so the trigger can be set on a quantity that is stable
across hosts.

## Method

- Host: macOS arm64, 8 cores (4 performance + 4 efficiency), loopback only, no
  traffic on ports 18000-18002.
- Binaries: this tree at `docs(todo): measure the worker-count question` —
  `target/release/{frps,frpc}`, default features, one build for every arm.
- Harness: `scripts/throughput-baseline.sh` (10 s per rep, `plain` row only:
  `tcp`, `tcp_mux = false`, no encryption, no compression, no TLS,
  `pool_count = 1`). `frps` kept its default pool in every arm.
- Worker arm: a copy of that script that appends

  ```toml
  [transport]
  worker_threads = 1        # 2 and 4 for the other arms
  ```

  to the generated client config. The repo script has no worker knob and was not
  changed.
- Connections: `--streams N`, i.e. N concurrent TCP connections to the proxy's
  remote port. With `tcp_mux = false` each one takes its own work connection, so
  "connections" here is what the item calls "sessions".
- Reps: three at 1 and at 8 client workers, two at 2 and at 4. All values are
  MiB/s as the harness reports them.
- Reading the numbers: the harness counts **bytes both ways** (sent + echoed,
  `scripts/frp-stress/src/scenarios/throughput.rs`), so a level here is twice a
  one-way rate. Levels are therefore not comparable with the one-way `abbench`
  figures in [`2026-11-13-splice-wrapper-peel.md`](2026-11-13-splice-wrapper-peel.md);
  ratios are.

## Result

| client workers | 1 connection | 8 connections | 8/1 |
|---|---|---|---|
| 1 | 363.4 / 366.4 / 363.8 | 681.5 / 719.7 / 718.0 | 1.88 / 1.96 / 1.97 |
| 2 | 350.2 | 799.7 / 781.5 | 2.28 / 2.23 |
| 4 | 347.9 | 822.0 / 835.6 | 2.36 / 2.40 |
| 8 (default) | 364.2 / 364.1 / 365.3 | 864.0 / 934.9 / 930.4 | 2.37 / 2.57 / 2.55 |

Raw loopback through the same harness with frp out of the path (`--scenario
throughput` straight at the echo backend), for the ceiling comparison:

| connections | MiB/s |
|---|---|
| 1 | 2295.2 / 2312.2 |
| 8 | 8507.7 / 8697.0 |

## What it says

1. **One connection is flat at 1 and at 8 workers** (363-366; the three-rep
   means are 364.5 either way) and slightly *lower* at 2 and 4 (350.2, 347.9) —
   the 5-7% one-flow cost of extra workers that
   [`2026-11-16-worker-thread-default.md`](2026-11-16-worker-thread-default.md)
   records for co-located processes.
2. **Eight connections are not flat**: 682-720 at one worker, 782-800 at two,
   822-836 at four, 864-935 at eight. Most of the gain arrives at two workers;
   2→4 adds nothing measurable; 4→8 is a further step. One worker carries
   **77-79%** of the default pool's eight-connection aggregate, paired rep-wise
   (681.5/864.0, 719.7/934.9, 718.0/930.4) — **on this host, against the
   eight-worker pool**. Against this host's own four-worker arm the same cell is
   706.4/828.8 = **85.2%**, and against two workers 89.3%; the § re-measured on
   Linux below compares 1 against 4 and reads 98%.
3. **The ~900 MiB/s plateau is the bridge, not the loopback**: without frp the
   same harness reaches 2295-2312 on one connection and 8508-8697 on eight. This
   host has no Linux `splice(2)`, so its bridge copy is userspace; that is
   consistent with the gap and is not measured as its cause.

## What it cannot say

- **It does not isolate the bridge tasks.** `worker_threads` sizes `frpc`'s one
  process-wide runtime (`frpc/src/main.rs` `build_runtime`), so the one-worker
  arm also serialises control, accept and handshake. Whether pinning *only*
  bridge/yamux onto another runtime reproduces the one-worker column is untested
  by this probe.
- **It says nothing about yamux or KCP.** The `plain` row runs `tcp_mux = false`,
  so no yamux task exists in these arms and no KCP driver thread does either.
- **It does not make the item's absolute trigger meaningful.** On the host the
  item quotes, eight sessions at one worker carried 2266 MiB/s against 2570 on
  one flow — 0.88×, already inside the 2.5× threshold, and that host's
  four-worker eight-session figure (2867) is 1.12× its one-flow rate. An absolute
  8/1 ratio measures the host and the counting, not the scheduling. This note
  originally read the worker-relative 77-79% as the quantity that holds across
  hosts (2266/2867 = 79% on the quoting host); the Linux re-measurement below
  weakens that — 79% there was one ratio from one host, and the Linux host reads
  98% on the plain shape, so the quantity is neither host-independent nor
  shape-independent.

## Re-measured on Linux (2026-11-25)

Same question, same harness row, on a host with `splice(2)`:

- Host `gc` (greencloud-tyo): 4 vCPU EPYC-Milan, loopback, load ~2 from
  unrelated daemons. Binaries `--release` at `4ba46c3c`.
- `scripts/throughput-baseline.sh`, `plain` row only (`tcp`, `tcp_mux = false`,
  no encryption/compression, `pool_count = 1`), 10 s per rep; `frps` left at its
  default pool, `frpc` pinned with `[transport] worker_threads = 1|4` appended to
  its generated config. Arms interleaved, order flipped every rep: 8 reps per
  cell at eight connections, 4 per cell at one.
- Counts bytes both ways, like the macOS run, so levels are not comparable with
  one-way figures — ratios are.
- Two sessions were run (the first before the rep count was raised) and they
  disagree by ~10% on the level: eight connections at one worker read 869.6 in
  the n=3 session and 788.7 in the n=8 one. Only within-session ratios are used
  below.

| session | frpc workers | 1 connection | 8 connections |
|---|---|---|---|
| n=3 | 1 | 325.1 | 869.6 (900.5 / 849.3 / 859.0) |
| n=3 | 4 (default) | 315.6 | 877.5 (915.4 / 826.0 / 891.0) |
| n=8 | 1 | 325.4 (317.0 / 322.3 / 324.2 / 338.0) | 788.7 sd 25.5 |
| n=8 | 4 (default) | 326.9 (313.4 / 329.3 / 330.8 / 333.9) | 802.2 sd 24.4 |

Reading the n=8 session, which is the one with enough reps to bound anything:

- **One worker carries 98.3% of the four-worker eight-connection aggregate**,
  paired rep-wise: +13.5 ± 15.4 MiB/s for four workers over one (t≈0.9, n=8),
  ratio 95% CI ≈ 0.96-1.03. Against macOS's same 1-vs-4 comparison (85.2%), that
  is not the same regime — but with one host per OS the difference cannot be
  attributed to `splice(2)`, to 8 cores against 4, or to this host's external
  load.
- **The item's trigger cannot be read on this host.** Eight connections at one
  worker are 2.42× the one-flow rate in this session and 2.68× in the n=3 one —
  across the 2.5× threshold, on the two sides of the same threshold. Both arms
  also sit on the same wall (~790-880 both-ways, i.e. ~400-440 one-way), which
  is six times below this host's raw `tcp` rate (2684/2542 MiB/s one-way,
  `docs/archive/notes/2026-11-16-worker-thread-default.md`), so the eight-connection
  row is bounded by something other than the worker count. No Linux
  raw-loopback ceiling was measured here to name that bound; the macOS section
  did measure one on its host.
- **One connection is flat**: 325.4 against 326.9 (+1.5 ± 4.8, t≈0.3, n=4) — the
  3% one-worker lead of the n=3 session does not survive more reps. macOS reads
  the same direction (364.5 at one worker against 347.9 at four, its "5-7%
  one-flow cost of extra workers"), so nothing here is *opposite* in sign.
- **This is one shape, not a host.** The same host shows a 20-37% one-worker
  penalty on the `tcpMux` and TLS shapes
  (`docs/archive/notes/2026-11-16-worker-thread-default.md:30,42`), which is
  what § "What it cannot say" above predicts: `worker_threads` sizes one
  process-wide runtime, so a plain, mux-free, TLS-free row exercises no yamux
  task and no KCP driver thread. The plain row's ~1.0 ratio therefore says the
  *plain* row has no fan-in penalty on this host; it does not say the bridge
  path is free everywhere.

What this measurement does not support: that the migration cost is absent on
Linux in general, that the macOS figure is caused by the userspace bridge copy,
or that the 2.5× trigger is meaningful — all three would need a second Linux
host, CPU figures per arm, and a raw-loopback row on the same box.

## Reproducing

```bash
cargo build --release -p frps -p frpc
(cd scripts/frp-stress && cargo build --release)
cp scripts/throughput-baseline.sh /tmp/tb.sh    # then: append [transport]/worker_threads
OUT=/tmp/w1-s1.jsonl bash /tmp/tb.sh 10 1
OUT=/tmp/w1-s8.jsonl bash /tmp/tb.sh 10 8
```

The probe copy must pin `PROJECT_DIR` to this tree if it lives outside the repo,
and each worker arm needs its own copy because the script regenerates the client
config per run.
