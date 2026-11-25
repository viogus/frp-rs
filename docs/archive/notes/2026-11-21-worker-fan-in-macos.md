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
   (681.5/864.0, 719.7/934.9, 718.0/930.4) — **on this host**; the § re-measured
   on Linux below reads 99% for the same quantity.
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
  falsifies that — 79% there was a single ratio, not a host-independent law.

## Re-measured on Linux (2026-11-25)

Same question, same harness row, a host with `splice(2)`:

- Host `gc` (greencloud-tyo): 4 vCPU EPYC-Milan, loopback, load ~2 from
  unrelated daemons. Binaries `--release` at `4ba46c3c`.
- `scripts/throughput-baseline.sh`, `plain` row only (`tcp`, `tcp_mux = false`,
  no encryption/compression, `pool_count = 1`), 10 s, 3 reps per cell; `frps`
  left at its default pool, `frpc` pinned with
  `[transport] worker_threads = 1|4` appended to its generated config.
- Counts bytes both ways, like the macOS run, so levels are not comparable with
  one-way figures — ratios are.

| frpc workers | 1 connection | 8 connections | 8/1 |
|---|---|---|---|
| 1 | 325.1 (326.2 / 322.5 / 326.5) | 869.6 (900.5 / 849.3 / 859.0) | **2.68** |
| 4 (default) | 315.6 (312.2 / 319.6 / 314.9) | 877.5 (915.4 / 826.0 / 891.0) | 2.78 |

- **The item's trigger does not fire here.** Eight connections at one worker
  reach 2.68× the one-flow rate, above the 2.5× threshold the item names.
- **There is no fan-in penalty at one worker on this host.** One worker carries
  **99%** of the four-worker eight-connection aggregate (869.6 / 877.5), against
  77-79% on macOS.
- **One worker is not slower at one connection either**: 325.1 against 315.6,
  i.e. one worker is 3% *ahead*, the opposite sign to the macOS column.

So the migration cost this item is about is not universal: on the Linux host
with `splice(2)` it is absent at both connection counts, and the macOS column is
consistent with the userspace bridge copy that host has (as § 3 above says,
without measuring it as the cause). A cross-host claim would need a third host
before it could be made.

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
