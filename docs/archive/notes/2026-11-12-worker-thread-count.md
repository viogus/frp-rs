# The worker-thread count dominates a single tunnel

**Date:** 2026-11-12
**Status:** Root cause found; the knob is shipped, the default is unchanged.

## Symptom

One KCP tunnel carried **64-66 MiB/s** on a four-vCPU test VM while Go frp v0.72.0
carried 99-102 MiB/s on the same host, harness and flow shape (one 2048 MiB
one-way stream, `tcpMux` + TLS). The stack was not CPU-bound: one worker thread
halves the CPU ticks while moving 1.73x the bytes, which is the proof used below.

The wins that were already in the build - AVX2 FEC parity, one `sendmmsg` per
flush, `recvmmsg`, the segment carry, one flush per write burst, the 1400-byte
MTU - each moved this stream by 3-13%. Every probe aimed at the *scheduling
shape* was then within noise: the one-copy write path (~0%), the 64 MiB yamux
stream window (0%), a blocking relay instead of tokio (0%), ACK batching to the
tick (-28%, rejected), Go's three flush models (-58% to -6%), 4 MiB UDP socket
buffers (0%) and read coalescing (+1.7%). None of them touched how work moves
between threads.

## What actually matters: how many worker threads the runtime has

`TOKIO_WORKER_THREADS` decides how
many threads the multi-threaded runtime runs its tasks on. One flow, 2048 MiB,
same binary:

| runtime workers | MiB/s | CPU ticks frps/frpc |
| --- | --- | --- |
| 4 (default on this VM) | 64.6 | 3512 / 3636 |
| 2 | 75.2 | 3570 / 3802 |
| **1** | **111.8** | 1755 / 1739 |

(The two-worker cell is a single run and burns slightly *more* CPU than four for
+16% throughput, so read it as a midpoint, not a trend.)

Four flows through `tcpMux` show the same ordering (1 worker 109.6, 4 workers
64.9). Four *separate* `tcp` sessions (no `tcpMux`, one proxy each, 2048 MiB
each, same VM, two pairs) measured 2362 / 2283 MiB/s total at four workers
against 2470 / 2811 at one - no measurable loss, but the within-arm spread is
14% against a 4.5% difference, so two pairs cannot establish equivalence and
four sessions say nothing about a server carrying hundreds.

Setting the knob on only one side recovers about half the gap each way -
client only 86.0, server only 87.8, both 111.8 - so the migration cost is paid
symmetrically.

## Confounds that were ruled out

- **Not tokio being slow multi-threaded.** A plain tokio relay on the same host:
  2686 MiB/s at one worker, 2679 at four.
- **Not CPU oversubscription.** Pinning the two processes to disjoint cores
  (`frps` on 0-1, `frpc` on 2-3): 110.1 MiB/s at one worker, 64.0 at four.
- **Not code generation.** A `-C target-cpu=native` build measured 65-67 MiB/s
  on the same harness; it was not written up as its own note, so treat it as a
  passing check rather than published evidence.
- **Not per-message wakeups.** Coalescing the KCP read path into one channel
  message per wake (branch `perf/kcp-read-coalesce`, three pairs per arm) was
  62.8 against 63.9 MiB/s means - inside the ±7% run-to-run spread this VM shows
  between identical runs (`docs/archive/notes/2026-11-12-kcp-go-flush-model.md`).
- **Direction confirmed on macOS.** Four-stream `tcp` + `tcpMux` on a laptop:
  1037 MiB/s at one worker against 837 at four (+24%).

## Why

A bridged tunnel is a pipeline of tasks - bridge read half, yamux stream, yamux
connection, KCP write queue, KCP socket driver. With several workers each wakeup
can land on a different thread, and every hop between them pays a wake, an IPI
and a cache invalidation on the session state the previous thread had hot. With
one worker every hop is a local wake on the same core.

Pinning only the KCP driver to its own thread (probe build, `FRP_KCP_DRIVER_THREAD=1`)
recovered about two-fifths of the gap (84.5 MiB/s against 64.6), which is consistent
with the same mechanism acting per task rather than per process. The profile
does not discriminate this from lock contention on shared session state: at
one worker the process uses ~1.1 of 4 cores, and the four-worker profile is 33.6%
syscalls plus 22% scheduler wakeups, which fits both stories.

## What ships

Status: **shipped** as `transport.workerThreads` (PR #619), restart-only.
`frpc` defaults to one worker, `frps` to one per available CPU; the config key
beats `TOKIO_WORKER_THREADS`, which still works when no config names a count.
Earlier drafts of this note said "no config-file key" — that was true before the
key landed and is kept here only as history. A `FRP_WORKER_THREADS` alias was
dropped in favour of tokio's own variable name.

Guidance: for a single fat tunnel - bulk transfer over `kcp`, `tcp` or `tcpMux` -
set `workerThreads = 1` on **both** ends (111.8 MiB/s). The client-side default
alone gets 89.7-91.2 (+37%). For a server carrying many independent tunnels on
many cores, leave `frps` at its default: one worker serialises the whole
process, and this note only shows four tunnels on a four-vCPU host.

## Limits

- Measured on one four-vCPU VM and one Apple-silicon laptop; no many-core server
  was available, and the multi-tunnel evidence covers four tunnels, not hundreds.
- The numbers are from a loopback harness: absolute MiB/s will differ on real
  links; the ~1.7x single-tunnel ratio and the both-ends requirement are the
  transferable part.
- The table's cells are single runs. This VM moves by up to ±7% between identical
  runs, which is why the arms here differ by 73% and why the two-worker cell is
  called a midpoint rather than a trend; the coalescing probe is the only one
  reported inside that band.
- The single-tunnel evidence is KCP. The advice extends to `tcp`/`tcpMux` on the
  strength of the four-stream macOS row only.
- The `FRP_KCP_DRIVER_THREAD=1` probe that recovered two-fifths is a throwaway
  build that is not in the tree, so that row cannot be re-run without
  re-applying the patch.
- The real fix - keeping one session's whole pipeline on one thread so that many
  sessions still spread over cores - is not implemented; see `TODO.md`.

## Reproduce

Harness on the VM (`/root/bench/kcd.sh <bindir> <label> <flows> <MiB> <mux>
<defer> <tick_ms>`), binaries built from `main`:

```sh
/root/bench/kcd.sh /root/bench/wt w4 1 2048 true 0 10
TOKIO_WORKER_THREADS=1 /root/bench/kcd.sh /root/bench/wt w1 1 2048 true 0 10
```

Control, on the same host and harness: Go frp v0.72.0 moves 99-102 MiB/s for the
same flow.
