# The worker-thread count dominates a single tunnel

**Date:** 2026-11-12
**Status:** Root cause found; the knob is shipped, the default is unchanged.

## Symptom

One KCP tunnel carried **64-65 MiB/s** on a four-vCPU test VM while Go frp v0.72.0
carried 99-102 MiB/s on the same host, harness and flow shape (one 2048 MiB
one-way stream, `tcpMux` + TLS). Four *independent* KCP tunnels on the same build
reached 106 MiB/s, so the stack was not CPU-bound: only one session was slow.

Sixteen earlier experiments on that ceiling - copies, syscalls, FEC, MTU,
ACK policy, flush model, driver batching, window size - were all neutral or
worse, because none of them touched the scheduling shape.

## What actually matters: how many worker threads the runtime has

`TOKIO_WORKER_THREADS` decides how
many threads the multi-threaded runtime runs its tasks on. One flow, 2048 MiB,
same binary:

| runtime workers | MiB/s | CPU ticks frps/frpc |
| --- | --- | --- |
| 4 (default on this VM) | 64.6 | 3512 / 3636 |
| 2 | 75.2 | 3570 / 3802 |
| **1** | **111.8** | 1755 / 1739 |

Four flows through `tcpMux` show the same ordering (1 worker 109.6, 4 workers
64.9), and four *separate* tunnels are not hurt by one worker at all
(2048 MiB each: 2469 / 2810 MiB/s total at one worker against 2362 / 2283 at
four).

Setting the knob on only one side recovers about half the gap each way -
client only 86.0, server only 87.8, both 111.8 - so the migration cost is paid
symmetrically.

## Confounds that were ruled out

- **Not tokio being slow multi-threaded.** A plain tokio relay on the same host:
  2686 MiB/s at one worker, 2679 at four.
- **Not CPU oversubscription.** Pinning the two processes to disjoint cores
  (`frps` on 0-1, `frpc` on 2-3): 110.1 MiB/s at one worker, 64.0 at four.
- **Not code generation.** `-C target-cpu=native`: 65-67, measured before the
  knob existed.
- **Not per-message wakeups.** Coalescing the KCP read path into one channel
  message per wake was +1.6%, i.e. noise.
- **Direction confirmed on macOS.** Four-stream `tcp` + `tcpMux` on a laptop:
  1037 MiB/s at one worker against 837 at four (+24%).

## Why

A bridged tunnel is a pipeline of tasks - bridge read half, yamux stream, yamux
connection, KCP write queue, KCP socket driver. With several workers each wakeup
can land on a different thread, and every hop between them pays a wake, an IPI
and a cache invalidation on the session state the previous thread had hot. With
one worker every hop is a local wake on the same core.

Pinning only the KCP driver to its own thread (probe build, `FRP_KCP_DRIVER_THREAD=1`)
recovered about a third of the gap (84 MiB/s against 64), which is consistent
with the same mechanism acting per task rather than per process.

## What ships

Nothing in frp-rs needs to change for this: the runtime reads tokio's own
`TOKIO_WORKER_THREADS` when it starts, in both `frps` and `frpc`. Unset keeps the
runtime default (one worker per core). No config-file key, no wire change — Go
frp ignores environment variables it does not know, and nothing about the
protocol moves. A `FRP_WORKER_THREADS` alias was prototyped and dropped: it
would have re-numbered sixty source citations to add a second name for a knob
tokio already owns.

Guidance: for a single fat tunnel - bulk transfer over `kcp`, `tcp` or `tcpMux` -
set `TOKIO_WORKER_THREADS=1` on **both** ends. For a server carrying many
independent tunnels on many cores, leave it unset: one worker serialises the
whole process, and this note only shows four tunnels on a four-vCPU host.

## Limits

- Measured on one four-vCPU VM and one Apple-silicon laptop; no many-core server
  was available, and the multi-tunnel evidence covers four tunnels, not hundreds.
- The numbers are from a loopback harness: absolute MiB/s will differ on real
  links, the 4:1 and 1.7x ratios are the transferable part.
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
