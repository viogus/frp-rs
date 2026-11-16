# The client worker default: one per core

**Status (2026-11-16): shipped.** `frpc` defaults to one worker per available CPU,
matching `frps` and Go's `GOMAXPROCS`. `transport.workerThreads = 1` restores the
previous behaviour.

## Symptom

`frpc` built a single-threaded runtime. Through `tcpMux` or a single flow that
cost nothing, but four independent connections measured 819 MiB/s through
`tcpMux` and 854 through TLS on a client with one worker, against 988 and 1167
with two — the client, not the network, was the ceiling.

## Why the old default existed

[`2026-11-12-worker-thread-count.md`](2026-11-12-worker-thread-count.md) measured
a single fat KCP stream at **89.7-91.2 MiB/s on one worker against 65.5-66.6 with
one per core** on a client sharing four cores with its server, and made one
thread the client default. Two later changes removed that penalty:

- `perf/kcp-driver-thread` (PR #621, recorded in
  [`2026-11-12-worker-thread-count.md`](2026-11-12-worker-thread-count.md) §
  "Driver thread") moved each KCP socket driver onto its own runtime thread (+26%
  at four workers).
- [`2026-11-15-kcp-window-autotune.md`](2026-11-15-kcp-window-autotune.md) sized
  the KCP window by load (+60% on a lone stream at four workers).

After those, the single-stream cost of extra workers fell to 5-7% on a
co-located host and to nothing when the ends do not share cores, while the
multi-connection cost of one worker stayed at 20-37%.

## Method

`ssh gc` is a 4-vCPU EPYC-Milan VM running `abbench`; the client and server were
pinned apart with `taskset` so they do not compete for cores (server two workers
on cores 0-1, client on cores 2-3), one 1024 MiB run per sample, three blocks,
medians of three, Go frp v0.72.0 measured on the same host for reference.

## Results (MiB/s, four parallel flows unless noted)

| Shape | 1 client worker | 1 per CPU (2 here) | Go v0.72.0 |
|---|---|---|---|
| `tcp` + `tcpMux` | 818.9 | **987.6 (+21%)** | 665.7 |
| `tcp` + TLS, no mux | 854.4 | **1167.0 (+37%)** | 936.2 |
| `websocket` + TLS + `tcpMux` | 472.3 | 495.1 (+5%) | 355.3 |
| `tcp` plain (splice) | 2684.2 | 2541.8 (-5%, spread 2380-3187) | 1616.6 |
| KCP + `tcpMux`, one flow | 119.3 | 119.4 (flat) | 97.1 |
| KCP + TLS, no mux, one flow | 104.7 | 101.0 (-3.5%) | 99.4 |

With both ends at their defaults on one shared four-core host — which is what a
laptop or a single lab box sees, and the shape the shipped change produces —
four-flow `tcp`+`tcpMux` reads **1025.7 against 723.6** for the old client
default, TLS without mux **1103.5 against 828.5**, and single-stream KCP 113.1
against 121.6 (-7%) and KCP without `tcpMux` 100.4 against 106.0 (-5%) — the
only rows that pay. The full series for that host:
 `tcp` + `tcpMux` four
flows 723.6 / 949.1 / 1137.1 / 1025.7 at 1-4 client workers, `tcp` + TLS four
flows 828.5 / 1253.0 / 1338.9 / 1103.5, `websocket` + TLS + `tcpMux` four flows
453.2 / 542.3 / 450.5 / 485.8, KCP one flow 121.6 / 115.2 / 112.8 / 113.1, KCP +
TLS one flow 106.0 / 103.1 / 105.1 / 100.4. The extra client threads there fight
the server's for the same cores, which is why the pinned run above is the one the
default is based on.

## What changed

`frpc/src/main.rs` gained `default_worker_threads()` (one per
`std::thread::available_parallelism()`, mirroring `frps/src/main.rs`) and every
lane that resolves a count now uses it; `frp-core/src/config/client.rs`'s
`worker_threads` field doc and `docs/deployment.md` state both sides of the
trade-off.

## Limits

- The measurements are loopback on a 4-vCPU VM; they establish the direction and
  rough size of the effect, not a production curve.
- One-per-CPU opens as many threads as the client has cores. On a 64-core client
  that is 64 idle-able threads' stacks; nothing was measured above four.
- A single fat tunnel on a busy client still prefers one worker — keep the knob.
