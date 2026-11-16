# frp-rs against Go frp v0.72.0: the comparison, measured interleaved

**Date:** 2026-11-16
**Status:** Settled for the shapes below, on one host, for **two configurations**.
At the defaults shipped at the time of the run — `frpc` ran one worker thread,
the Go release runs one per CPU — 20 of 24 rows are faster, 2 are indistinguishable, and 2 are behind;
both deficits are TLS without `tcpMux` at four flows. Given one client worker per
CPU, the same run leaves **no row behind** (19 faster, 5 indistinguishable) and
those two rows read 1.19x and 1.47x. The client worker count, not the TLS path,
was the difference.

## Why this note exists

Two matrices ran minutes apart on the same tree and the same host and disagreed
on the `tcpMux` rows by 15-20% (`tcp`, TLS off, `tcpMux` on, four flows: 1.06x in
one run, 0.87x in the next). Both had measured **all reps of one arm, then all
reps of the other**, so host drift landed entirely on whichever arm went second,
and single pairs of numbers were quoted to users as wins and losses. One of the
two also had a stale binary directory and a KCP row whose client pointed at the
TCP port, so a few rows were not the comparison they claimed to be.

## Method

`scripts/bench-vs-go.py`, run on a dedicated bench host:

- Arms alternate **inside** every block (`rs,go,go,rs`), and the orientation
  flips between blocks, so neither arm systematically occupies the middle slots.
- 1024 MiB per rep, 3 blocks, 6 samples per arm per row; the rep-size
  cross-check table below is 8192 MiB and 2 blocks, matching the README.
- Both implementations run the same `abbench` client and sink on loopback.
- A row is a win or a loss only when **every** block ratio lands on the same
  side of 1.0; a row that straddles prints `indistinguishable`, which is a
  result, not a failure.
- The header records the commit, the sha256 of all four binaries, the host, and
  the `rs` client worker count. The harness refuses to run if the two arms
  resolve to the same binary.
- `rs` is built from `1e113d9a`; Go is the v0.72.0 release (`frps` 4ad311e0…,
  `frpc` 52235224…).

Host: `greencloud-tyo`, AMD EPYC-Milan, 4 vCPU, x86-64.

## Table A — defaults at the time (`frpc` one worker, Go one per CPU)

Since `perf/worker-threads-default` the client also uses one worker per CPU, so
Table A describes a configuration that no longer ships; it is kept because it is
what the retraction of the earlier rows was argued from, and Table B is now the
shipped shape.

| shape | flows | frp-rs | go frp | ratio | quotient | verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| tcp, TLS off, `tcpMux` off | 1 | 2235.8 | 1025.0 | 2.06x | 2.18x | rs faster |
| tcp, TLS off, `tcpMux` on | 1 | 922.0 | 499.4 | 1.82x | 1.85x | rs faster |
| tcp, TLS on, `tcpMux` off | 1 | 717.8 | 626.2 | 1.20x | 1.15x | rs faster |
| tcp, TLS on, `tcpMux` on (default) | 1 | 585.6 | 381.3 | 1.56x | 1.54x | rs faster |
| websocket, TLS off, `tcpMux` off | 1 | 1182.5 | 693.6 | 1.66x | 1.70x | rs faster |
| websocket, TLS on, `tcpMux` off | 1 | 677.5 | 534.7 | 1.28x | 1.27x | rs faster |
| websocket, TLS on, `tcpMux` on (default) | 1 | 459.6 | 305.5 | 1.53x | 1.50x | rs faster |
| kcp, TLS off, `tcpMux` off | 1 | 86.9 | 75.3 | 1.24x | 1.15x | rs faster |
| kcp, TLS off, `tcpMux` on | 1 | 123.7 | 111.3 | 1.11x | 1.11x | rs faster |
| kcp, TLS on, `tcpMux` off | 1 | 105.7 | 106.8 | 1.00x | 0.99x | indistinguishable |
| kcp, TLS on, `tcpMux` on (default) | 1 | 116.8 | 109.5 | 1.07x | 1.07x | rs faster |
| quic (mux off, TLS on) | 1 | 241.5 | 208.5 | 1.16x | 1.16x | rs faster |
| tcp, TLS off, `tcpMux` off | 4 | 2583.2 | 1599.3 | 1.62x | 1.62x | rs faster |
| tcp, TLS off, `tcpMux` on | 4 | 781.5 | 663.5 | 1.21x | 1.18x | rs faster |
| tcp, TLS on, `tcpMux` off | 4 | 855.4 | 1036.6 | 0.81x | 0.83x | **go faster** |
| tcp, TLS on, `tcpMux` on (default) | 4 | 620.8 | 431.0 | 1.45x | 1.44x | rs faster |
| websocket, TLS off, `tcpMux` off | 4 | 1184.2 | 1280.0 | 0.93x | 0.93x | indistinguishable |
| websocket, TLS on, `tcpMux` off | 4 | 840.0 | 882.2 | 0.95x | 0.95x | **go faster** |
| websocket, TLS on, `tcpMux` on (default) | 4 | 477.0 | 345.4 | 1.37x | 1.38x | rs faster |
| kcp, TLS off, `tcpMux` off | 4 | 103.2 | 82.5 | 1.28x | 1.25x | rs faster |
| kcp, TLS off, `tcpMux` on | 4 | 127.3 | 111.8 | 1.13x | 1.14x | rs faster |
| kcp, TLS on, `tcpMux` off | 4 | 109.2 | 88.3 | 1.27x | 1.24x | rs faster |
| kcp, TLS on, `tcpMux` on (default) | 4 | 120.0 | 112.4 | 1.06x | 1.07x | rs faster |
| quic (mux off, TLS on) | 4 | 284.6 | 211.3 | 1.35x | 1.35x | rs faster |

`ratio` is the median of the three block ratios; `quotient` is the ratio of the
two printed medians. They differ where the medians are noisy, and both are shown
so either can be re-derived.

## Table B — equal parallelism (`WORKERS=4`, one client worker per CPU)

Same script, same host, same binaries; the only change is
`transport.workerThreads = 4` in the `rs` client config (`WORKERS=4`). The Go
arm already runs one thread per CPU.

| shape | flows | frp-rs | go frp | ratio | quotient | verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| tcp, TLS off, `tcpMux` off | 1 | 2247.8 | 1067.2 | 2.20x | 2.11x | rs faster |
| tcp, TLS off, `tcpMux` on | 1 | 788.1 | 532.9 | 1.54x | 1.48x | rs faster |
| tcp, TLS on, `tcpMux` off | 1 | 750.5 | 610.0 | 1.30x | 1.23x | rs faster |
| tcp, TLS on, `tcpMux` on (default) | 1 | 572.2 | 376.1 | 1.52x | 1.52x | rs faster |
| websocket, TLS off, `tcpMux` off | 1 | 1173.6 | 731.2 | 1.53x | 1.61x | rs faster |
| websocket, TLS on, `tcpMux` off | 1 | 642.0 | 496.8 | 1.26x | 1.29x | rs faster |
| websocket, TLS on, `tcpMux` on (default) | 1 | 421.5 | 305.7 | 0.84x | 1.38x | indistinguishable |
| kcp, TLS off, `tcpMux` off | 1 | 83.3 | 74.1 | 1.12x | 1.12x | rs faster |
| kcp, TLS off, `tcpMux` on | 1 | 116.2 | 110.0 | 1.07x | 1.06x | rs faster |
| kcp, TLS on, `tcpMux` off | 1 | 105.2 | 106.0 | 1.00x | 0.99x | indistinguishable |
| kcp, TLS on, `tcpMux` on (default) | 1 | 107.1 | 104.5 | 1.03x | 1.03x | indistinguishable |
| quic (mux off, TLS on) | 1 | 231.1 | 220.8 | 1.05x | 1.05x | rs faster |
| tcp, TLS off, `tcpMux` off | 4 | 3074.6 | 1617.3 | 1.89x | 1.90x | rs faster |
| tcp, TLS off, `tcpMux` on | 4 | 1069.8 | 789.8 | 1.41x | 1.35x | rs faster |
| **tcp, TLS on, `tcpMux` off** | 4 | **1293.3** | **1071.0** | **1.19x** | 1.21x | **rs faster** |
| tcp, TLS on, `tcpMux` on (default) | 4 | 564.1 | 443.5 | 1.26x | 1.27x | rs faster |
| websocket, TLS off, `tcpMux` off | 4 | 1851.0 | 1270.8 | 1.38x | 1.46x | rs faster |
| **websocket, TLS on, `tcpMux` off** | 4 | **1331.1** | **881.5** | **1.47x** | 1.51x | **rs faster** |
| websocket, TLS on, `tcpMux` on (default) | 4 | 486.1 | 369.2 | 1.31x | 1.32x | indistinguishable |
| kcp, TLS off, `tcpMux` off | 4 | 104.8 | 84.4 | 1.25x | 1.24x | rs faster |
| kcp, TLS off, `tcpMux` on | 4 | 125.0 | 118.6 | 1.06x | 1.05x | rs faster |
| kcp, TLS on, `tcpMux` off | 4 | 107.8 | 89.9 | 1.19x | 1.20x | rs faster |
| kcp, TLS on, `tcpMux` on (default) | 4 | 113.0 | 116.2 | 0.97x | 0.97x | indistinguishable |
| quic (mux off, TLS on) | 4 | 228.9 | 219.2 | 1.05x | 1.04x | rs faster |

The two rows that lose under Table A's defaults are bolded: at four client
workers they are 1.19x and 1.47x.

## Why the two tables differ: the client worker count

`frpc` shipped `transport.workerThreads = 1` at the time of the run (one client
thread regardless of CPU count; `frps` takes one per CPU). The Go release runs `GOMAXPROCS` threads. Table
A therefore compares one client thread against four, which costs nothing while a
tunnel is a single pipeline (`tcpMux` on, or one flow) and costs a lot when four
independent connections share one thread.

Measured directly, `tcp`, TLS on, `tcpMux` off, four flows, 1024 MiB, same host
and same binaries:

| `frpc` worker threads | frp-rs MiB/s | client CPU | note |
| ---: | ---: | ---: | --- |
| 1 (shipped) | 860.8 / 890.0 / 906.0 | 0.92-0.96 cores | Table A's 855.4 |
| 2 | 1267.3 (n=4, 1170.1-1371.4) | not sampled | already at the plateau |
| 3 | 1239.8 (n=4, 1201.6-1403.2) | not sampled | |
| 4 | 1292.0 / 1539.4 | 1.40-1.52 cores | Table B's 1293.3 |
| Go (GOMAXPROCS 4) | 1022.8 / 1030.3 | 1.52-1.55 cores | reference |

The effect is a step at the first extra thread and then flat: two workers already
reach 1267 MiB/s, so the missing middle is not a gradual curve and "four" is not
a tuned endpoint — any value ≥ 2 behaves like four on this shape.

Two independent readings agree that frp-rs was not CPU-bound under the shipped
default: at one worker it moved 861-906 MiB/s using **under one core**, while Go
moved 1030 using **one and a half**. The single-threaded client was the limit,
not the TLS path, the record framing, or a per-connection cost.

This also explains the shape of Table A's four-flow column. The four-flow to
one-flow scaling factor is 0.85-1.24 for frp-rs in every shape and 1.13-1.85 for
Go on the `tcp` and `websocket` shapes (Go's `kcp` and `quic` rows barely scale
at all, 0.83-1.10). The identity
`quotient(4 flows) = quotient(1 flow) × scale_rs / scale_go` holds of course —
it is the same four medians rearranged, so it shows how the four-flow ratio
decomposes rather than adding evidence. The decomposition does reproduce the four
`tcp` shapes from their one-flow ratios to within 0.02%, which is all it claims.
Under Table A the whole four-flow column is "one client thread against four".

The two archive notes that had already recorded this effect and were not
connected to this matrix until the review of this note asked about parallelism:
`2026-11-13-splice-wrapper-peel.md` measured eight independent sessions without
`tcpMux` at 1227/1201 MiB/s on one worker, 2266/2465 after the peel, and
2105/2548 → 2867/3122 at four workers; `2026-11-12-worker-thread-count.md`
measured four separate `tcp` sessions at 2362/2283 against 2470/2811. Both were
read at the time as "one worker is fine for many sessions"; at one worker on this
shape the cap is real and the earlier readings were taken on shapes where one
thread was not the limit.

## Rep-size cross-check against the README table

The README's performance table is measured at **8192 MiB per run**, four flows,
mean of three interleaved repeats. Re-measured at the same rep size with this
harness (2 blocks, 4 flows), under both worker settings:

| README row | README (frp-rs / Go) | shipped defaults | `WORKERS=4` | verdict at `WORKERS=4` |
| --- | --- | --- | --- | --- |
| `tcpMux` + TLS (default) | 562 / 399 (+41%) | 619.0 / 422.1 | 576.3 / 426.4 | rs faster |
| `tcpMux`, TLS off | 970 / 647 (+50%) | 795.0 / 684.2 | 1022.3 / 675.8 | rs faster |
| no `tcpMux`, TLS on | 1298 / 956 (+36%) | 865.5 / 1029.4 | **1314.8 / 1046.5** | rs faster |
| no `tcpMux`, TLS off | 2168 / 1650 (+31%) | 2851.9 / 1746.4 | 3104.9 / 1636.3 | rs faster |

The cells are the two medians; their ratios are 1.37x, 1.15x/1.50x, 0.84x/1.26x
and 1.67x/1.88x respectively (median block ratios; the raw lines below carry the
per-block ratios and the quotient of the medians, which differ by up to 2% where
the medians are noisy). At the README's rep size with equal client parallelism
**three of the four rows land within 10%** of the published figure (default
+2.5%/+6.9%, `tcpMux`-off no-TLS +5.4%/+4.5%, no-`tcpMux` TLS-on +1.3%/+9.5%)
and the fourth is `no tcpMux`, TLS off: +43.2% on the frp-rs side (its own gain
from the splice peel) and −0.8% on Go. **The README is not retracted and needed
no re-measurement: it was right.** What was wrong was this harness's earlier
reading of it, which used a 1024 MiB rep and a single-threaded client.
`README.md:166` states its own method ("two repeats"), which cannot resolve 10% —
that limitation is real, but the numbers themselves stand.

An earlier draft of this note claimed the README used "a different load
generator". That was wrong: the README rows came from `abbench` as well
(`scripts/bench-vs-go.py`'s `BENCH` default, and the archive note that recorded
them, `2026-11-10-bridge-buffer-64k-default.md`, §6 names the same client).

## What earlier rounds got wrong, and what still stands

Each "earlier" cell says where the figure was recorded, or states that it exists
only in a session log.

| claim | earlier | interleaved | disposition |
| --- | --- | --- | --- |
| `tcp`, TLS off, `tcpMux` on, 4 flows | 1.06x and 0.87x, both arm-ordered, session logs only | 1.21x, rs faster | the 0.87x was drift |
| `websocket`, TLS off, no `tcpMux`, 4 flows | 1.15x and 0.93x, both arm-ordered, session logs only | 0.93x, indistinguishable | neither figure resolved anything |
| `websocket`, TLS on, no `tcpMux`, 4 flows | "parity" in the standing summary at `docs/history/development-log.md:189`; the 1.02x itself is session-log only | 0.95x under shipped defaults, 1.47x at equal parallelism | the parity call was optimistic, and the loss was the worker count |
| `kcp`, TLS on, no `tcpMux`, 1 flow | the withdrawn TLS-on-vs-Go-TLS-off pairing read 0.9x to 1.4x (`2026-11-15-kcp-window-autotune.md`); the corrected record there is parity at 1.04x | 1.00x, indistinguishable | consistent with the corrected record |
| `kcp`, default (TLS + `tcpMux`), 4 flows | 1.10x and 1.11x, both arm-ordered, session logs only | 1.06x, rs faster | direction holds, size shrinks |

One row moved a long way in the other direction, and the archive already tracks
why: `kcp`, TLS off, no `tcpMux`, 1 flow was recorded as 0.84x behind in
`2026-11-15-kcp-window-autotune.md`; the read-coalescing change recorded in
`2026-11-15-kcp-read-coalescing.md` landed after that measurement and now reads
1.24x here (86.9 against 75.3) and 1.14x in its own note (86.4 against 75.9 at
768 MiB). That is a shipped change, not a measurement correction.

## Limits

- Loopback only. Nothing here speaks to loss, RTT, or pacing on a real path;
  `docs/archive/notes/2026-11-10-real-host-throughput.md` is the record for that.
- 1024 MiB per rep, except the cross-check table (8192 MiB). Absolute numbers are
  not comparable across rep sizes; the ratios mostly are — the no-mux TLS row
  reads 0.81x at 1024 MiB and 0.84x at 8192 MiB under the same worker setting.
- The rows are noisy: `rs` sample spread reaches 49% in Table A (`tcp` no-mux
  no-TLS, one flow) and 86% in Table B (the stalled sample below); `go` spread
  reaches 54%. Two Go samples in particular decide two rows — 44.1 MiB/s in
  `kcp` TLS-off no-mux (median 75.3) and 54.4 MiB/s in `kcp` TLS-on no-mux
  (median 106.8) — so those two rows' verdicts are the softest in the table and
  should be raised to more blocks before they are quoted.
- Two Table B rows carry a single catastrophically low `rs` sample: `websocket`,
  TLS on, `tcpMux` on at one and four flows bottomed at 87.2 and 102.2 MiB/s
  against medians of 421.5 and 486.1. Re-run in isolation at 12 samples the same
  shape stalled once — the two processes sat at **zero CPU for 7.5 s** and then
  finished at 92.7 MiB/s — so this is an intermittent stall in that path, not
  ordinary noise; it is tracked in `TODO.md` and both rows are counted as
  `indistinguishable`, which is the honest verdict but understates frp-rs when
  the stall does not fire.
- A row that straddles 1.0 is not evidence of equality either; it is evidence
  that this harness at this rep count cannot separate the two. Raising `BLOCKS`
  settles one row at a time.
- The client worker count changes every multi-flow row. Table A is what a default
  deployment gets; Table B is what the same code does with the same parallelism
  as the Go release. Neither is "the" number — quote which one you mean.
- The harness `pkill -9`s `frps`/`frpc`/`abbench` between reps: it belongs on a
  dedicated bench host.

## Raw records

The per-row lines the harness printed, reformatted for width. Table A's block was
written before the harness emitted `quotient=`, so those lines carry only the
three block ratios; Table B's and the `WORKERS=4` cross-check lines carry both.
The verdicts are not part of these lines — they are the `[verdict]` at the end of
the corresponding SUMMARY line in the harness output, repeated in the tables
above. Table A, shipped defaults:

    tcp tls=false mux=false flows=1  rs=2235.8 n=6 (1774.9-2872.2, 49%)  go=1025.0 n=6 (901.1-1194.0)  ratios=[1.87, 2.06, 2.60]
    tcp tls=false mux=true  flows=1  rs=922.0  n=6 (798.4-982.3, 20%)   go=499.4  n=6 (467.7-529.2)   ratios=[1.82, 1.85, 1.78]
    tcp tls=true  mux=false flows=1  rs=717.8  n=6 (689.8-846.5, 22%)   go=626.2  n=6 (564.6-646.9)   ratios=[1.23, 1.20, 1.15]
    tcp tls=true  mux=true  flows=1  rs=585.6  n=6 (549.6-609.9, 10%)   go=381.3  n=6 (363.6-394.5)   ratios=[1.56, 1.48, 1.58]
    websocket tls=false mux=false flows=1  rs=1182.5 n=6 (1010.8-1310.3, 25%) go=693.6 n=6 (657.8-782.5) ratios=[1.55, 1.66, 1.74]
    websocket tls=true  mux=false flows=1  rs=677.5  n=6 (576.5-718.3, 21%)  go=534.7 n=6 (460.4-557.8) ratios=[1.16, 1.30, 1.28]
    websocket tls=true  mux=true  flows=1  rs=459.6  n=6 (431.8-497.2, 14%)  go=305.5 n=6 (284.1-312.4) ratios=[1.49, 1.53, 1.59]
    kcp tls=false mux=false flows=1  rs=86.9   n=6 (83.2-94.1, 13%)     go=75.3   n=6 (44.1-76.9)    ratios=[1.24, 1.41, 1.17]
    kcp tls=false mux=true  flows=1  rs=123.7  n=6 (120.1-125.9, 5%)    go=111.3  n=6 (107.4-113.5) ratios=[1.13, 1.10, 1.11]
    kcp tls=true  mux=false flows=1  rs=105.7  n=6 (102.0-108.7, 6%)    go=106.8  n=6 (54.4-111.8)  ratios=[0.98, 1.29, 1.00]
    kcp tls=true  mux=true  flows=1  rs=116.8  n=6 (115.8-118.4, 2%)    go=109.5  n=6 (105.2-113.5) ratios=[1.07, 1.08, 1.05]
    quic tls=true mux=false flows=1  rs=241.5  n=6 (231.3-253.6, 9%)    go=208.5  n=6 (197.0-212.5) ratios=[1.15, 1.16, 1.21]
    tcp tls=false mux=false flows=4  rs=2583.2 n=6 (2392.9-2772.5, 15%)  go=1599.3 n=6 (1394.4-1714.8) ratios=[1.62, 1.68, 1.61]
    tcp tls=false mux=true  flows=4  rs=781.5  n=6 (737.1-800.0, 8%)    go=663.5  n=6 (619.6-720.6) ratios=[1.08, 1.24, 1.21]
    tcp tls=true  mux=false flows=4  rs=855.4  n=6 (786.4-937.4, 18%)   go=1036.6 n=6 (936.8-1114.5) ratios=[0.81, 0.88, 0.81]
    tcp tls=true  mux=true  flows=4  rs=620.8  n=6 (599.2-645.9, 8%)    go=431.0  n=6 (396.3-455.5) ratios=[1.43, 1.45, 1.47]
    websocket tls=false mux=false flows=4  rs=1184.2 n=6 (1153.6-1214.0, 5%) go=1280.0 n=6 (1143.2-1410.9) ratios=[0.93, 1.03, 0.85]
    websocket tls=true  mux=false flows=4  rs=840.0  n=6 (726.0-910.6, 22%)  go=882.2  n=6 (813.1-998.9) ratios=[0.90, 0.95, 0.99]
    websocket tls=true  mux=true  flows=4  rs=477.0  n=6 (466.9-500.6, 7%)   go=345.4  n=6 (319.3-382.7) ratios=[1.29, 1.37, 1.48]
    kcp tls=false mux=false flows=4  rs=103.2  n=6 (98.5-108.1, 9%)     go=82.5   n=6 (77.2-84.5)   ratios=[1.21, 1.28, 1.31]
    kcp tls=false mux=true  flows=4  rs=127.3  n=6 (116.8-129.7, 10%)   go=111.8  n=6 (109.7-115.3) ratios=[1.15, 1.09, 1.13]
    kcp tls=true  mux=false flows=4  rs=109.2  n=6 (103.5-113.8, 9%)    go=88.3   n=6 (85.4-89.9)   ratios=[1.27, 1.20, 1.27]
    kcp tls=true  mux=true  flows=4  rs=120.0  n=6 (116.7-121.0, 4%)    go=112.4  n=6 (106.8-117.2) ratios=[1.08, 1.06, 1.04]
    quic tls=true mux=false flows=4  rs=284.6  n=6 (267.4-292.4, 9%)    go=211.3  n=6 (196.2-232.3) ratios=[1.35, 1.36, 1.28]

Table B, `WORKERS=4`:

    tcp tls=false mux=false flows=1  rs=2247.8 n=6 (1873.5-2677.0, 36%)  go=1067.2 n=6 (914.0-1195.2, 26%)  quotient=2.11 ratios=[2.20, 2.37, 1.88]
    tcp tls=false mux=true  flows=1  rs=788.1  n=6 (628.8-938.4, 39%)   go=532.9  n=6 (508.4-557.5, 9%)    quotient=1.48 ratios=[1.58, 1.31, 1.54]
    tcp tls=true  mux=false flows=1  rs=750.5  n=6 (665.8-832.2, 22%)   go=610.0  n=6 (550.7-618.6, 11%)   quotient=1.23 ratios=[1.15, 1.30, 1.33]
    tcp tls=true  mux=true  flows=1  rs=572.2  n=6 (566.4-578.0, 2%)    go=376.1  n=6 (353.7-397.5, 12%)   quotient=1.52 ratios=[1.51, 1.52, 1.53]
    websocket tls=false mux=false flows=1  rs=1173.6 n=6 (1032.1-1304.4, 23%) go=731.2 n=6 (696.7-757.2, 8%) quotient=1.61 ratios=[1.53, 1.76, 1.50]
    websocket tls=true  mux=false flows=1  rs=642.0  n=6 (570.5-796.6, 35%)  go=496.8 n=6 (386.5-537.9, 30%) quotient=1.29 ratios=[1.64, 1.26, 1.22]
    websocket tls=true  mux=true  flows=1  rs=421.5  n=6 (87.2-448.2, 86%)   go=305.7 n=6 (293.0-318.8, 8%) quotient=1.38 ratios=[0.83, 1.47, 0.84]
    kcp tls=false mux=false flows=1  rs=83.3   n=6 (80.6-85.3, 6%)     go=74.1   n=6 (73.6-74.7, 1%)    quotient=1.12 ratios=[1.10, 1.12, 1.15]
    kcp tls=false mux=true  flows=1  rs=116.2  n=6 (110.6-121.6, 9%)   go=110.0  n=6 (105.9-112.4, 6%)  quotient=1.06 ratios=[1.07, 1.04, 1.07]
    kcp tls=true  mux=false flows=1  rs=105.2  n=6 (102.0-107.3, 5%)   go=106.0  n=6 (100.1-109.1, 8%)  quotient=0.99 ratios=[1.00, 1.00, 0.98]
    kcp tls=true  mux=true  flows=1  rs=107.1  n=6 (102.9-109.0, 6%)   go=104.5  n=6 (103.9-111.0, 7%)  quotient=1.03 ratios=[0.96, 1.03, 1.03]
    quic tls=true mux=false flows=1  rs=231.1  n=6 (226.8-240.9, 6%)   go=220.8  n=6 (199.1-232.7, 15%)  quotient=1.05 ratios=[1.05, 1.04, 1.09]
    tcp tls=false mux=false flows=4  rs=3074.6 n=6 (2602.5-3241.8, 21%) go=1617.3 n=6 (1512.7-1779.1, 16%) quotient=1.90 ratios=[1.92, 1.71, 1.89]
    tcp tls=false mux=true  flows=4  rs=1069.8 n=6 (985.4-1139.6, 14%)  go=789.8  n=6 (672.6-823.7, 19%)   quotient=1.35 ratios=[1.41, 1.28, 1.46]
    tcp tls=true  mux=false flows=4  rs=1293.3 n=6 (1225.7-1340.5, 9%)  go=1071.0 n=6 (933.5-1118.6, 17%)  quotient=1.21 ratios=[1.36, 1.19, 1.16]
    tcp tls=true  mux=true  flows=4  rs=564.1  n=6 (527.3-596.6, 12%)   go=443.5  n=6 (418.1-478.7, 14%)   quotient=1.27 ratios=[1.26, 1.24, 1.29]
    websocket tls=false mux=false flows=4  rs=1851.0 n=6 (1706.2-2143.8, 24%) go=1270.8 n=6 (1236.6-1400.3, 13%) quotient=1.46 ratios=[1.38, 1.56, 1.38]
    websocket tls=true  mux=false flows=4  rs=1331.1 n=6 (1186.1-1394.7, 16%) go=881.5 n=6 (800.9-952.0, 17%) quotient=1.51 ratios=[1.49, 1.46, 1.47]
    websocket tls=true  mux=true  flows=4  rs=486.1  n=6 (102.2-515.2, 85%)   go=369.2 n=6 (316.0-404.2, 24%) quotient=1.32 ratios=[1.39, 1.31, 0.78]
    kcp tls=false mux=false flows=4  rs=104.8  n=6 (99.4-110.8, 11%)   go=84.4   n=6 (80.1-85.6, 7%)    quotient=1.24 ratios=[1.25, 1.26, 1.25]
    kcp tls=false mux=true  flows=4  rs=125.0  n=6 (118.4-126.7, 7%)   go=118.6  n=6 (112.1-121.1, 8%)  quotient=1.05 ratios=[1.03, 1.06, 1.07]
    kcp tls=true  mux=false flows=4  rs=107.8  n=6 (102.3-111.9, 9%)   go=89.9   n=6 (87.7-91.3, 4%)    quotient=1.20 ratios=[1.24, 1.17, 1.19]
    kcp tls=true  mux=true  flows=4  rs=113.0  n=6 (109.6-114.7, 5%)   go=116.2  n=6 (112.7-118.2, 5%)  quotient=0.97 ratios=[1.00, 0.95, 0.97]
    quic tls=true mux=false flows=4  rs=228.9  n=6 (224.7-237.4, 6%)   go=219.2  n=6 (210.2-226.9, 8%)  quotient=1.04 ratios=[1.05, 1.04, 1.06]

The 8192 MiB cross-check, both worker settings (2 blocks, 4 flows):

    shipped defaults
    tcp tls=true  mux=true  flows=4  rs=619.0  n=4 (605.0-639.7, 6%)   go=422.1  n=4 (409.1-432.7)  ratios=[1.42, 1.52]
    tcp tls=false mux=true  flows=4  rs=795.0  n=4 (769.2-812.2, 5%)   go=684.2  n=4 (671.0-721.4)  ratios=[1.13, 1.17]
    tcp tls=true  mux=false flows=4  rs=865.5  n=4 (856.8-868.1, 1%)   go=1029.4 n=4 (995.6-1053.9) ratios=[0.84, 0.84]

    WORKERS=4
    tcp tls=true  mux=true  flows=4  rs=576.3  n=4 (574.6-601.3, 5%)   go=426.4  n=4 (413.3-431.6, 4%)  quotient=1.35 ratios=[1.38, 1.36]
    tcp tls=false mux=true  flows=4  rs=1022.3 n=4 (979.2-1034.5, 5%)  go=675.8  n=4 (663.8-688.4, 4%)  quotient=1.51 ratios=[1.49, 1.51]
    tcp tls=true  mux=false flows=4  rs=1314.8 n=4 (1290.1-1389.3, 8%) go=1046.5 n=4 (1044.1-1053.3, 1%) quotient=1.26 ratios=[1.23, 1.30]
    tcp tls=false mux=false flows=4  rs=3104.9 n=4 (2979.9-3269.3, 9%) go=1636.3 n=4 (1596.8-1757.6, 10%) quotient=1.90 ratios=[1.91, 1.85]
