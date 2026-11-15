# frp-rs against Go frp v0.72.0: the comparison, measured interleaved

**Date:** 2026-11-16
**Status:** Settled for the shapes below, on one host. Of 24 measured rows, 20
are faster, 2 are indistinguishable, and 2 are **behind** — both of them TLS
without `tcpMux` at four flows, which is a new finding rather than a retraction.

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

- the two implementations alternate **inside** every block, and the block
  orientation flips (`rs, go, go, rs` / `go, rs, rs, go`), so neither arm
  systematically occupies the middle slots;
- 3 blocks per row × 2 reps per arm per block = **6 samples per arm**;
- a row counts as *rs faster* / *go faster* only when **every** block ratio lands
  on the same side of 1.0; otherwise it is *indistinguishable* — a result, not a
  failure, and not evidence of equality either;
- the harness prints the commit, the sha256 of all four binaries, the host, and
  the per-row sample counts, so the run can be attributed and re-run.

This run: commit `1e113d9a`, host `greencloud-tyo` (4 vCPU EPYC-Milan, x86_64),
1024 MiB per rep, Go frp v0.72.0, `dropped=0`.

    RS:frps  ca47476f54e6ccd591d011ca7d347b9a380fb9e5448e3983a4eec6f90d68f3d0
    RS:frpc  78a73bbf6596a88b18b462d32e9cd1abe22c0e38eaf3b74c6420aefe61a8945e
    GO:frps  4ad311e0630cf12945041143b926f515458836e896ff93c253d43c98cf304b89
    GO:frpc  522352244a4872beaa0ad6fa136c8cc8d2e993e72bcf49f9c8a1d9683770d80e

## Result

Medians of six samples per arm; `ratio` is the median of the three block ratios,
`quotient` the ratio of the two printed medians — they differ only when an arm's
sample spread is large, and both are shown so either can be re-derived.

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

The two losses are the same shape twice: **TLS without `tcpMux`, four flows** —
0.81x on `tcp` and 0.95x on `websocket`, with block ratios of `[0.81, 0.88, 0.81]`
and `[0.90, 0.95, 0.99]`. That shape was not in the earlier matrices at all
(the `tcp` row was missing from `SHAPES`), so this is a new finding, not a
reversal of a published win. It reproduces at the larger rep size below.

## Rep-size cross-check against the README table

The README's performance table is measured at **8192 MiB per run** (four flows,
mean of three interleaved repeats), this matrix at 1024 MiB. Re-measured at the
README's rep size with the same harness (2 blocks, 4 flows):

| README row | README figure (frp-rs / Go) | this harness at 8192 MiB | verdict |
| --- | --- | --- | --- |
| `tcpMux` + TLS (default) | 562 / 399 (+41%) | 619.0 / 422.1 = 1.47x | rs faster |
| `tcpMux`, TLS off | 970 / 647 (+50%) | 795.0 / 684.2 = 1.15x | rs faster |
| no `tcpMux`, TLS on | 1298 / 956 (+36%) | 865.5 / 1029.4 = 0.84x | **go faster** |
| no `tcpMux`, TLS off | 2168 / 1650 (+31%) | 2851.9 / 1746.4 = 1.67x | rs faster |

Two rows reproduce within the expected drift (the default row is 10% higher on
both arms than when the README was written; the no-mux no-TLS row is 32% higher
for frp-rs since the splice-peel landed). **Two do not**: `tcpMux` without TLS
reads 795 against 970, and no-`tcpMux` with TLS reads 865 against 1298 — and the
latter is the row where Go leads. The README's numbers came from a different
load generator, so neither set is retracted here; the README's two no-mux rows
need re-measuring with this harness before they are quoted again (tracked in
`TODO.md`), and the TLS-without-mux deficit is the next optimisation target
rather than a documentation problem.

## What earlier rounds got wrong, and what still stands

None of these was a real regression; each was drift plus arm order. The
"earlier" column quotes where the figure was recorded, or says plainly that it
exists only in a session log.

| claim | earlier | interleaved | disposition |
| --- | --- | --- | --- |
| `tcp`, TLS off, `tcpMux` on, 4 flows | 1.06x and 0.87x, both arm-ordered, session logs only | 1.21x, rs faster | the 0.87x was drift |
| `websocket`, TLS off, no `tcpMux`, 4 flows | 1.15x and 0.93x, both arm-ordered | 0.93x, indistinguishable | neither figure resolved anything |
| `websocket`, TLS on, no `tcpMux`, 4 flows | "parity" (1.02x) in the previous matrix | 0.95x, **go faster** | the parity call was optimistic |
| `kcp`, TLS on, no `tcpMux`, 1 flow | 0.87x / 0.95x from the TLS-on-vs-Go-TLS-off mis-pairing that `2026-11-15-kcp-window-autotune.md` withdrew; that note records parity at 1.04x | 1.00x, indistinguishable | consistent with the corrected record |
| `kcp`, default (TLS + `tcpMux`), 4 flows | 1.10x and 1.11x, both arm-ordered | 1.06x, rs faster | direction holds, size shrinks |

One row moved a long way in the other direction, and the archive already tracks
why: `kcp`, TLS off, no `tcpMux`, 1 flow was recorded as 0.84x behind in
`2026-11-15-kcp-window-autotune.md`; the read-coalescing change (#626) landed
after that measurement and now reads 1.24x here (86.9 against 75.3) and 1.14x in
its own note (86.4 against 75.9 at 768 MiB). That is a shipped change, not a
measurement correction.

## Limits

- Loopback only. Nothing here speaks to loss, RTT, or pacing on a real path;
  `docs/archive/notes/2026-11-10-real-host-throughput.md` is the record for that.
- 1024 MiB per rep, except the cross-check table above (8192 MiB). Absolute
  numbers are not comparable across rep sizes; the ratios mostly are, but not
  perfectly — the no-mux TLS row reads 0.81x at 1024 MiB and 0.84x at 8192 MiB.
- KCP rows still carry 4-13% run-to-run spread even interleaved, because a flow's
  throughput depends on its own ACK timing. A 1.06x KCP row is a direction, not a
  precise number.
- `abbench` is a synthetic one-way stream: one socket per flow, no request
  patterns, so `websocket` rows measure the framing path and not HTTP semantics.
- A row that straddles 1.0 is not evidence of equality either; it is evidence
  that this harness at this rep count cannot separate the two. Raising `BLOCKS`
  settles one row at a time.
- The harness `pkill -9`s `frps`/`frpc`/`abbench` between reps: it belongs on a
  dedicated bench host.

## Raw records

The per-row lines the harness printed, verbatim, so every median above can be
checked against its sample range and block ratios:

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

And the 8192 MiB cross-check (2 blocks, 4 flows):

    tcp tls=true  mux=true  flows=4  rs=619.0  n=4 (605.0-639.7, 6%)   go=422.1  n=4 (409.1-432.7)  ratios=[1.42, 1.52]
    tcp tls=false mux=true  flows=4  rs=795.0  n=4 (769.2-812.2, 5%)   go=684.2  n=4 (671.0-721.4)  ratios=[1.13, 1.17]
    tcp tls=true  mux=false flows=4  rs=865.5  n=4 (856.8-868.1, 1%)   go=1029.4 n=4 (995.6-1053.9) ratios=[0.84, 0.84]
    tcp tls=false mux=false flows=4  rs=2851.9 n=4 (2669.1-3040.1, 13%) go=1746.4 n=4 (1575.7-1774.2) ratios=[1.79, 1.55]
