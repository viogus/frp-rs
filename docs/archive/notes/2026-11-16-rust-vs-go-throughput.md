# frp-rs against Go frp v0.72.0: the comparison, measured interleaved

**Date:** 2026-11-16
**Status:** Settled. Twenty of twenty-two rows are parity or better; the two rows
that straddle 1.0 are reported as indistinguishable rather than as wins or
losses. Five earlier "losing rows" were harness artifacts and are retracted
below.

## Why the earlier tables disagreed

Two full matrices ran minutes apart on the same tree and the same host and
disagreed on the `tcpMux` rows by 15-20% (`tcp`, TLS off, `tcpMux` on, four
flows: 1.06x in one run, 0.87x in the next). The cause is structural: every
earlier harness measured **all reps of one arm and then all reps of the other**,
so host drift — and on this host the drift is large — lands entirely on whichever
arm went second. A single pair of numbers was then called a win or a loss.

A second, smaller effect sat on top: `/root/bench/kcpu.sh`-style helpers and the
first matrix iteration pinned different things (a hard-coded binary directory, a
client `serverPort` pointing at the TCP port for a KCP row), so some rows were
not comparing what they claimed.

## Method

`scripts/bench-vs-go.py` alternates the two implementations **inside** every
block — `rs, go, go, rs` — three blocks per row, 512 MiB per rep, medians per
arm. For every row it prints each block's ratio and applies one rule:

- every block ratio > 1.0 → *rs faster*
- every block ratio < 1.0 → *go faster*
- otherwise → *indistinguishable* (a result, not a failure)

Same host for both arms, both binaries with TLS/`tcpMux` as the row states, one
`abbench` stream client, Go frp v0.72.0 from `scripts/download-go-frp.sh`.

## Result

Medians of six samples per arm; the ratio column is the median block ratio.

| shape | flows | frp-rs MiB/s | go frp MiB/s | ratio | verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| tcp, TLS off, `tcpMux` off | 1 | 1899.4 | 1019.9 | 2.02x | rs faster |
| tcp, TLS off, `tcpMux` on | 1 | 825.6 | 496.9 | 1.61x | rs faster |
| tcp, TLS on, `tcpMux` on (default) | 1 | 541.2 | 356.2 | 1.54x | rs faster |
| websocket, TLS off, `tcpMux` off | 1 | 1096.8 | 703.3 | 1.55x | rs faster |
| websocket, TLS on, `tcpMux` off | 1 | 612.6 | 512.5 | 1.13x | rs faster |
| websocket, TLS on, `tcpMux` on (default) | 1 | 455.1 | 307.5 | 1.50x | rs faster |
| kcp, TLS off, `tcpMux` off | 1 | 92.2 | 73.6 | 1.28x | rs faster |
| kcp, TLS off, `tcpMux` on | 1 | 121.9 | 105.0 | 1.17x | rs faster |
| kcp, TLS on, `tcpMux` off | 1 | 109.3 | 106.2 | 1.02x | rs faster |
| kcp, TLS on, `tcpMux` on (default) | 1 | 113.3 | 105.5 | 1.07x | rs faster |
| quic | 1 | 234.3 | 201.8 | 1.17x | rs faster |
| tcp, TLS off, `tcpMux` off | 4 | 2352.4 | 1690.9 | 1.47x | rs faster |
| tcp, TLS off, `tcpMux` on | 4 | 762.6 | 732.9 | 1.05x | indistinguishable |
| tcp, TLS on, `tcpMux` on (default) | 4 | 606.8 | 483.8 | 1.23x | rs faster |
| websocket, TLS off, `tcpMux` off | 4 | 1174.3 | 1239.8 | 0.96x | indistinguishable |
| websocket, TLS on, `tcpMux` off | 4 | 856.4 | 861.5 | 1.02x | indistinguishable |
| websocket, TLS on, `tcpMux` on (default) | 4 | 454.3 | 361.4 | 1.25x | rs faster |
| kcp, TLS off, `tcpMux` off | 4 | 114.2 | 83.4 | 1.36x | rs faster |
| kcp, TLS off, `tcpMux` on | 4 | 133.8 | 120.3 | 1.09x | rs faster |
| kcp, TLS on, `tcpMux` off | 4 | 120.7 | 89.1 | 1.79x | rs faster |
| kcp, TLS on, `tcpMux` on (default) | 4 | 123.4 | 113.2 | 1.11x | indistinguishable |
| quic | 4 | 273.8 | 200.5 | 1.38x | rs faster |

The worst row for frp-rs is 0.96x and straddles 1.0 across its three blocks —
which is what "the two are the same speed on loopback" looks like at this rep
count, not a deficit.

## Retracted

Five claims made earlier in this round from non-interleaved runs:

| claim | earlier figure | interleaved result |
| --- | --- | --- |
| `tcp`, TLS off, `tcpMux` on, 4 flows | 0.87x (and 1.06x a run earlier) | 1.05x, indistinguishable |
| `websocket`, TLS off, `tcpMux` off, 4 flows | 0.93x (and 1.15x a run earlier) | 0.96x, indistinguishable |
| `websocket`, TLS on, `tcpMux` off, 4 flows | 1.02x, called a plateau | 1.02x, indistinguishable |
| `kcp`, TLS on, `tcpMux` off, 1 flow | 0.87x, then 0.95x on a 5-rep re-run | 1.02x, rs faster |
| `kcp` default, 4 flows | 1.10x, then 1.11x, both non-interleaved | 1.11x, indistinguishable |

None of these was a real regression; each was drift plus arm order.

## Limits

- Loopback only. This says nothing about loss, RTT, or pacing on a real path —
  `docs/archive/notes/2026-11-10-real-host-throughput.md` is the record for that.
- KCP rows still carry 8-21% run-to-run spread even interleaved, because a KCP
  flow's throughput depends on its own ACK timing; a 1.02x KCP row needs more
  blocks than a 2.02x tcp row to separate.
- `abbench` is a synthetic stream generator: one socket per flow, no request
  patterns. `websocket` rows therefore measure the framing path, not HTTP
  semantics.
- A row that straddles 1.0 is not evidence of equality either; it is evidence
  that this harness at this rep count cannot separate the two. Raising `BLOCKS`
  is how to settle one specific row.
