# KCP without TLS: the residue is write granularity, not TLS

**Status:** investigation complete, follow-up open. Entry point: the `TODO.md`
item "Raw KCP with TLS off runs about a fifth slower than the same KCP engine
with TLS on".

`docs/archive/notes/2026-11-15-kcp-read-coalescing.md` closed most of the bare
KCP deficit and left a residue it called **unexplained**: a 1-flow,
`tcpMux = false`, TLS-off row at 86.4 MiB/s against 110.2 for the same engine
with TLS on. This note re-measures the shape on `4ba46c3c` and finds that

- the deficit is **5-7 %** on this harness, not a fifth, and the sender pool is
  not what closed the rest (it is neutral on this shape, inside ±3 %), and
- what is left tracks **the size of the writes the application hands KCP**, not
  TLS: cap the writer at 16 KiB and the naked row reaches the TLS row.

## Method

Host `gc` (greencloud-tyo, 4 vCPU EPYC-Milan), loopback, both binaries
`--release` at `4ba46c3c` (i.e. with the read coalescing **and** the sender
pool). Shape: `transport.protocol = "kcp"`, `tcpMux = false` on both sides, one
proxied TCP flow, one 64 KiB-per-`sendall` client into a `recv`-only sink,
1 s unmeasured warm-up then 768 MiB timed. Arms interleaved; `senderThread`
flipped per arm; `CHUNK` sets the client's write size. Harness
`scripts/kcp-tls-ab.sh` (embedded `sink.py`/`client.py`), run by hand on that
host.

## Result

MiB/s, per-arm mean over 2-4 interleaved reps (medians in brackets).

| write chunk | TLS off, pool off | TLS off, pool on | TLS on, pool off | TLS on, pool on |
| --- | --- | --- | --- | --- |
| 64 KiB | 104.8 (104.8) | 99.8-101.1 (99.8-102.7) | 111.3 (111.3) | 111.1-112.7 (111.7-112.7) |
| 16 KiB | 102.6-111.9 (107.2-111.9) | 107.4 (107.4-107.9) | 108.5 (108.1) | 105.1-109.8 (103.2-109.8) |

Reading it:

- At the 64 KiB write size the naked row sits **6-11 %** under its TLS shape in
  the runs with the larger samples, and the pool neither creates nor removes the
  gap: pooled sessions gave 0.910x (n=4) and 0.950x (n=3), inline sessions
  0.943x (n=4) and 1.040x (n=2 — the one run of five where the naked arm came
  out ahead, and the one with the fewest reps).
- Cut the writer to 16 KiB and the same naked row lands **on** the TLS row:
  medians 107.2-107.9 against 103.2-108.1, i.e. inside the host's per-arm spread.
- The TLS arm is indifferent to the client's write size — 111.3 at 64 KiB and
  108.1-109.8 at 16 KiB — because rustls already re-blocks whatever it is given
  into ~16 KiB records before KCP ever sees it. That is the whole asymmetry: the
  TLS arm's KCP writes are 16 KiB by construction, the naked arm's are whatever
  the bridge read.

## What the earlier 24 MiB/s was

Two granularities, not one. The 2026-11-15 round fixed the **read** side
(coalesced reads: 63.0 → 86.4 on the nine-pair mean of that shape). On
`4ba46c3c` the same shape reads 100-105. **What closed that 86 → 102 stretch is
not established here**: the sender pool is the only candidate this file can
test, and flipping it moves the naked arm by less than the spread (101.1 pooled
against 104.5 inline, n=4 each) — so the pool is not the credit. It is also
possible the 2026-11-15 harness wrote smaller chunks than 64 KiB (its write size
is not recorded), which by this note's own finding would have held its row down.

The 5-7 % that remains on the 64 KiB write size is the **write** side: KCP
fragments an application write into MTU-sized segments and flushes them as one
burst, so a 64 KiB write becomes a ~48-datagram burst per flush while a 16 KiB
record becomes ~12.

This does not contradict the flush-model round's conclusion that "the write side
is already the right shape" — that conclusion is about *per-segment* cost
(one datagram per segment either way). What changes with the write size is the
burst, and the burst is what the receiver's socket buffer sees.

## What is not proven

The drop hypothesis is plausible but **not** demonstrated. `/proc/net/snmp`'s
`Udp: InErrors` was recorded per arm; it bounces between 72 and 13 130 across
identical arms (teardown traffic from a just-killed KCP session lands in the
same counter), so it cannot carry the claim. The claim rests on the chunk-size
sensitivity alone, which is reproducible in both directions.

## Follow-up

The obvious lever is to hand KCP at most one record's worth of bytes per write —
cap the bridge's write to the KCP stream at 16 KiB instead of writing the whole
read chunk. That is one change to the bridge, and this harness measures it
directly: rebuild, rerun the 64 KiB arm, and the naked row should move from
100-105 to 107+ with the client untouched. Whether it is worth a wire-visible
change for 5-7 % on one shape is a separate decision — the same cap inside the
TLS arm is already in force by accident, and the muxed shapes do not show the
deficit.
