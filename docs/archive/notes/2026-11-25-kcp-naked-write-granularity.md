# KCP without TLS: the "fifth" does not reproduce, and the write-size theory is falsified

**Status:** investigation complete, no fix landed (2026-11-25). Entry point: the
item at `TODO.md:13052`.

`docs/archive/notes/2026-11-15-kcp-read-coalescing.md` closed most of the bare
KCP deficit and left a residue it called **unexplained**: a 1-flow,
`tcpMux = false`, TLS-off row at 86.4 MiB/s against 110.2 for the same engine
with TLS on — "about a fifth". This note re-measures the shape on `4ba46c3c`
and reports two results, one of which overturns the first draft of this note:

- the deficit is **not a fifth** any more — the naked arm now sits 2-12 % under
  its TLS shape, with the estimate depending on the session, not on the code;
- the residue **does not follow the application's write size**. The first draft
  of this note claimed it did; a design that gives every cell the same number of
  reps and quotes one statistic falsifies that, and the paired analysis below
  puts the effect the wrong way round.

## Method

Host `gc` (greencloud-tyo, 4 vCPU EPYC-Milan), loopback, both binaries
`--release` at `4ba46c3c`. Shape: `transport.protocol = "kcp"`,
`tcpMux = false` on both sides, `kcp_bind_port` set on the server, one proxied
TCP flow, one 64 KiB-per-`sendall` client into a `recv`-only sink, 1 s
unmeasured warm-up then 768 MiB timed. Harness `scripts/kcp-tls-ab.sh` (embedded
`sink.py`/`client.py`), run by hand on that host.

`CHUNKS` takes a list and rotates every arm inside one session, so write sizes
and TLS are compared on the same host state; `senderThread` is flipped per arm
**on the frpc only** (the frps's own sends on this shape are ACKs). Two sessions
were run: `CHUNKS="65536 16384"`, 5 reps per cell (8 cells), and `CHUNKS="65536"`,
12 reps per cell (4 cells), after the first looked session-limited.

**Statistic.** Arms are ~11 s apart, so a drift in host load lands on both arms
of a pair differently and inflates the arm means. Every number below is the
**paired** difference, TLS-on minus TLS-off, within the same rep, same chunk,
same pool setting — `t` is the mean over its standard error.

## Result

MiB/s paired difference (TLS on − TLS off), positive = the naked arm is slower.

| session | chunk | pool | pairs | mean Δ | se | t | deltas |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A (n=5) | 64 KiB | on | 5 | +4.10 | 2.60 | 1.58 | −0.3, −0.1, 1.5, 4.1, 15.3 |
| A | 64 KiB | off | 5 | +1.74 | 3.29 | 0.53 | −9.2, −1.4, 1.0, 5.2, 13.1 |
| A | 16 KiB | on | 5 | +12.24 | 4.75 | 2.58 | −0.6, 6.2, 9.9, 14.7, 31.0 |
| A | 16 KiB | off | 5 | +5.66 | 2.38 | 2.38 | −1.2, 3.0, 3.9, 8.1, 14.5 |
| B (n=12) | 64 KiB | on | 12 | +6.62 | 1.63 | 4.07 | −0.8, −0.3, 2.5, 2.7, 2.9, 3.0, 6.5, 8.9, 11.0, 11.9, 13.8, 17.4 |
| B | 64 KiB | off | 12 | +12.56 | 3.34 | 3.76 | −2.9, 2.3, 3.1, 3.6, 3.8, 5.2, 6.3, 21.8, 24.5, 24.8, 29.0, 29.2 |

Reading it:

- **The gap is real but small.** Pooled at 64 KiB (the shipping default) it is
  +6.6 MiB/s over 108.3, i.e. **6 %**, at t≈4 in the 12-pair session — and only
  +4.1 at t≈1.6 in the 5-pair one. The same cell, two sessions, 1.6x apart:
  between-session drift is larger than the within-session error, so the honest
  statement is a **2-12 % band**, not a number.
- **Write size is the wrong suspect.** Inside session A, where both were
  measured, the 16 KiB arm's gap is **three times** the 64 KiB arm's (+12.2
  against +4.1 MiB/s, pooled). Halving the write size made the naked arm worse
  relative to TLS, not better. The first draft quoted a median for 16 KiB and a
  mean for 64 KiB and read a closed gap out of that comparison; means-only, the
  arm is 0.946x against 0.942x, i.e. unchanged.
- **The pool neither creates nor removes it.** Session A: +4.1 (pool on) against
  +1.7 (pool off) at 64 KiB. Session B: +6.6 against +12.6 — the opposite order.
  The pool's own cost is visible in the arm means (103.3 vs 107.7 at 64 KiB in
  session A, ~4 %), consistent with the ~5 % CPU-per-byte it costs at saturation
  (`docs/archive/notes/2026-11-23-kcp-send-thread.md`), but it is not what the
  gap is made of.
- **The tails are not explained.** Session B's pool-off naked arm has six reps
  at 21.8-29.2 s of gap and six at −2.9 to +6.3; session A's 16 KiB/pool-on
  arm holds a single +31.0. Bimodality that large on a 4-vCPU VM under ~2 load
  could be scheduler placement, but nothing here distinguishes that from KCP.

## What is falsified

The claim that the residue tracks the application's write chunk size — the
title of this note's first draft, and `TODO.md:13052`'s premise as it stood after
`75e0ff98`. Equal-n cells and a single statistic show the opposite ordering at
two of the three comparisons, and the mechanism story that went with it (a
64 KiB write becoming a ~48-datagram burst per flush against ~12 for a 16 KiB
record — plausible arithmetic on `Kcp::send` at
`frp-core/src/kcp/protocol.rs:502` and `Kcp::flush` at
`frp-core/src/kcp/protocol.rs:1205`, since KCP fragments to `mss` and emits
pending segments per flush) does not survive: shrinking the write should then
have helped, and it did not.

## What is not proven

- **The cause.** Nothing measured here names it.
- **`/proc/net/snmp`'s `Udp: InErrors`** is not a drop counter on this shape:
  it read 72 to 13,130 across identical arms, teardown traffic lands in it too.
  No drop-based explanation is offered.
- **What closed the 86 → 102 stretch** since 2026-11-15. The sender pool is the
  only candidate this file can test and it is neutral; the harness of that round
  is not preserved, so its write size (which the falsified theory says matters)
  is unknown. Not established either way.
- **Whether the 2-12 % band is code or host.** Resolving it needs a paired run
  on a quiet machine (this one carries a scheduler service using 85-95 % of a
  core for hours), not more reps here: at one core-minute of drift per session,
  n=12 was already too few to hold the estimate still.

## What a next step would have to do

If someone wants the 6 % back, the instrument has to beat the drift first:
paired arms inside a single process lifetime (both frpc configurations against
one frps, 5 s alternating windows), or a host whose load is flat for the length
of a session. Reps of 11 s on a shared VM cannot separate 6 % from 2 %.
