# Nagle in the benchmark: a 7 ms tax that was never frp's

**Date:** 2026-11-10
**Status:** fixed in `scripts/frp-stress`; earlier matrix and baseline numbers include the tax.

## 1. Symptom

The protocol matrix has always been noisy. Rows that should differ by tens of
percent have differed by 3×, the same row has measured
`tcp-plain` anywhere between 18 and 526 MiB/s on different runners, and one
repeated anomaly was recorded as a real effect: at a 32 KiB bridge buffer, a
64 KiB message shape collapsed on Linux (10–30 MiB/s) while the same shape on
macOS collapsed at 64 KiB instead (165 vs 301).

## 2. Reproduced away from frp

A plain tokio relay — no frp, no yamux, two 32 KiB buffers, `set_nodelay(true)`
on both relay sockets — shows the same collapse:

| message | relay buffer | throughput | round-trip rate |
|---|---|---|---|
| 64 KiB | 32 KiB | **12.6 / 14.7 MiB/s** | 101 / 118 /s (8.5–9.9 ms) |
| 64 KiB | 64 KiB | 642.9 / 677.1 MiB/s | 5,143 / 5,417 /s |
| 32 KiB | 32 KiB | 560.4 MiB/s | 8,966 /s |
| 128 KiB | 64 KiB | 36.1 MiB/s | 145 /s |
| direct, no relay | — | 1,508 MiB/s | 12,067 /s |

Same relay, with the echo peer's `TCP_NODELAY` turned on. (These are separate
runs from the table above: 18.0 MiB/s here against 12.6 / 14.7 MiB/s there for
the same shape — the taxed rate is not stable, which is itself part of the
problem.)

| shape | echo without nodelay | echo with nodelay |
|---|---|---|
| 64 KiB × 32 KiB buffer | 18.0 MiB/s | **736.8 MiB/s** |
| 128 KiB × 32 KiB buffer | — | 965.5 MiB/s |
| 128 KiB × 64 KiB buffer | 36.1 MiB/s | 1,007.5 MiB/s |

## 3. Cause

Recorded earlier as a platform property in
[`2026-11-10-bridge-buffer-64k-default.md`](2026-11-10-bridge-buffer-64k-default.md)
("Linux prefers the 64 KiB one (6.4-19.7x, on this harness only)") — the
parenthetical was the clue.

Nagle. When the relay splits a message into more chunks than the peer expects,
the peer's second `write` finds an unacknowledged small segment in flight and
waits for the ACK — a timer, not a copy. The relay, tokio and frp are all
innocent; the peer socket is the one holding the timer.

`scripts/frp-stress` set `TCP_NODELAY` nowhere. Every matrix row, every
throughput baseline and the latency scenario were measured against a peer with
Nagle on, so a timer entered the measurement on precisely the chunked paths the
matrix exists to compare.

## 4. Fix

`set_nodelay(true)` on all four benchmark call sites (three files):

- `scripts/frp-stress/src/scenarios/echo.rs` — each accepted connection.
- `scripts/frp-stress/src/scenarios/throughput.rs` — the load client.
- `scripts/frp-stress/src/scenarios/latency.rs` — the `steady` and `setup`
  clients, where the measurement *is* the round trip.

frp itself sets `TCP_NODELAY` on every data-path socket since the 2026-07 L1
work (`frp-server/src/service.rs:866`, `frp-core/src/transport/mod.rs:943`, and
the helper at `mod.rs:998-1002` used at ~15 further sites), so this changes what
the harness measures, not what the proxy does.

## 5. What this does and does not explain

- **Explained:** the Linux collapse at a 32 KiB buffer (10–30 → 736 MiB/s once
  the peer stops running a timer), and part of the row-to-row noise.
- **Not this:** the macOS 1-stream dip. With nodelay on both ends, a 64 KiB
  message still measures 298 MiB/s at a 32 KiB buffer and 168 MiB/s at 64 KiB —
  the buffer-size effect already recorded in
  [`baselines/README.md`](../../../scripts/frp-stress/baselines/README.md) and
  [§4 of the 64 KiB note](2026-11-10-bridge-buffer-64k-default.md), not a timer.
  Per round trip that is 419 µs at a 32 KiB buffer and 744 µs at 64 KiB, against
  83 µs for the same 64 KiB round trip over a direct connection (1,508 MiB/s at
  12,067 round trips/s). Four streams move the same aggregate at both sizes
  (718.8 / 712.6 MiB/s), so the per-message cost is not fixed — it is the same
  store-and-forward shape, not a defect, and still not something the throughput
  gate measures.

## 6. Consequence for recorded numbers

Throughput baselines and matrix rows recorded before this change carry the tax
and should not be compared against a run from a fixed harness without saying so.
The latency and memory records do not: those scenarios send 64-byte messages one
at a time, so the previous write is already acknowledged and Nagle never
engages. The one-way throughput numbers in
[`2026-11-10-real-host-throughput.md`](2026-11-10-real-host-throughput.md) are
unaffected in kind — a streaming write is not a ping-pong — but they were taken
with the same peer, so a re-run on a fixed harness is the honest comparison.
Three earlier notes published `frp-stress throughput` tables measured through
the Nagle-on peer and cannot say from their own text whether a row was taxed:
[`2026-11-08-mux-throughput-scaling.md`](2026-11-08-mux-throughput-scaling.md),
[`2026-11-08-bridge-buffer-frame-match.md`](2026-11-08-bridge-buffer-frame-match.md)
and [`2026-11-10-bridge-buffer-64k-default.md`](2026-11-10-bridge-buffer-64k-default.md).
Their relative comparisons were made in-pair on one harness, which is the
property this fix preserves; their absolute rows are the ones to re-measure.
