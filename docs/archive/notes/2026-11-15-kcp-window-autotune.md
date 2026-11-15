# KCP window: one busy session takes the budget, several share it

**Date:** 2026-11-15
**Status:** Shipped (PR #623). One `tcpMux = false` KCP flow goes from **68 to
95 MiB/s** on the measurement VM; two, four and muxed flows are unchanged.

## Symptom

The Rust-vs-Go matrix left exactly one row behind: a single KCP stream with
`transport.tcpMux = false`, at 68 MiB/s against Go frp v0.72.0's 75-77. Every
other shape led, and the same KCP engine moved 120 MiB/s through `tcpMux`.

## Where the ceiling comes from

KCP paces a connection by its window and its tick interval:

    window × segment ÷ interval  =  1024 × 1376 B ÷ 20 ms  ≈  68 MiB/s

which is where both builds sat. Sweeping the knobs on the four-vCPU VM
(768 MiB single flow / 1024 MiB four flows, `tcpMux = false`, medians or full
ranges of 2-3 reps):

| configuration | 1 flow | 4 flows |
| --- | --- | --- |
| shipped (window 1024, interval 20) | 67.4-68.4 | 105-121 |
| window 2048 | 79.6-101.5 | 77-85 (CPU 1472 vs 1000 ticks) |
| window 4096 | 83.9-96.4 | 82-92 |
| window 8192 | 82.0-90.8 | 80-88 |
| window 512 | 34.2-34.3 | 91.1 |
| interval 10 | 86.7-94.5 | 92-107 |
| window 2048 + interval 10 | 97.8-100.7 | 76-77 |
| window 2048 + 8 MiB socket buffers | 87.0-90.5 | 84-85 |
| two flows, window 2048 | — | 96-98 (CPU 1130-1167 vs 872-886) |

Two conclusions:

1. A lone flow is **paced**, not limited: widening the window or shortening the
   tick raises it immediately. Disabling FEC changed nothing (67.7 / 68.5 /
   68.5 against 66.8 / 68.5 / 68.0), so FEC padding is not involved.
2. Several flows are **not** paced: they already saturate what one driver task
   can retire, and a wider window only inflates the per-tick flush scan — it
   costs ~40% more CPU and ~25% of the throughput. The optimum is inverted
   between the two shapes, which is why neither value can be the default.

## The change

The driver now sizes the window from load, every tick:

    window = clamp(2048 / busy_sessions, 1024, configured_cap)

`busy` counts the sessions in this driver that have unacked data queued or
inbound traffic within the last 250 ms, so idle control connections and unused
proxies do not dilute the budget. The configured `wnd_size` becomes an upper
bound and is raised to 4096 by default; the 1024 floor is the old fixed value,
so a busy server keeps exactly the behaviour it had.

Both directions follow: `Kcp::set_wndsize(wnd, wnd)`. Only the receive window
is advertised on the wire, but the send side has to move with it, or the
configured cap alone lets a busy server hold 4096 segments per session — see
the first pitfall below.

## Result

Same harness, `tcpMux = false`, `ssh gc`, 4 vCPU EPYC-Milan, interleaved:

| shape | before | after |
| --- | --- | --- |
| 1 flow, 768 MiB | 67.7 / 67.9 / 68.0 | **95.0 / 95.0 / 95.6** (+40%) |
| 2 flows, 1024 MiB | 93.9 / 99.1 | 101.3 / 102.2 |
| 4 flows, 1024 MiB | 113.0 / 116.2 / 119.3 | 113.0 / 116.0 / 125.0 |
| 1 flow through `tcpMux`, 512 MiB | 115.4 / 116.6 / 122.5 | 109.8 / 119.8 / 121.4 |

Server CPU for the single-flow case rises from 666-690 to 726-772 ticks per
768 MiB (about +9%), which is the cost of putting more data in flight; the
four-flow case stays at 904-1006 against 954-1006.

Against Go frp v0.72.0 the muxless single flow moves from 0.9x to **1.24x**.

## Pitfalls found while building it

- **Setting only the receive window regresses the busy case.** `set_wndsize(0,
  wnd)` keeps the send window at the configured cap, so four flows ran with
  4096 segments in flight each: 83-89 MiB/s at 1234-1360 CPU ticks, against
  109-118 at 953-1024. Both bounds have to follow the autotune.
- **Resizing only when the target changes misses new sessions.** A work
  connection created after the last change starts at the configured cap and is
  never revisited if the target stays put — the same 4-flow regression, with
  the single-flow win intact, which makes it easy to misread as noise. The tick
  therefore compares each session's current window against the target.
- The first implementation also kept an `applied_window` field as a
  "changed?" flag. It was removed once the per-session comparison replaced it;
  a flag that can disagree with the sessions is a bug waiting to happen.

## Limits

- The budget (2048 segments) and the floor (1024) are constants tuned on this
  VM's 4 vCPU / loopback. They are not derived from link capacity, so a
  satellite-link or high-BDP deployment may want a different shape; the
  configured `wnd_size` still caps it.
- The controller keys on *busy sessions per driver*, which is a proxy for "is
  the driver the limit". It cannot tell a wide-bandwidth single flow from a
  narrow one; both get 2048.
- What it does not do: touch the tick interval (10 ms helps single flow and
  costs four flows — same trade, worse), or make the flush scan cheaper. The
  scan is O(in-flight segments) per tick and is the reason the wide window is
  expensive under load; a cheaper scan would let the budget grow further.

## Measurement discipline

The first attempt at a KCP read-coalescing change (PR #622) reported +18% and
was withdrawn: each A/B ran the baseline first, so the second arm always
benefited from the host settling. Re-running with the order flipped and with
A/B/A blocks put both builds at ~68 MiB/s. Every number above comes from
interleaved runs of both orders, and the same-binary A/B/A check reproduced the
baseline to within 1%.
