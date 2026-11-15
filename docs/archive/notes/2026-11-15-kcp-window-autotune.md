# KCP window: one busy session takes the budget, several share it

**Date:** 2026-11-15
**Status:** Shipped (PR #623). One `tcpMux = false` KCP flow goes from **68 to
108-114 MiB/s** on the measurement VM; two, four and muxed flows stay within
run-to-run spread.

## Symptom

The Rust-vs-Go matrix left exactly one row behind: a single KCP stream with
`transport.tcpMux = false`, at 68 MiB/s against Go frp v0.72.0's ~107 on the
same TLS-enabled shape — 0.64x. Every other shape led, and the same KCP engine
moved 120 MiB/s through `tcpMux`.

## Where the ceiling comes from

KCP paces a connection by its window and its tick interval:

    window × segment ÷ interval  =  1024 × 1376 B ÷ 20 ms  ≈  68 MiB/s

which is where frp-rs sat. Sweeping the knobs on the four-vCPU VM
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

The driver advertises the wide window when exactly one of its sessions is moving
payload, and the old 1024 otherwise:

    cap    = max(configured_cap, 1024)      // below the floor is raised
    window = cap.min(2048) if busy <= 1 else 1024

This is deliberately not a shared budget: `2048 / busy` with a 1024 floor is the
same function for every `busy >= 2`, and pretending otherwise ("several share
it") would misdescribe 200 busy sessions each keeping 1024 — which is exactly
what they had before. What changed is the 0/1 boundary, where the pacing formula
binds.

`busy` is payload-based, not datagram-based. The first version tested "inbound
datagram within 250 ms", which yamux pings satisfy (one every 10 s per idle
session), so on a server with a few dozen idle clients the count hovered at 2
and the loaded session flapped between 2048 and 1024 every few seconds — each
shrink drops in-flight segments past the new window and costs a retransmit
burst. Sessions now carry a payload counter: a session is busy when it received
at least one MTU inside the window, or has data queued *and* is still being
acked. Pings and heartbeats are tens of bytes, so they never qualify; a peer
that stopped ACKing is not busy either, it is stalled.

Both directions follow: `Kcp::set_wndsize(wnd, wnd)`. Only the receive window
is advertised on the wire, but the send side has to move with it, or the
configured cap alone lets a busy server hold 4096 segments per session — see
the first pitfall below. The configured `wnd_size` is an upper bound above the
floor; it is an internal field, not a TOML key, and a value narrower than 1024
is raised to it.

A newly created session is seeded at the current window rather than left at the
configured 4096 until the next tick (which would let it advertise and buffer 4x
the old per-session bound for one interval).

## Result

Same harness, `tcpMux = false`, `ssh gc`, 4 vCPU EPYC-Milan, interleaved:

| shape | before | after |
| --- | --- | --- |
| 1 flow, 768 MiB | 67.8 / 68.1 / 67.9 | **108.3 / 110.2 / 112.1** (+60%) |
| 2 flows, 1024 MiB | 95.2 / 112.2 | 99.2 / 107.2 (spread, not an effect: two busy sessions also get 1024) |
| 4 flows, 1024 MiB | 105.2 / 107.7 / 109.9 | 108.8 / 114.1 / 120.0 |
| 1 flow through `tcpMux`, 512 MiB (6 interleaved pairs) | 114.0-124.4 | 117.3-121.1 |

Server CPU for the single-flow case is unchanged — 690-717 ticks per 768 MiB
before, 694-711 after — because the wider window fills the same tick with more
payload rather than more work per payload. The 2-, 4- and `tcpMux` rows
move inside the ~8-10% spread those shapes already showed, and the 2-flow row
cannot move by construction: at two busy sessions the window is the old 1024.

Against Go frp v0.72.0 the muxless single flow moves from 0.64x to **parity**:
111.5 against 106.7 MiB/s (medians of three, same host, same shape, TLS enabled
on both sides). The earlier Result row (108.3 / 110.2 / 112.1) is the batch
measured while the change was being validated; the 110.3 / 111.5 / 113.7 triple
below was re-measured in the same session as the Go column, on both binaries at
`6178c8e0` with the shipped defaults (frps one worker per CPU, frpc one), and it
is the one quoted elsewhere. An earlier version of this note quoted 0.9x to 1.4x
by pairing frp-rs's TLS-on number with Go's TLS-*off* one; the like-for-like
pairs are:

| shape | frp-rs | Go frp v0.72.0 | ratio |
| --- | --- | --- | --- |
| 1 flow, 768 MiB, `tcpMux = false`, TLS on | 110.3 / 111.5 / 113.7 | 102.3 / 106.7 / 107.7 | 1.04x |
| 1 flow, 768 MiB, `tcpMux = false`, `transport.tls.enable = false` | 62.9 / 63.8 / 66.1 | 74.3 / 76.2 / 77.2 | 0.84x |

In the TLS-off row the window is 2048 at both frp-rs ends, so frp-rs being behind
is not explained by its own window setting — but Go runs that row at its own
pinned 1024, so it is not a window-controlled comparison either; see Limits.

The gain also only appears when both ends are frp-rs. Go sets `SetWindowSize(1024, 1024)` on both
directions of its KCP conns, so a Rust-Go pair stays at 1024 both ways and sees
no change from this work.

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
- **The wait-queue bound had to grow with the ceiling.** `KCP_SND_BACKLOG_THRESHOLD`
  was 2048 — 2x the old 1024 window, so a session at full window still had a
  window of write-ahead queue. With a 2048 ceiling that margin became 1x: the
  gate would fire as soon as the window filled and remove the headroom the
  high-BDP case needs. It is now 4096 (~5.6 MiB per stalled session).
- **Clock arithmetic wraps.** The driver clock is `u32` milliseconds (~49.7
  days). An `last_inbound + 250 >= now` test is true forever after the wrap for
  any session stamped before it, so every session would count as busy and the
  autotune would silently degrade to the old behaviour for the rest of the
  process's life. The test is `now.wrapping_sub(last_inbound) <= 250`, matching
  the reaper's convention.

## Limits

- **With `transport.tls.enable = false` both builds are slower and frp-rs is
  behind.** Same shape, one 768 MiB flow: frp-rs 63.8 against Go 76.2 MiB/s
  (0.84x), while both reach ~107-112 with TLS enabled. Two things make that row
  different from every other one here. First, turning TLS *off* costs frp-rs
  ~40% on this shape, the opposite of the usual relation (TLS normally costs
  ~40%; see the throughput table in `README.md`), so the TLS-off row is not the
  cheap baseline it is elsewhere. Second, the window is 2048 at both frp-rs ends
  in that row but Go runs it at its own pinned 1024, so the comparison is
  unregulated on our side and regulated on theirs — if anything that credits Go
  with doing more per window. The likely cause of the inversion — unverified —
  is read granularity: the TLS deframer and yamux hand the bridge 16-64 KiB
  chunks while a raw KCP stream hands it one ~1376-byte segment per read, so the
  bridge pays its per-read cost four to fifty times as often. Collapsing queued
  segments into one read is the change PR #622 tried; that probe ran on the
  TLS+`tcpMux` shape, where yamux had already coalesced, so it never tested this
  row. **Confirmed and shipped since:** coalescing on this shape measures
  63.0 → 86.4 MiB/s (+37%, nine interleaved pairs), 1.13x Go — see
  `docs/archive/notes/2026-11-15-kcp-read-coalescing.md`.
- Do not read the TLS-off number as a regression from this work: it is the same
  band as the pre-change baseline for that shape, and the autotune's own arms
  were measured with TLS on (the only shape this note was opened for).
- The budget (2048) and the floor (1024) are constants tuned on this VM's 4 vCPU
  / loopback. They are not derived from link capacity, so a satellite or
  high-BDP deployment may want a different shape; the configured `wnd_size` caps
  the budget but not the floor.
- The rule keys on *busy sessions per driver*, which is a proxy for "is the
  driver the limit". It cannot tell a wide-bandwidth single flow from a narrow
  one; both get 2048. One driver serves every client of a listening socket
  (`frp-core/src/kcp/listener.rs:76`), so on a server the decision is made per
  port, not per client — which is why the payload test matters.
- Shrinking a window mid-flight can cost a retransmit burst: segments already
  sent beyond the new window are dropped and resent. KCP self-heals (the receive
  window reopens once the app drains, `KCP_ASK_TELL`), and the retransmit is
  bounded by the RTO, but a driver whose busy count oscillates at the 250 ms
  boundary would pay it repeatedly. The payload test makes that unlikely; it is
  not impossible (a flow that pauses for 250 ms exactly).
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
