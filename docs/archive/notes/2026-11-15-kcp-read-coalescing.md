# KCP read coalescing: hand the bridge every queued segment

**Date:** 2026-11-15
**Status:** Shipped. A raw KCP stream (`transport.tcpMux = false`,
`transport.tls.enable = false`) goes from **63.0 to 86.4 MiB/s** (+37%,
mean of nine interleaved pairs) and moves from behind Go frp v0.72.0 to ahead
of it: 0.83x → 1.14x on means (1.12x on medians). Every other shape measures
unchanged.

## Symptom

The Rust-vs-Go matrix after the window autotune had one row behind: KCP, one
flow, `tcpMux = false`, TLS off, at 63.8 against Go's 76.2 MiB/s (0.84x, medians
of three). The same KCP engine moved 111 MiB/s with TLS on and 120 through
`tcpMux` — the two configurations where a wrapper sits between the session and
the bridge — so the deficit was in the naked path only.

## Where the loss comes from

`KcpStream::poll_read` (`frp-core/src/kcp/stream.rs:145`) served **one channel
message per call**. A message is one KCP segment — ~1376 bytes at the
production MTU of 1400, because stream mode never carries fragment chains
(`frp-core/src/kcp/protocol.rs:560-564`) and `KcpSession::recv_and_push` pushes
one pooled buffer per delivered message.

The bridge asks for 64 KiB (`frp-core/src/buffer_pool.rs`). So every bridge
read returned after ~1.4 KiB, and the per-read cost — a channel receive, a
length check, an accounting update, a pool push, and the bridge's own loop
iteration — was paid four to fifty times more often than on the TLS or yamux
path, where the wrapper hands over 16-64 KiB per read.

## The change

`poll_read` already drained the stashed tail of an oversized message; it now
**keeps polling** the channel after that, while the caller's buffer has room:

    while buf.remaining() > 0 {
        match self.read_rx.poll_recv(cx) {
            Ready(Some(data)) => { copy; filled += take; pool_push(data) or stash tail }
            Ready(None)      => break when filled > 0, else NotConnected / EOF
            Pending          => break when filled > 0, else Pending
        }
    }

Accounting and the debug log report the call's total (`filled`), not one
segment's. The debug event's field is `first`: the first **new** segment of the
call, capped at eight bytes (a stashed tail drained first is not "first").
Returning `Ready` after a `Pending` poll is allowed and the waker stays
registered, so a caller that received a coalesced read is still woken for the
next segment — which is why the loop may stop on `filled > 0` rather than
having to drain to `Pending`.

Tests (`frp-core/src/kcp/stream.rs`): `poll_read_coalesces_every_queued_segment`
(three 100-byte segments with distinct payloads in one poll, order asserted),
`poll_read_returns_queued_bytes_before_eof` (a closed channel must not turn
queued bytes into an early EOF), `poll_read_stops_at_the_buffer_edge_and_keeps_the_tail`,
`poll_read_drains_the_tail_before_new_segments` (tail first, then a fresh
segment; `read_count` moves by the call's total, not by one message),
`poll_read_leaves_the_waker_registered_after_a_coalesced_read` (a counting
waker is rung by the next segment), and `poll_read_reports_a_dead_session_instead_of_eof`.

## Measurements

Same host (`ssh gc`, 4 vCPU EPYC-Milan, loopback), three interleaved pairs per
block, base = `main` at `6178c8e0`, coalesced = a tree with only this change
applied, both arms built `--release`.

| shape | base | coalesced | delta |
| --- | --- | --- | --- |
| KCP, `tcpMux = false`, TLS off, 1 flow, 768 MiB | 57.8 / 62.1 / 65.0 | 81.6 / 83.4 / 82.0 | +34% (block 1) |
| same, second block | 61.8 / 60.6 / 66.0 | 86.0 / 85.2 / 88.7 | +38% (block 2) |
| same, third block (after the test additions) | 68.1 / 65.3 / 60.3 | 90.3 / 99.2 / 81.2 | +40% (block 3) |
| KCP, `tcpMux = false`, TLS off, 4 flows, 512 MiB | 96.2 / 99.6 / 108.3 | 101.4 / 103.5 / 104.3 | +1.7% (spread 96-108) |
| KCP, `tcpMux = false`, TLS on, 1 flow, 768 MiB | 111.0 / 110.1 / 113.3 | 111.4 / 108.5 / 110.8 | -1% (spread 108-113) |
| KCP, `tcpMux = true`, TLS off, 1 flow, 512 MiB | 124.3 / 115.7 / 127.8 | 122.6 / 122.2 / 124.2 | neutral (spread 116-128) |
| KCP, `tcpMux = true`, TLS on, 1 flow, 512 MiB | 112.8 / 110.9 / 117.6 | 119.2 / 117.5 / 118.4 | +4% (spread 111-119) |

Across the nine pairs of the target row: base **mean 63.0** (median 62.1),
coalesced **mean 86.4** (median 85.2) — **+37% on the mean, +37% on the
median**. Go frp v0.72.0 measured 74.3 / 76.2 / 77.2 on the same shape in the
same session (mean 75.9, median 76.2), so the row moves from **0.83x on means
(0.81x on medians) to 1.14x on means (1.12x on medians)**.

## Why the earlier attempt measured nothing

PR #622 proposed the same coalescing and measured no change: its arms sat at
64-68 MiB/s before and after. That probe ran at `tcpMux = false` with **TLS
left on** — the configuration directly above in this table, where the rustls
deframer already hands up to a whole 16 KiB record per read, so there was
nothing left to coalesce. The 62.8 against 63.9 MiB/s figure quoted in
`docs/archive/notes/2026-11-12-worker-thread-count.md` is a different probe
(coalescing in the driver's receive path, not the stream read) and also
predates this change.

The lesson is the one the harness notes keep repeating: an optimisation aimed
at read granularity has to be measured on the shape that has the granularity
problem. The naked row is that shape; the wrapped ones are not.

## Limits

- Helps only when the caller's buffer is larger than one segment. `read_exact`
  users with small buffers, and the `tcpMux`/TLS consumers (already 16-64 KiB
  per read), see no change — and the measurements above confirm they do not
  regress.
- Bounded by the caller's buffer, so a 64 KiB bridge chunk can still come back
  in several polls when the channel drains mid-loop; that is a wakeup, not a
  copy, and it costs one scheduler hop.
- Does not touch the write path. The TLS-off row's write side is still one
  `sendmmsg` per tick burst, which the earlier flush-model round showed is
  already the right shape.
- Even after this change the naked row (86) is slower than the same engine with
  TLS on (111). Coalescing removed most of the read-granularity cost, not all
  of it; the residue is unexplained and is recorded in `TODO.md`.
