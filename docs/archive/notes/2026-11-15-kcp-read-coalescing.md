# KCP read coalescing: hand the bridge every queued segment

**Date:** 2026-11-15
**Status:** Shipped. A raw KCP stream (`transport.tcpMux = false`,
`transport.tls.enable = false`) goes from **63 to 86 MiB/s** (+37%, nine
interleaved pairs) and overtakes Go frp v0.72.0's 76.2 MiB/s on that shape
(1.13x). Every other shape measures unchanged.

## Symptom

The Rust-vs-Go matrix after the window autotune had one row behind: KCP, one
flow, `tcpMux = false`, TLS off, at 63.8 against Go's 76.2 MiB/s (0.84x). The
same KCP engine moved 120 MiB/s through `tcpMux`, and 111 MiB/s with TLS on
(the two configurations where a wrapper sits between the session and the
bridge), so the deficit was in the naked path only.

## Where the loss comes from

`KcpStream::poll_read` (`frp-core/src/kcp/stream.rs:144`) served **one channel
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

`poll_read` now drains the stashed tail of an oversized message, then keeps
polling the channel while the caller's buffer has room:

    while buf.remaining() > 0 {
        match self.read_rx.poll_recv(cx) {
            Ready(Some(data)) => { copy; filled += take; pool_push(data) or stash tail }
            Ready(None)      => break when filled > 0, else NotConnected / EOF
            Pending          => break when filled > 0, else Pending
        }
    }

Accounting and the debug log report the call's total (`filled`), not one
segment's. Returning `Ready` after a `Pending` poll is allowed and the waker
stays registered, so a caller that received a coalesced read is still woken for
the next segment — which is why the loop may stop on `filled > 0` rather than
having to drain to `Pending`.

Tests (`frp-core/src/kcp/stream.rs`): `poll_read_coalesces_every_queued_segment`
(three 100-byte segments with distinct payloads in one poll, order asserted),
`poll_read_returns_queued_bytes_before_eof` (a closed channel must not turn
queued bytes into an early EOF), `poll_read_stops_at_the_buffer_edge_and_keeps_the_tail`,
and `poll_read_leaves_the_waker_registered_after_a_coalesced_read` (a counting
waker is rung by the next segment).

## Measurements

Same host (`ssh gc`, 4 vCPU EPYC-Milan, loopback), three interleaved pairs per
block, base = `main` at `6178c8e0`, coalesced = the same tree with this change,
both built `--release` from the same commit.

| shape | base | coalesced | delta |
| --- | --- | --- | --- |
| KCP, `tcpMux = false`, TLS off, 1 flow, 768 MiB | 57.8 / 62.1 / 65.0 | 81.6 / 83.4 / 82.0 | +37% (block 1) |
| same, repeat block | 61.8 / 60.6 / 66.0 | 86.0 / 85.2 / 88.7 | +38% (block 2) |
| same, final build | 68.1 / 65.3 / 60.3 | 90.3 / 99.2 / 81.2 | +40% (block 3) |
| KCP, `tcpMux = false`, TLS off, 4 flows, 512 MiB | 96.2 / 99.6 / 108.3 | 101.4 / 103.5 / 104.3 | +1.7% (spread) |
| KCP, `tcpMux = false`, TLS on, 1 flow, 768 MiB | 111.0 / 110.1 / 113.3 | 111.4 / 108.5 / 110.8 | -1% (spread) |
| KCP, `tcpMux = true`, TLS off, 1 flow, 512 MiB | 124.3 / 115.7 / 127.8 | 122.6 / 122.2 / 124.2 | neutral |
| KCP, `tcpMux = true`, TLS on, 1 flow, 512 MiB | 112.8 / 110.9 / 117.6 | 119.2 / 117.5 / 118.4 | +4% (spread) |

Mean-to-mean on the target row across all nine pairs: 63.0 → 86.4 MiB/s
(**+37%**). Against Go frp v0.72.0's 76.2 MiB/s measured in the same session on
the same shape (74.3 / 76.2 / 77.2), the row moves from 0.84x to **1.13x**.

## Why the earlier probe measured nothing

PR #622 tried the same change and was withdrawn: it measured
57-63 MiB/s before and after. That probe ran on the TLS + `tcpMux` shape,
where the TLS deframer and yamux had **already** coalesced the stream into
16-64 KiB reads, so there was nothing left to coalesce — and the 46-58 MiB/s
dips in that run were host noise, not an effect. The lesson is the one the
harness notes keep repeating: an optimisation aimed at the read granularity has
to be measured on the shape that has the granularity problem.

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
