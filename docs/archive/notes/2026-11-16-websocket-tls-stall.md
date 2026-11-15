# The websocket + TLS stall: a flush that never reached the TLS record layer

**Date:** 2026-11-16
**Status:** Root-caused and fixed. The shape that stalled about once in ten reps
ran 0 of 44 reps stalled after the fix; before it, 6 of 58.

## Symptom

The interleaved Rust-vs-Go matrix kept producing two rows whose spread was far
outside the harness's own noise — `websocket` + TLS + `tcpMux` bottomed at 87.2
MiB/s at one flow and 102.2 at four, against medians of 421.5 and 486.1. That is
not a slow sample, it is a stalled one: a normal 1024 MiB rep takes 2.3 s, so
those two samples imply 11.7 s and 10.0 s of wall clock. The dedicated
reproduction below caught two stalls of 10.9 s and 12.3 s.

Reproduced on the bench VM (4 vCPU EPYC-Milan, loopback), one flow, 1024 MiB,
`frpc` at four worker threads:

| shape | stalls | reps |
| --- | ---: | ---: |
| `websocket` + TLS + `tcpMux` | 6 | 58 |
| `tcp` + TLS + `tcpMux` | 0 | 10 |
| `websocket` + `tcpMux`, TLS off | 0 | 10 |

Those control cells are consistent with the mechanism rather than proof of it:
at the baseline rate (6 in 58) ten clean reps is a 35 % outcome, so they cannot
exclude a 10 % rate on their own. What carries the claim is the code: on the
bare `tcp` transport the work connection is a `tokio-rustls` stream whose own
`poll_flush` does push the records, and `websocket` without TLS wraps a raw
`TcpStream`, where a flush that returns `Ready` is genuinely harmless because a
completed write already reached the kernel.

`tcpMux` belongs in the trigger too, and for a second reason beyond the shape
table: the swallowed flush is only fatal when the writer is *parked* waiting for
something that is not a write. With `tcpMux` off the next bridge write goes
straight into rustls's own `poll_write`, which pushes the pending records, so the
bug is self-healing there. Inside yamux the idle writer parks in `poll_flush`
(the drained-queue state), which is exactly where the lie lands. The
`websocket` + TLS + `tcpMux` **off** cell was not sampled at stall-rate counts —
only the three cells in the table were.

## What the stall looks like

Sampling `ss -tinH` and both processes' CPU ticks every 0.5 s while a rep runs,
at the moment of a stall:

```
0  11420613  127.0.0.1:58152  127.0.0.1:19056      <- bench client, send queue
956556        0  127.0.0.1:19056  127.0.0.1:58152  <- frps accepted socket, recv queue
0        0  127.0.0.1:19100  127.0.0.1:34642       <- the tunnel, empty both ways
```

The client has 11.4 MB queued to send, the server has received ~956 KB and is not
reading it, and **the tunnel is empty in both directions**. Both processes sit at
zero CPU for the whole stall (tick samples freeze for fifteen consecutive
half-second intervals), so nothing is spinning and nothing is retransmitting. A
`gdb` attach at that point shows every worker parked in `epoll_wait`/futex.

That combination is decisive: no bytes are in flight, no bytes are in either
socket, and yet the writer is parked. The bytes that should be moving are inside
one of the processes, in userspace.

## Root cause

`WsByteStream` (the manual RFC 6455 layer, `frp-core/src/transport/websocket.rs`)
wrote frames through the inner stream and had this flush:

```rust
fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    // ... drain a partially written frame if needed ...
    if needs_flush_local {
        // ... poll_write the remainder ...
    } else {
        Poll::Ready(Ok(()))          // <- never reaches the inner stream
    }
}
```

With a raw `TcpStream` inside, that is harmless: a completed `poll_write` has
already put the bytes in the kernel. With a **TLS** stream inside it is a
deadlock. `tokio-rustls` accepts plaintext into rustls's send buffer and then
tries to push records to the socket; when the socket write returns `WouldBlock`
it keeps the remaining ciphertext in `sendable_tls` and registers writable
interest. The wake arrives, the io driver re-polls, yamux's writer calls
`poll_flush` on the WebSocket stream — and the WebSocket layer answers
`Ready(Ok(()))` without asking rustls to flush. The ciphertext stays in
userspace, no socket has anything queued, and both ends wait for each other.
The stall ends when something else happens to write again, and the only timer in
this tree with that cadence is vendored yamux's RTT ping:
`const PING_INTERVAL: Duration = Duration::from_secs(10)` at
`vendor/yamux/src/connection/rtt.rs:24`, whose ping frame is a write. That
matches the observed ~7.5-10 s stalls. It is worth naming the two constants it is
*not*: frp's own liveness keepalive is 30 s
(`const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30)`,
`frp-core/src/mux.rs:40`) and would be too slow to explain these durations, and
`DEFAULT_WRITE_DEADLINE` is also 10 s (`frp-core/src/mux.rs:181`) but is a
watchdog that *fails* a stalled write rather than resuming it.

The same bug cannot fire on the plain `tcp` transport, where the work connection
is a bare TLS stream and `poll_flush` is tokio-rustls's own, which does push the
records. That is exactly the shape split the measurement showed.

## Fix

`WsByteStream::poll_flush` now always delegates to the inner stream after the
(drained) frame work, so the TLS record layer is asked to flush on every flush
call:

```rust
    // Always flush the inner stream, even when no frame bytes remain here.
    Pin::new(raw.as_mut()).poll_flush(cx)
```

Everything else about the drain machinery is unchanged: a partially written
frame is still finished from `write_buf`, `drain_completed` still lets the
caller's re-polled buffer be consumed rather than re-sent, and `Ok(0)` on a
non-empty remainder is still `WriteZero`.

## Verification

- **Reproduction, before the fix:** 6 stalls in 58 reps of the shape (2/10, 2/12,
  1/16, 1/20 across sessions).
- **After the fix:** 0 stalls in 44 reps of the same shape on the same host, same
  binaries otherwise (`CARGO_TARGET_DIR=/root/fix-target`, `websocket` + TLS +
  `tcpMux`, 4 client workers, 1024 MiB per rep). That is a separate-session A/B,
  not an interleaved pair (Fisher one-sided p = 0.03), so it corroborates rather
  than proves: the deterministic unit tests and the library mechanism above carry
  the proof.
- **Regression tests** (`frp-core/src/transport/websocket.rs`), both of which
  fail on the pre-fix code and pass after it:
  `flush_reaches_the_inner_stream_with_nothing_pending` and
  `flush_reaches_the_inner_stream_after_draining_a_partial_frame`. They use a
  sink that counts its own `poll_flush` calls, so "the wrapper swallowed the
  flush" is directly observable; the second one also primes the drain path with a
  sink that accepts half of every write.
- A first attempt at instrumentation (log every yamux park and wake) made the
  stall disappear over 48 reps, which is why the diagnosis above is built on
  `ss`/`/proc` sampling and `gdb` at the stall instead of on traces: this is a
  timing-sensitive lost flush, and any syscall in the write path hides it.

## Limits

- The fix makes the flush call reach the TLS layer; it does not make the flush
  cheap. `tokio-rustls` 0.26.6 pushes the buffered records in `poll_flush`
  (`src/common/mod.rs:351`, which loops over `write_io`, `:121`), so the flush is
  simply where the work now happens.
- The stall was only reproducible on loopback with four client worker threads and
  the `websocket` + TLS + `tcpMux` shape. The bug class was still audited across
  every `poll_flush` on a write path: the wrapping writers all delegate
  (`cipher_stream.rs`, `snappy_stream.rs`, `transport/{tls,pre_read,buffered_read,ssh_channel}.rs`,
  `transport/mod.rs`, `mux.rs` `ActivityIo`, `quic.rs`, `kcp/stream.rs`,
  `xtcp_session.rs`, `crypto.rs`, `frp-server/src/control/{bridge,login}.rs`,
  `ssh_gateway/stream.rs`, `vhost_h2c.rs`, the visitor and `tls2raw` plugins). The
  single non-delegating write-path implementation, `frp-core/src/xtcp_p2p.rs:815`,
  drains into a raw UDP socket and has no inner stream, so it cannot strand a
  buffered layer.
- The interleaved comparison's two affected rows carried the stall in their
  tails, so they printed `indistinguishable`. Re-measured after the fix on the
  same host, same harness (`scripts/bench-vs-go.py`, 1024 MiB, 3 blocks, n=6 per
  arm, `dropped=0`):

  | shape | shipped defaults (frpc 1 worker) | `WORKERS=4` |
  | --- | --- | --- |
  | `websocket` + TLS + `tcpMux`, 1 flow | 472.1 vs 305.1 = **1.58x** | 459.9 vs 299.0 = 1.56x |
  | `websocket` + TLS, no `tcpMux`, 1 flow | 623.5 vs 510.8 = **1.28x** | 686.0 vs 516.2 = 1.37x |
  | `websocket` + TLS + `tcpMux`, 4 flows | 490.6 vs 366.0 = **1.32x** | 490.8 vs 358.9 = 1.33x |
  | `websocket` + TLS, no `tcpMux`, 4 flows | 828.9 vs 859.7 = 0.95x (`indistinguishable`) | 1225.2 vs 937.6 = 1.27x |

  So the four-flow `tcpMux` row was `indistinguishable` **because** of the
  stalled samples and is now a clear 1.32x; the four-flow no-`tcpMux` row stays
  at parity with the shipped one-worker client, which is the separate
  `transport.workerThreads` trade-off recorded in `TODO.md`, not this bug.
