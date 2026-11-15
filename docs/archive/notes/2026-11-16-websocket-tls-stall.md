# The websocket + TLS stall: a flush that never reached the TLS record layer

**Date:** 2026-11-16
**Status:** Root-caused and fixed. The shape that stalled about once in ten reps
ran 0 of 44 reps stalled after the fix; before it, 6 of 58.

## Symptom

The interleaved Rust-vs-Go matrix kept producing two rows whose spread was far
outside the harness's own noise — `websocket` + TLS + `tcpMux` bottomed at 87.2
MiB/s at one flow and 102.2 at four, against medians of 421.5 and 486.1. That is
not a slow sample, it is a stalled one: a normal 1024 MiB rep takes 2.3 s, the
stalled ones took 10.9 s and 12.3 s.

Reproduced on the bench VM (4 vCPU EPYC-Milan, loopback), one flow, 1024 MiB,
`frpc` at four worker threads:

| shape | stalls | reps |
| --- | ---: | ---: |
| `websocket` + TLS + `tcpMux` | 6 | 58 |
| `tcp` + TLS + `tcpMux` | 0 | 10 |
| `websocket` + `tcpMux`, TLS off | 0 | 10 |

So the trigger is the combination of the manual WebSocket framing with a TLS
inner stream — neither layer alone.

## What the stall looks like

Sampling `ss -tinH` every 0.25 s while a rep runs, and both processes' CPU ticks
every 0.25 s, at the moment of a stall:

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
The stall ends when something else happens to write again — the yamux keepalive
ping at 10 s is the obvious candidate, which matches the observed 8-10 s stall
durations.

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
  `tcpMux`, 4 client workers, 1024 MiB per rep).
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
  cheap. `poll_flush` on `tokio-rustls` is where the `write_rustls_io` push
  happens, so a stalled-capable path now simply does the right thing.
- The stall was only reproducible on loopback with four client worker threads and
  the `websocket` + TLS + `tcpMux` shape; whether other combinations can lose the
  same flush (a TLS inner with a different framing layer) was not audited beyond
  grepping every `poll_flush` in the tree — the two other wrapping writers
  (`snappy_stream.rs`, `cipher_stream.rs`) do delegate.
- The interleaved comparison's two affected rows are counted as
  `indistinguishable` with the stall present; with the fix the medians move
  together and the rows should be re-measured before the numbers are quoted
  again.
