# The mux write path was emitting two segments per frame

2026-11-22. Measured on a 4-core Linux VPS, loopback, `scripts/frp-stress`
`stream`/`sink` shapes (one-way, 64 KiB writes, 10 s, 2 reps, arms interleaved).

## What the mux penalty actually is

`tcpMux = true` runs at 1111-1141 MiB/s (1108 in the interleaved pair runs below) where `tcpMux = false` runs at
3096-3280 MiB/s on the same box with TLS off. That gap is not a defect: the
non-mux path hands the socket pair to `splice(2)` on Linux, and a framed
transport cannot splice — it must see the bytes. The number that matters is
therefore the mux path against Go's mux path, which is where frp-rs is ahead
(679 vs 531 MiB/s at eight streams, TLS on).

## Three hypotheses, falsified by measurement

- **Flow control.** Steady-state stream window already reaches 4 MiB (traced
  `RUST_LOG=yamux=debug`: 0.25 → 0.5 → 1 → 2 → 4 MiB in 33 ms, cap never hit),
  and a 16 MiB initial credit changed nothing (694 vs 651 MiB/s, inside noise).
  Window is not the limiter.
- **Per-byte copying.** A probe that deleted the receive-side payload copy
  (`vendor/yamux/src/connection/stream.rs:360`) — the hard upper bound on any
  zero-copy refactor — moved throughput by nothing (611/656 vs 634/609). `perf`
  put the whole memcpy/memset family at 8.2% of samples; `entry_SYSCALL_64` was
  56.7% with `sendto` alone at 27.9%.
- **Syscall count by itself.** Making the frame writer emit header+body in one
  `poll_write_vectored` (`vendor/yamux/src/frame/io.rs`) changed neither
  throughput nor calls/byte, because on the server the wrapper chain degraded
  every vectored call to "write the first non-empty slice".

## The defect the third hypothesis uncovered

`impl AsyncWrite for PreReadStream` (`frp-core/src/transport/mod.rs:2559`) had
`poll_write`, `poll_flush`, `poll_shutdown` — and no `poll_write_vectored`, so
tokio's default applied and every mux frame left frps as two segments: a 12-byte
header and a 64 KiB body. `frpc` builds its mux rail without that wrapper, and its adapter
(tokio-util's `WriteCompat`) has no vectored method either, so the client split
frames too; the forwarding in `frp-core/src/mux.rs` (`VectoredWrite`) is the
second half of the fix, without which only frps would have gained.

Forwarding the method, plus the single-vectored-frame writer, measures:

| | MiB/s (8 streams) | MiB/CPU-s | out-segments/MiB |
|---|---|---|---|
| before | 1108 (interleaved pairs) | 492 | 96.2 |
| after | 1207 | 536 | 87.3 |

+8.9% on 3/3 interleaved pairs (+7.2% on 4/4 against the writer-only patch), no
change at one stream (881 → 869) and none on the `tcpMux = false` control
(3077 → 3134). Most of the gain is the removed 12-byte segment, not the syscall:
the box sends 9% fewer segments per MiB, which is what a header written
separately from a 64 KiB body costs.

## What was NOT measured

- macOS. The same mux cell reports differently there (an 11% deficit against Go
  on an 8-core Mac that does not reproduce on Linux), and nothing here explains
  it.
- WAN. Loopback has no segments-in-flight cost, so removing a small segment is
  worth more on a real path than these numbers show.
- The vendored crate has no unit tests, so frame framing is covered only by
  `frp-core`'s mux/protocol tests (120) and the protocol matrix.
