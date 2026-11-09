# What a tcpMux frame costs, and the one knob that moves it (2026-11-10)

**Status (2026-11-10).** Accepted as a measurement record, **nothing landed**.
§2–§4 are three structural changes that were built, measured and rejected
because none moved throughput. §5 is the one setting that did move it, and the
counter-measurement that stopped it from becoming the default.

## 1. The gap and the unit

Same host, same harness, same peer, `linux/arm64` container with 4 vCPUs,
64 KiB writes, `TCP_NODELAY`, one-way stream unless marked ping-pong.
MiB/s, medians of three interleaved runs:

| | Go frp v0.72.0 | frp-rs (before this change) |
|---|---|---|
| tcp, 1 flow | 1507 | 1255 |
| tcp, 4 flows | 1773 | 1348 |
| tcp with `tcpMux` off, 4 flows | 3163 | 2630 |
| ws, 1 flow | 1199 | 726 |
| tcp-tls, 4 flows | 1825 | 1369 |

Rust is ~17% behind on the **plain** bridge too, so nothing here is a
`tcpMux`-specific defect; the mux path is simply where the product spends its
time, because `tcpMux` is on by default.

## 2. The cost model

Throughput plateaus at the same *frame* rate at 1 and 4 flows (~40–44k
frames/s), so a fixed per-frame cost dominates: comparing the mux path with the
non-mux path on the same binary, one MiB costs 0.774 ms with mux and 0.380 ms
without it — 0.394 ms per MiB, i.e. **≈12 µs of fixed cost per 32 KiB frame**.
That is the order of a loopback `write` plus the peer's wakeup, which is why
none of the three experiments below (each of which removed *work*, not
*round trips*) changed anything.

## 3. Single `writev` per yamux frame — no gain

`vendor/yamux/src/frame/io.rs` wrote the 12-byte frame header and the body as
two separate `write` calls on buffered transports. Collapsing `WriteState` into
one `Frame { header, header_offset, buffer, body_offset }` state and issuing a
single `poll_write_vectored([&header[..], &body[..]])`, with partial-progress
and `written == 0` handling and the body returned to the pool on completion,
plus `poll_write_vectored`/`is_write_vectored` forwarding through
`frp-core/src/mux.rs` (`Compat` does not forward vectored writes —
`tokio-util-0.7.20/src/compat.rs:291-310`), measured **1241 / 1337 MiB/s**
(1 flow / 4 flows) against a 1213 / 1340 baseline: inside noise.

## 4. One copy instead of two — no gain

The mux data path copied every chunk twice: `frp-core/src/protocol.rs`
(`write_v2_frame_raw`) merged header and payload into a fresh `Vec` because the
writer is not vectored, then `vendor/yamux/src/connection/stream.rs`
(`Stream::poll_write`) copied that into its pooled frame body. Adding
`Stream::poll_write_bufs(&[&[u8]])` — fill one pooled body straight from the
slices, `k = min(send_window, sum(len), split_send_size)` — and a
`YamuxStream` newtype implementing tokio `AsyncWrite` with
`is_write_vectored() == true` deleted the intermediate `Vec`. Measured over
three interleaved pairs: 4 flows **1388.6 → 1364.9** (base → change), 1 flow
**1259.8 → 1286.3**. No gain, so the copy is not on the critical path.

## 5. What moved: 64 KiB per frame (measured, not adopted)

The frame budget says "more bytes per frame". Raising the bridge buffer — and
with it the derived `split_send_size` — from 32 KiB to 64 KiB:

| row | 32 KiB | 64 KiB | delta |
|---|---|---|---|
| tcp, 4 flows | 1348.5 | 1512.8 | **+12.2%** |
| tcp, 1 flow | 1255.3 | 1332.9 | +6.2% |
| tcp-tls, 4 flows | 1368.5 | 1524.1 | +11.4% |
| ws, 1 flow | 726.1 | 964.2 | +32.8% |
| ws, 4 flows | 1018.0 | 1085.6 | +6.6% |

The split stays capped at `MAX_MUX_FRAME_PAYLOAD` = 64 KiB: a larger frame
cannot cross the WebSocket transport, whose reader rejects anything above
`V2_MAX_FRAME_PAYLOAD + 128` and kills the session.

**Why the default stays at 32 KiB.** `scripts/protocol-matrix.sh` on the same
macOS host, the same binaries and `FRP_BRIDGE_BUF_KB` as the only difference:

| row | 32 KiB | 64 KiB | delta |
|---|---|---|---|
| tcp-plain | 526.3 | 530.2 | +0.7% |
| tcp-tls-mux | 288.8 | 312.9 | +8.4% |
| ws-plain | 301.5 | 165.5 | **-45%** |
| ws-tls | 222.8 | 133.2 | **-40%** |
| ws-tls-mux | 185.8 | 181.2 | -2.5% |
| wss | 226.2 | 134.0 | **-41%** |

The loss is confined to the WebSocket rows that do **not** run through yamux,
and it reproduced in three runs and with `FRP_BRIDGE_BUF_KB` alone (no rebuild).
`ws`/`wss` without `tcpMux` is a supported configuration, so a 64 KiB default
would trade a 12% mux win for a 45% WebSocket loss. Worth noting the container
told the opposite story for the mux-over-ws row, where 64 KiB measured 726 →
964 MiB/s — the macOS regression is in the non-mux WebSocket write path, not in
the frame size itself.

Suspected mechanism, **not verified**: without yamux the bridge writes the
whole chunk to `WsByteStream`, which copies and masks it into `write_buf`
(`frp-core/src/transport/websocket.rs::build_frame_into`) and then writes the
frame; a 64 KiB frame on macOS loopback takes more partial-write rounds, and
each round returns `Pending` with a self-wake (`websocket.rs:1010-1011` on the
copy path, `websocket.rs:1057-1059` on the drain path), so the per-byte cost
grows with frame size there.

Cost of the knob when used: 2x64 KiB of buffer per live bridge instead of
2x32 KiB, and the pool ceiling doubles from 4 MiB to 8 MiB per process
(`MAX_POOLED_BUFFERS` = 128).

## 6. Inline writes from the bridge task — measured, not landed

`keep/yamux-inline-write-v2` (2026-11-09) let `Stream::poll_write` write
directly on the caller's task when the connection write lock is free, falling
back to the channel, with flush waiters woken by the driver. On this benchmark
it measured 4 flows **1274.9** against a 1400 baseline: no better, and it cost
a page of concurrency reasoning. Keeping the queue means a single writer and
therefore a single serialization point per session; removing it does not pay
because the limit is the round trip, not the hand-off.

## 7. What is left

frp-rs is still ~15% behind Go frp on the mux path (1513 vs 1773 MiB/s at 4
flows) and ~17% behind on the plain path. Nothing measured above explains it:
copies, syscalls and the channel hop are each worth ~0. A CPU profile of both
processes during a 4-flow run is the next step — the `profiling` feature can
dump one — and until that lands, treat the remainder as unexplained rather
than as a known defect.

## 8. Reproduce

Harness and binaries live outside the tree (`/Users/cdf/kcpbench`): the Go frp
v0.72.0 binaries, an `abbench` peer (`sink`/`echo`/`stream`/`pp`), and
`protoab.sh <go|rs> [tcp|tcp-tls|ws|wss|quic|kcp|kcp-tls]`, which runs both
stacks in one container with the same peer:

```bash
docker run --rm -v /Users/cdf/kcpbench:/w --platform linux/arm64 \
  -w /w debian:bookworm-slim bash /w/protoab.sh rs tcp
```

The Rust binaries are built from this tree inside `rust:alpine`:

```bash
docker run --rm -v $PWD:/src -v /Users/cdf/kcpbench:/w --platform linux/arm64 \
  -w /src rust:alpine sh -c \
  'RUSTUP_TOOLCHAIN=1.99.1 CARGO_TARGET_DIR=/w/rsbuild cargo build --locked --release -p frps -p frpc'
```

`protoab.sh` honours `FRP_BRIDGE_BUF_KB` and `MUX`, which is how §5's table was
produced from one binary pair. The rates are MiB/s (the harness divides by
1024²), not MB/s.
