# The server's zero-copy splice path was dead: a wrapper hid it

**Date:** 2026-11-13
**Status:** Fixed — drained `PreRead`/`BufferedRead` wrappers now forward the
raw-TCP fast path. Plain `tcp` proxies (`tcp_mux = false`, `transport.tls.enable =
false`) move 1.7-2.0x more bytes.

## Symptom

On the four-vCPU measurement VM a single plain `tcp` proxy streamed
**1320 MiB/s** without TLS, while an `abbench` sink/source pair with no frp in
the middle moved **2489 MiB/s** over the same loopback. `strace -c` on each
process showed why: the client issued 4596 `splice` calls for a 512 MiB stream
and the server issued none — it ran the userspace copy loop (`sendto` +
`recvfrom` at 64 KiB per iteration).

## Root cause

The server wraps every accepted connection stream in a byte-replay wrapper
before it reaches the bridge:

| side | transport before the bridge | `try_tcp()` |
| --- | --- | --- |
| client (`tcp_mux = false`, TLS off) | `IoStream::Tcp` | `Some` → splices |
| server user conn | `IoStream::Tcp` | `Some` |
| **server work conn** | `IoStream::PreRead` / `IoStream::BufferedRead` | **`None` → copy loop** |

The work connection is sniffed for the V2 magic and the connection type before
the proxy bridge sees it, so it always arrives wrapped. Both wrappers used the
default `Transport` implementations of `try_tcp`/`try_tcp_mut`/`into_tcp`,
which return `None` — correct for a wrapper with bytes still to replay, but
wrong once those bytes are spent: `into_split` already applied exactly that
rule (it refuses only when `pos < len`).

`relay_plain_fast_inner` requires *both* sides to be raw TCP before it calls
`frp_core::splice::bridge_splice`, so the server half never qualified and the
fast path was unreachable in every configuration — not just this one.

## Fix

`frp-core/src/transport/pre_read.rs` and
`frp-core/src/transport/buffered_read.rs` now delegate the fast path when their
replay buffer is fully consumed:

```rust
fn try_tcp(&self) -> Option<&tokio::net::TcpStream> {
    if self.fully_drained() { self.inner.try_tcp() } else { None }
}
```

(`into_tcp` uses the same guard; `PreReadTransport::fully_drained()` is
`pos >= pre_read.len()`, `BufferedReadTransport` compares `pos >= buf.len()`.)
Nothing is dropped: a drained wrapper holds no bytes, and an undrained one
still refuses, so the copy loop keeps running whenever replay is pending.

## Measurements

VM: 4-vCPU AMD EPYC-Milan, loopback, release build, `tcp` proxy, one-way
`abbench` stream, `abbench sink` peer. Before = the same tree without the
delegation (identical binaries besides this patch).

| shape | before | after |
| --- | --- | --- |
| 1 flow, 2048 MiB, TLS off, `tcp_mux = false` | 1320 / 1322 MiB/s | **2248 / 2570 MiB/s** |
| 1 flow, TLS default (`enable = true`) | 669 / 751 | 746 / 642 (unchanged, noise) |
| 8 sessions, 128 MiB each, TLS off, 1 worker | 1227 / 1201 MiB/s | **2266 / 2465 MiB/s** |
| 8 sessions, 128 MiB each, TLS off, 4 workers | 2105 / 2548 MiB/s | **2867 / 3122 MiB/s** |
| raw loopback ceiling (no frp) | 2489 (1 flow), 4661 (8 flows) | — |

Server CPU at 1 flow fell from 0.99 to 0.81 cores (the client stays at 0.81-0.86,
it was already splicing). `strace -c` on the patched server: 1587 `splice` calls
and no `sendto`/`recvfrom` for a 512 MiB stream.

## What this does *not* cover

The win needs **raw TCP on both sides of both hops**, i.e. `tcp_mux = false` and
`transport.tls.enable = false`. The defaults (`tcp_mux = true`,
`tls.enable = true`) end the client-side hop in a yamux stream and a TLS record
layer, neither of which `splice(2)` can cross:

* `tcp_mux = true` (default): the work connection is a yamux stream — copy loop,
  ~600 MiB/s per session on this VM against 2500 splice-able;
* `transport.tls.enable = true` (default): TLS costs ~2x CPU per byte
  (622-684 MiB/s, 0.97 cores server + 0.86 client) — the record layer forces
  16 KiB writes (63,845 `sendto` per stream against 15,676 plain), and neither
  end can be spliced. AES-128-GCM itself is not the limit: `openssl speed` puts
  it at 3.6 GB/s on this VM.

Those two are the remaining default-path costs, and neither is addressed here.

## Harness notes

* `pkill -f "abbench sink"` over `ssh` matches the remote shell's own command
  line and kills the session (silent exit 255) — use `pkill -x abbench`.
* `wait` with no arguments waits for the background servers too; collect the
  stream PIDs and `wait "$p"` per PID.
* macOS `ControlCenter` (AirPlay) holds TCP 7000, so test configs must set
  `bind_port` explicitly; `--config-dir` and reload tests need `pkill` between
  runs or the next bind fails with `Address already in use (os error 48)`.
