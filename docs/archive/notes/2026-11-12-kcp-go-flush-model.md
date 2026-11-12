# KCP: three ports of Go's flush behaviour, all slower than what we ship

Measured 2026-11-12. **Negative result.** The hypothesis was that frp-rs's
per-write flush is what costs it the bulk-stream gap against Go frp
(66 against 95-102 MiB/s on a 4-vCPU Linux VM). Porting three pieces of Go's
behaviour — delaying the write-path flush to the tick, enlarging the UDP socket
buffers to Go's 4 MiB, and flushing when an ACK slides the send window — each
made the same stream slower: 24-30 MiB/s for the tick-only variants (2.2-2.8x
slower than shipped) and 61-63 MiB/s for the ACK-driven variant (about 6%
slower).

## 1. What Go actually does

`frp` v0.72.0 sets the same KCP options on both ends — server in
`pkg/util/net/kcp.go:60-65` (after `AcceptKCP`) and client in `:119-124`:

```go
conn.SetStreamMode(true)
conn.SetWriteDelay(true)      // Write() itself does not flush
conn.SetNoDelay(1, 20, 2, 1)  // interval = 20 ms
conn.SetMtu(1350)             // mss 1326 — not the 1400 library default
conn.SetWindowSize(1024, 1024)
conn.SetACKNoDelay(false)     // only gates the "ack immediately" branch
```

The write path (`kcp-go` v5.6.73 `sess.go:343-399`) only cuts the payload into
segments and appends them to `snd_queue`; it flushes **when the send queue has
reached the window** (`waitsnd >= snd_wnd`, 1024 segments ≈ 1.36 MB) or when
`writeDelay` is off (`sess.go:389-393`). Everything else waits for
`UDPSession.update` (`sess.go:769-782`), which runs every `interval` and calls
`kcp.flush(IKCP_FLUSH_FULL)`.

There is a second, larger trigger: `KCP.Input` ends with
(`kcp.go:723-740`)

```go
if flushSegments != 0 {                                    // window slid / fastack
    kcp.flush(IKCP_FLUSH_FULL)
} else if len(kcp.acklist) >= int(kcp.mtu/IKCP_OVERHEAD) { // "clocking"
    kcp.flush(IKCP_FLUSH_ACKONLY)
} else if ackNoDelay && len(kcp.acklist) > 0 {
    kcp.flush(IKCP_FLUSH_ACKONLY)
}
```

where `flushSegments` is set by `parse_una` (`kcp.go:639-641`) and
`parse_fastack` (`:648`). So in a bulk stream, where an ACK arrives every few
miliseconds and always advances `snd_una`, **Go flushes a full round on every
inbound ACK** — as often as our write-path flush, not rarely. The ACK clocking
branch (~58 queued ACKs) is separate and is not gated by `ackNoDelay`.

The same reading also showed two smaller differences, both now measured:

- **Socket buffers.** Go's KCP *listener* sets `SetReadBuffer`/`SetWriteBuffer`
  to 4 MiB (`pkg/util/net/kcp.go:40-41`); the client constructor sets none, and
  frp-rs uses 1 MiB (`frp-core/src/kcp/listener.rs:14-16`). Ported: no effect
  (section 3).
- **MTU.** Go pins 1350; 1400 is kcp-go's *library* default, so our 1400 is a
  deliberate deviation from Go frp. `docs/archive/notes/2026-11-11-kcp-mtu-1400.md`
  records the gain and section 4 shows it is interoperable.

## 2. The three ports

Probe branches, not for merge: `perf/kcp-flush-model` (tick-only + socket
buffers) and `perf/kcp-ack-flush` (ACK-driven flush).

- **Tick-only.** `FRP_KCP_DEFER_FLUSH=1` makes `handle_data_burst` skip its
  flush and makes `WriteRequest::Flush` complete its oneshot without flushing,
  so only the driver tick flushes; `FRP_KCP_TICK_MS` sets the tick period.
- **Socket buffers.** `FRP_KCP_UDP_BUF_KB` overrides the UDP receive/send
  buffer sizes (1 MiB default).
- **ACK-driven flush.** The faithful half of Go's model: `Kcp::flush_segments`
  is set when `parse_una` drops acked segments or `parse_fastack` ticks a
  segment, and `KcpSession::take_ack_flush()` lets the driver flush right after
  the `input()` that caused it (`frp-core/src/kcp/socket.rs`,
  `frp-core/src/kcp/protocol.rs`, `frp-core/src/kcp/session.rs`).

All three are measurement switches; none is a configuration surface.

## 3. Result

One flow, 2048 MiB one-way, `tcpMux` on, `abbench stream`, gc VM (4 vCPU
AMD EPYC-Milan), CPU in 100 Hz ticks from `/proc/<pid>/stat`, alternating runs.

| arm | runs (MiB/s) | CPU frps/frpc (ticks) |
|---|---|---|
| shipped — flush once per write burst (≤4 × ~16 KiB), 10 ms tick | 65.5 / 66.4 / 65.0, and 64.9 / 65.7 on a rebuilt base | 3516/3565, 3469/3491, 3576/3581 |
| tick-only, 10 ms tick | **27.3 / 29.9 / 27.5**, 23.9 / 29.5 | 2500-2530 / 5650-5890 |
| tick-only, 20 ms tick | **31.6 / 26.1** (one pair) | 2620-2890 / 5940-6350 |
| ACK-driven flush (Go's `kcp.go:723-728`) | **62.6 / 62.5 / 61.3** | 3713/3787, 3730/3809, 3782/3896 |
| 4 MiB socket buffers, shipped | 62.9 / 65.3 | 3603/3674, 3571/3597 |
| 4 MiB socket buffers, tick-only | **26.6 / 26.5** | 2547/6273, 2432/6318 |

Deferring the flush to the tick costs 2.2-2.8x throughput and raises client CPU
by 1.6-1.8x. Flushing on ACKs — closer to what Go really does — still costs
about 6% and raises CPU. The run-to-run spread on this host is ±7%, so only the
tick-only arms are unambiguous; the ACK-driven arm is consistently negative
across three pairs but the effect is small.

Two observations bound the interpretation:

- The 20 ms arm was run twice per binary, so it is context, not a measured
  cadence curve. At a 10 ms tick the deferred arm sits at 24-30 MiB/s and the
  shipped arm at 65-66, so the loss is not the 20 ms period alone.
- Enlarging the socket buffers to Go's 4 MiB changes nothing in either
  direction, so the tick-only loss is not a receiver buffer overflow.

## 4. Interoperability of the 1400-byte MTU (the one win that stands)

`kc-m9.sh` moves a 1024 MiB stream between a Rust build at MTU 1400 and the Go
v0.72.0 binaries at MTU 1350:

| server | client | MiB/s |
|---|---|---|
| frp-rs | Go | **83.1 / 80.3** |
| Go | frp-rs | 60.9 |

Both directions complete without stalls, so an asymmetric MTU is fine on the
wire (both sides read into 1500 bytes and KCP never negotiates MTU). The
numbers also restate where the gap lives: with Go as the client the same
servers carry 80-83 MiB/s, with frp-rs as the client 61-66 — the **client** is
the limiting end, not the server.

## 5. What this rules out

With this run, the implementations of Go's flush behaviour are measured and
negative: the tick-only write-delay model (10 ms and 20 ms), the 4 MiB socket
buffers, and the ACK-driven flush. Added to the passes already landed
(`sendmmsg`, `recvmmsg`, write coalescing, segment carry, AVX2 FEC, MTU 1400)
and the earlier negative results (copy elimination, yamux stream window,
tokio-vs-blocking relay, ACK batching to the tick), that leaves no single call
site in the KCP or bridge path that has not been either improved or measured
and rejected.

The remaining 70 MiB/s of headroom against Go is therefore not a missing
flush trigger, a socket buffer, a copy, or a syscall batch. What the probes do
show is *where* to look: the limiting end is the client, its CPU is dominated
by syscalls and scheduler wakeups (33.6% + 22% in the profile) yet no thread is
saturated (~1.1 cores of 4), and the same server reaches 80-83 MiB/s with a Go
client. That is a pacing/wakeup shape, and the tick-only arms show which
direction is *wrong* to go; they do not tell us which shape is right.

## 6. Reproduce

```bash
# on the VM
/root/bench/kcd.sh /root/bench/base-real base  1 2048 true 0  10
/root/bench/kcd.sh /root/bench/base-real base  1 2048 true 0  10
/root/bench/kcd.sh /root/bench/dfr       defer 1 2048 true 1  10
/root/bench/kcd.sh /root/bench/dfr       defer 1 2048 true 1  20
FRP_KCP_UDP_BUF_KB=4096 /root/bench/kcd.sh /root/bench/dfr defer4m 1 2048 true 1 10
/root/bench/kcd.sh /root/bench/ackfl     ackfl 1 2048 true 0  10
```

`kcd.sh` signature: `<bindir> <label> <flows> <MiB> <tcpMux> <deferFlush> <tickMs>`;
it kills stale `frps`/`frpc`, writes `/tmp/k3s.toml` (bind 19100, `kcp_bind_port`
19101) and `/tmp/k3c.toml` (KCP transport, `tcpMux` as given), starts
`abbench sink 19054`, waits for the proxy port 19056 and prints MiB/s with both
processes' CPU ticks.

Binaries: `/root/bench/base-real` (a fresh `git worktree` of `origin/main` at
`43637997`), `/root/bench/dfr` (`perf/kcp-flush-model`), `/root/bench/ackfl`
(`perf/kcp-ack-flush`).
