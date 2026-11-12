# KCP: porting Go's flush model makes it slower, not faster

Measured 2026-11-12. **Negative result.** The hypothesis was that frp-rs's
per-write flush is what costs it the bulk-stream gap against Go frp
(66 against 95-102 MiB/s on a 4-vCPU Linux VM). Reading Go's source supported
it; porting the model refuted it: the same stream runs at **27-32 MiB/s** with
Go's write-delay behaviour, i.e. 2.0-2.4x slower than what we ship.

## 1. What Go actually does

`frp` v0.72.0 sets the same KCP options on both ends — server in
`pkg/util/net/kcp.go:60-65` (after `AcceptKCP`) and client in `:119-124`:

```go
conn.SetStreamMode(true)
conn.SetWriteDelay(true)      // Write() does not flush
conn.SetNoDelay(1, 20, 2, 1)  // interval = 20 ms
conn.SetMtu(1350)             // mss 1326 — not the 1400 library default
conn.SetWindowSize(1024, 1024)
conn.SetACKNoDelay(false)     // ACKs are not flushed early either
```

In `kcp-go` v5.6.73, `UDPSession.Write` (`sess.go:343-399`) only cuts the
payload into segments and appends them to `snd_queue`; it flushes **only** when
the send queue has reached the window (`waitsnd >= snd_wnd`, 1024 segments
≈ 1.36 MB). Everything else waits for the periodic updater,
`UDPSession.update` (`sess.go:769-782`), which runs every `interval` and calls
`kcp.flush(IKCP_FLUSH_FULL)`.

So Go batches up to a full window (≈1.36 MB) per flush and accepts a 20 ms
floor on latency. This tree instead flushes on every bridge write and on
stream `poll_flush`, which is why frp-rs moves 64 KiB per flush, answers in
2.1 ms where Go takes 20.8 ms, and loses on bulk throughput.

The same reading also showed two smaller differences, both now measured:

- **Socket buffers.** Go's KCP listener sets `SetReadBuffer`/`SetWriteBuffer`
  to 4 MiB (`pkg/util/net/kcp.go:38-39`); frp-rs uses 1 MiB
  (`frp-core/src/kcp/listener.rs:14-16`). Ported: no effect (section 3).
- **MTU.** Go pins 1350, not the library default of 1400 — so the claim in
  `docs/archive/notes/2026-11-11-kcp-mtu-1400.md` that "Go frp has always sent
  1400-byte datagrams" was wrong. Our 1400 is a deliberate deviation; section 4
  shows it is interoperable.

## 2. The port

Branch `perf/kcp-flush-model` (probe only, not for merge):

- `FRP_KCP_DEFER_FLUSH=1` makes `handle_data_burst` skip its flush and makes
  `WriteRequest::Flush` complete its oneshot without flushing, so only the
  driver tick flushes. `FRP_KCP_TICK_MS` sets the tick period.
- `FRP_KCP_UDP_BUF_KB` overrides the UDP socket buffer sizes.

Both are environment switches rather than a configuration surface: this was a
measurement, not a feature.

## 3. Result

One flow, 2048 MiB one-way, `tcpMux` on, `abbench stream`, gc VM (4 vCPU
EPYC-Milan), alternating runs, CPU in 100 Hz ticks from `/proc/<pid>/stat`.

| arm | MiB/s | CPU frps/frpc |
|---|---|---|
| shipped, flush per write, 10 ms tick | 65.5 / 66.4 / 65.0 | 3516/3565, 3469/3491, 3576/3581 |
| Go model, 10 ms tick | **27.3 / 29.9 / 27.5** | 2523/5891, 2527/5653, 2501/5826 |
| Go model, 20 ms tick | **31.6 / 26.1** | 2621/5944, 2894/6345 |
| 4 MiB socket buffers, flush per write | 62.9 / 65.3 | 3603/3674, 3571/3597 |
| 4 MiB socket buffers, Go model | **26.6 / 26.5** | 2547/6273, 2432/6318 |

Deferring the flush halves throughput and *raises* client CPU by ~1.7x. The
mechanism is consistent with the window arithmetic: with a 20 ms flush period
the sender can place at most one window (1.36 MB) per 20 ms (≈68 MiB/s
theoretical), and in practice roughly half of that arrives, because a 1 MB
burst into a 1-4 MiB socket buffer at the receiver loses datagrams and the
resulting retransmissions keep the flight size below the window. Enlarging the
socket buffers to Go's 4 MiB did not change it. Our per-64 KiB flush keeps the
pipe continuously fed and is the faster shape on this host and this hardware.

## 4. Interoperability of the 1400-byte MTU (the one win that stands)

`kc-m9.sh` moves a 1024 MiB stream between a Rust build at MTU 1400 and the Go
v0.72.0 binaries at MTU 1350:

| server | client | MiB/s |
|---|---|---|
| frp-rs | Go | **83.1 / 80.3** |
| Go | frp-rs | 60.9 |

Both directions complete without stalls, so an asymmetric MTU is fine on the
wire (the receiver reads into 1500 bytes on both sides; KCP never negotiates
MTU). The numbers also restate where the gap lives: with Go as the client the
same servers carry 80-83 MiB/s, with frp-rs as the client 61-66 — the **client**
is the limiting end, not the server.

## 5. What this rules out

With this run, every candidate named after reading Go's source is measured and
negative: the write-delay flush model, the 4 MiB socket buffers, and (earlier)
the MTU direction, segment carry, `sendmmsg`/`recvmmsg` batching, write
coalescing, copy elimination, yamux windows, FEC vectorisation, ACK batching,
and bridge buffering. The remaining 1.5x on a single-session bulk stream is a
property of this implementation's steady-state pacing, not of any one call
site, and closing it would mean redesigning the driver around a different
scheduler (kcp-go's timer-driven flush plus per-session goroutine) with no
evidence yet that the redesign wins.

## 6. Reproduce

```bash
# on the VM: /root/bench/dfr holds the probe build, /root/bench/base9 the shipped one
/root/bench/kcd.sh /root/bench/base9 base   1 2048 true 0 10
/root/bench/kcd.sh /root/bench/dfr   defer  1 2048 true 1 10
FRP_KCP_UDP_BUF_KB=4096 /root/bench/kcd.sh /root/bench/dfr defer4m 1 2048 true 1 10
```
