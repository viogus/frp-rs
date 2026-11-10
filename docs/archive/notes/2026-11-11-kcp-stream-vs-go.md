# KCP: the stream shape is 2× behind Go, the ping-pong shape is ahead

**Question.** After the GF(2^8) multiply tables (#596) and the 64 KiB bridge
buffer, every TCP row beats Go frp v0.72.0 on the same host. KCP had no
publishable comparison: the earlier "+23%" came from a benchmark whose `stream`
mode reported rates it did not produce (see
[`2026-11-10-real-host-throughput.md`](2026-11-10-real-host-throughput.md) §1),
and it was withdrawn. This note measures KCP properly.

## Result

Linux VM (4 vCPU AMD EPYC-Milan, Debian 13, loopback), 2048 MiB one-way stream,
`tcpMux` on, two runs per cell:

| shape | frp-rs | Go v0.72.0 | ratio of means |
|---|---|---|---|
| 1 flow, stream | 49.6 / 49.5 MiB/s | 105.9 / 100.7 MiB/s | **0.48×** |
| 4 flows, stream | 48.6 / 48.3 MiB/s | 105.9 / 100.9 MiB/s | **0.47×** |
| CPU per MiB | 46.2 ms | 22.1 ms | **2.09×** |
| UDP datagrams per 512 MiB | 661,824 | 536,444 | **1.23×** |

With `tcpMux` on, all flows of one proxy ride **one** KCP session per side, so
this run cannot separate flow count from session count: the 4-flow row repeats
the 1-flow ceiling (frp-rs ~49, Go ~103 MiB/s) rather than testing scaling.
Measured CPU: frp-rs 94.6 CPU-seconds per 41.3 s wall, Go 45.3 per 19.8 s — and
because the client and the sink share the same four vCPUs the box is
oversubscribed, which is why CPU per byte sets throughput here (see the same
caveat in the README's Performance section). One session saturating one driver
task is a **possible** explanation, not something this experiment established.

The small-payload shape points the other way: through a 64 KiB ping-pong the
in-tree KCP answers 394 round trips/s at one flow where Go answers 40. That
number comes from a **different harness and host** (Linux container,
`abbench pp`), so it establishes direction, not a ratio.

## What the numbers say

1. **frp-rs puts 1.23× more datagrams on the wire for the same payload** —
   811 B of payload per datagram against Go's 1,001 B (the same measurement
   expressed two ways: 661,824/536,444 = 1.2337 and 1,000.8/811.2 = 1.234).
   The FEC parameters are not the difference — `frp-core/src/kcp/mod.rs` mirrors
   kcp-go's `10, 3` with mtu 1350 and mss 1326, and a 10+3 group at that mss
   predicts ~1,020 B per datagram, which is where Go lands. Why frp-rs lands at
   811 is **not established**. The leading candidate is **retransmission and
   control traffic**, not a smaller segment: the socket driver queues a failed
   send in `pending_udp` and drops it once that queue is full, relying on KCP to
   resend (`frp-core/src/kcp/socket.rs:828-842`), and every session already
   counts RTO retransmissions in `xmit` (`frp-core/src/kcp/protocol.rs:226`),
   so one counter per side settles it. A per-direction packet count would
   localise the excess to one side but could not classify it; the KCP cmd byte
   or `xmit` is what classifies.
2. **The rest is per-packet cost.** CPU per byte is 2.09× while packets per byte
   are 1.23×, so frp-rs also spends more CPU per packet. A `perf` run on the
   production binary (symbols stripped) puts ~26% of frpc samples in the
   `sendto` syscall path, 3.5% in `clock_gettime` through the vDSO, and 2% in
   wake-up spin locks — i.e. per-packet work, not bulk copying.
3. **The FEC encode is still the hottest named user-space frame** — and it was
   vectorised after this measurement, which took the stream shape from 49 to 58
   MiB/s (**+19%**, CPU −16%); see
   [`2026-11-11-kcp-avx2-parity.md`](2026-11-11-kcp-avx2-parity.md). Before that
   change the wording was: On the
   debuginfo build (the stripped release binary cannot resolve it) frps spends
   **16.3%** of its samples in `KcpSession::fec_encode_output`, and frpc 4.3% in
   the `KcpSocket::run` loop plus 3.6% in `clock_gettime` and 3.6% in wake-up
   spin locks. Go delegates this to `klauspost/reedsolomon`, which vectorises
   the same 10+3 encode; a scalar table loop is ~10 dependent lookups per byte.
   The tables made the multiply 3× cheaper (#596) and that win stands — the
   point here is that the remaining cost is a *vectorisation* gap, not a
   correctness or configuration one.

## Limits

- Loopback only: a real path with loss would move both numbers, and KCP's ARQ
  would amplify the difference in packets (more retransmits on the slower side).
- One host class (4 vCPU, CPU-bound). The TCP matrix on the same host
  (`README.md` Performance table, four flows over the tcpMux/TLS variants) shows
  frp-rs ahead by 31-50%, so the deficit here is KCP-specific, not a general
  data-plane problem.
- The ping-pong comparison is from a different harness and host (Linux
  container, `abbench pp`), so it establishes direction, not a ratio.
- Reported here as a whole: 2.1× behind at a CPU-bound single session, with the
  FEC encode (16%) and per-packet syscalls as the named costs. Nothing in this
  note shows what a vectorised encode would recover.

## Reproduce

```
# on the host, with both v0.72.0 builds in place
bash /root/bench/kcp3.sh rs rs rs-f1 1 2048 true   # frps, frpc, label, flows, MiB, mux
bash /root/bench/kcp3.sh go go go-f1 1 2048 true
```

`kcp3.sh` writes both configs (frp-rs: `kcp_bind_port`, client
`server_port=<kcp port>` + `transport_protocol = "kcp"`; Go: `kcpBindPort`,
`transport.protocol = "kcp"`, `tcpMux` matched on both sides), starts
`abbench sink`, waits for the proxy port, and prints the stream rate plus the
CPU seconds each process burned. Datagram counts come from `/proc/net/snmp`
(`Udp: InDatagrams OutDatagrams`) around the same run.
