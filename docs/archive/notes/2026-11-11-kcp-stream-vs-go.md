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

| shape | frp-rs | Go v0.72.0 | ratio |
|---|---|---|---|
| 1 flow, stream | 49.6 / 49.5 MiB/s | 105.9 / 100.7 MiB/s | **0.48×** |
| 4 flows, stream | 48.6 / 48.3 MiB/s | 105.9 / 100.9 MiB/s | **0.46×** |
| CPU per MiB | 46.2 ms | 22.1 ms | **2.09×** |
| UDP datagrams per 512 MiB | 661,824 | 536,444 | **1.23×** |

Neither side scales with flow count: one KCP session already saturates its
driver task, so 4 flows share the same ceiling as 1 flow (frp-rs ~49 MiB/s,
Go ~103 MiB/s). Both consume ~2.3 cores at their own rate, i.e. the difference
is CPU per byte, not parallelism.

The small-payload shape points the other way: through a 64 KiB ping-pong the
in-tree KCP answers 394 round trips/s at one flow where Go answers 40
(measured in a Linux container, same harness).

## What the numbers say

1. **frp-rs puts ~23% more packets on the wire for the same payload.** 661,824
   datagrams per 512 MiB is 811 B per datagram; Go's 536,444 is 1,001 B. The
   FEC parameters are not the difference — `frp-core/src/kcp/mod.rs` mirrors
   kcp-go's `10, 3` with mtu 1350 and mss 1326, and a 10+3 group at that mss
   predicts ~1,020 B of payload per datagram, which is where Go lands. Why
   frp-rs lands at 811 is **not established**: candidates are a smaller
   effective segment, extra ACK/command packets in the same window, or the
   stream-mode split (`frp-core/src/kcp/protocol.rs` `mss` handling). Counting
   only one direction (ACLs on the four UDP sockets, or `tcpdump` on the
   loopback interface) would settle it.
2. **The rest is per-packet cost.** CPU per byte is 2.09× while packets per byte
   are 1.23×, so frp-rs also spends more CPU per packet. A `perf` run on the
   production binary (symbols stripped) puts ~26% of frpc samples in the
   `sendto` syscall path, 3.5% in `clock_gettime` through the vDSO, and 2% in
   wake-up spin locks — i.e. per-packet work, not bulk copying.
3. **This is not the multiply tables.** `fec_encode_output` no longer appears in
   the profile; the earlier 3× win is intact. The remaining gap is in the
   per-packet path around the FEC/KCP loops.

## Limits

- Loopback only: a real path with loss would move both numbers, and KCP's ARQ
  would amplify the difference in packets (more retransmits on the slower side).
- One host class (4 vCPU, CPU-bound). The TCP matrix on the same host shows
  frp-rs ahead by 31-50%, so the deficit here is KCP-specific, not a general
  data-plane problem.
- The ping-pong comparison is from a different harness (Linux container,
  `abbench pp`), so it establishes direction, not a ratio.

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
