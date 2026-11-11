# Batching KCP writes into one flush

Date: 2026-11-11. Status: landed.

## 1. Symptom

After the AVX2 parity pass, `sendmmsg` and the segment carry, a one-flow bulk
KCP stream reached ~60 MiB/s where Go frp v0.72.0 reached ~102 MiB/s on the same
host. The profile had stopped pointing at user-space arithmetic: frps's largest
named entry was the kernel's task-wakeup path, frpc's was the driver loop
(`KcpSocket::run`) plus `clock_gettime`.

Every bridge write (one `read` from the local TCP connection, ~16 KiB) took the
whole driver round trip: wake the driver task, queue into the session, segment,
FEC-encode, one `sendmmsg`, then park again. At 65 MiB/s that is ~4,000 wakeups
and ~4,000 flushes per second per direction.

## 2. What changed

`frp-core/src/kcp/socket.rs`, write arm only:

- a write no longer flushes on its own; the arm drains up to `WRITE_BATCH = 4`
  queued `WriteRequest::Data` first (a `Flush` encountered mid-drain is honoured
  after the writes that preceded it), then issues one flush per touched session;
- the burst-end rule from the segment carry is preserved: when the write queue
  is empty after the batch, the session's carried tail is released and flushed
  immediately, so a request/response shape still answers within the same
  wakeup instead of waiting for the 10 ms tick.

Nothing in the segmentation, FEC, ACK or framing paths changed; the wire bytes
are byte-identical for the same payload.

## 3. Result

One-flow 2048 MiB bulk stream, `tcpMux` + TLS, 4-vCPU AMD EPYC-Milan VM,
loopback, single-thread transfer, CPU ticks from `/proc/<pid>/stat` (100 Hz),
eight interleaved pairs (two runs of four) of the previous commit (`d40af6fc`)
against this change:

| pair | before | after |
|---|---|---|
| 1 | 66.5 | 66.1 |
| 2 | 62.6 | 67.2 |
| 3 | 62.9 | 65.0 |
| 4 | 64.1 | 67.4 |
| 5 | 63.9 | 66.5 |
| 6 | 64.5 | 66.1 |
| 7 | 62.7 | 65.8 |
| 8 | 63.9 | 67.8 |
| mean | 63.9 | 66.5 |
| CPU ticks | 3.60k | 3.46k |

**+4.0% throughput, −4% CPU**, seven of eight pairs positive and one flat
(−0.6%). The absolute numbers move between sessions on this VM by ±3%, so read
the paired ratios, not the means.

Against Go's 102 MiB/s on the same host the gap is now ~1.5×, from 2.1× when
the parity pass started.

The small-payload shape is unchanged: the driver stops batching as soon as the
queue is empty, so a 64 KiB ping-pong round still leaves in the same wakeup that
received it. `scripts/protocol-matrix.sh` measures `kcp-plain` at 61.3 MiB/s
after the change, inside that row's spread.

## 4. Limits

- `WRITE_BATCH = 4` is a guess with one measurement behind it; the gain comes
  from fewer flushes, and going deeper trades wakeup latency for throughput
  without a measured optimum.
- One flow, one host, TLS on. Multi-flow and other transports were not measured.
- The remaining gap is per-datagram cost in the kernel and scheduler on a
  loopback host that runs both proxies against the same four cores; it is not
  established how much of that survives a real network path.

## 5. Reproduce

```bash
# build the tree, copy `frps`/`frpc` to /root/btb, the previous commit's to
# /root/recv2bin, then:
sed 's#/root/recvbin#/root/btb#' /root/vmcmp3.sh > /root/vmcmp5.sh
bash /root/vmcmp5.sh     # four interleaved pairs
```

The harness writes `kcp_bind_port = 19101`, proxies `str` on 19056 to an
`abbench` sink on 19054, and reads CPU from `/proc/<pid>/stat`.
