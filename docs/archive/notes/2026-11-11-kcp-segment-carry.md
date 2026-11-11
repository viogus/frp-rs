# KCP: fill segments before sending them

Date: 2026-11-11
Status: landed
Related: `2026-11-11-kcp-stream-vs-go.md`, `2026-11-11-kcp-avx2-parity.md`,
`2026-11-11-kcp-sendmmsg.md`

## Symptom

After the AVX2 parity pass (`b3984bb7`) and the batched `sendmmsg` sends
(`fe45f022`), a one-flow KCP bulk stream through frps + frpc measured
**60 MiB/s** against Go frp v0.72.0's **102 MiB/s** on the same VM. Datagram
counts were also unequal. On the pre-AVX2/sendmmsg build (`/root/bench/base-bin`)
frp-rs sent 663,234 datagrams for 512 MiB where Go sent 537,685 — 1.23× the
packets for the same payload. On the build this note measures against
(`fe45f022`, `/root/bench/merged`) the same 512 MiB took 636,594, which is the
baseline the Result section's −5.1% is computed from; the two frp-rs counts
differ by 4.2% because they are different binaries, so they are quoted
separately rather than interchanged.

## Cause

The bridge hands the KCP stream whatever a single socket read returned —
16,406 bytes in the measured runs — and every write was flushed immediately.
16,406 bytes is 12 full 1,326-byte segments plus a **494-byte tail**, and the
tail is sent as its own short segment. Counting segments from inside the sender
(debug counters in a scratch tree, `SEGCOUNTS`/`MSSAT`) showed the average data
segment carrying **1,244 bytes of payload against an mss of 1,326**: ~6% of the
mss capacity wasted, which on a fixed payload works out to ~843 data segments
per MiB where full segments need 791, i.e. ~6.6% more. Control and keepalive
writes (36 bytes average) had the same problem at a smaller scale.

## Change

`KcpSession::send_carry` (`frp-core/src/kcp/session.rs`) queues the write, sends
only whole `mss`-sized segments and keeps the remainder in a `carry` buffer that
the next write tops up. Two escape hatches:

- a write smaller than one segment that arrives with an empty carry is sent
  immediately, so the interactive path (a keypress, a small command) gains no
  latency;
- the driver flushes the carry on its 10 ms tick and on an explicit flush, so a
  stream that pauses never strands its last bytes and control messages (Login,
  NewProxy, StartWorkConn) never wait for the next write.

The carry is bounded by `mss - 1` bytes. The socket driver
(`frp-core/src/kcp/socket.rs`) only flushes on a data write when the write
actually completed a segment, and it flushes the carry before an explicit
`WriteRequest::Flush`.

## Result

Same host, same harness (`/root/bench/kcp4.sh`, one flow, 2048 MiB, tcpMux on),
interleaved:

| run | before (`fe45f022`) | after |
|---|---|---|
| 1 | 60.1 MiB/s | 63.8 MiB/s |
| 2 | 60.1 MiB/s | 62.7 MiB/s |
| 3 | 60.7 MiB/s | 61.2 MiB/s |

Means 60.3 → 62.6 MiB/s (**+3.8%**). The packet-count side is a separate,
shorter shape — 512 MiB, one run per side, same harness — where the same
change measured 636,594 → 604,047 datagrams (**−5.1%**) at 59.2 → 62.9 MiB/s
(+6.3%).

## Rejected

- **Batching the ack list to the tick** (`Kcp::flush_data`, leaving ACKs for
  `update()` every 20 ms). It removed 48k datagrams but cost 28% of throughput
  (62.9 → 45.4 MiB/s): with ACKs arriving 50 times a second the sender's
  `una` advances in large jumps and its 1,024-segment send window stalls. The
  one-ack-per-write cost (78k datagrams per 512 MiB against Go's ~9k) is real
  but cheaper than the stall it buys.
- **Aligning writes to FEC groups** (`data_shards` × mss = 13,260 bytes).
  Measured 64.8 / 62.6 MiB/s against 63.8 / 62.7 for segment alignment and no
  change in datagram count: FEC groups are formed from the segment stream in
  order, so where a write ends does not change how groups fill. Segment
  alignment is kept because it holds far fewer bytes back.

## What is left

frp-rs is still ~1.6× behind Go on this shape (62.6 against 101.7 MiB/s), at
~32 µs of CPU per datagram against Go's ~21 µs. The remaining per-packet cost is
the KCP driver loop itself (profile after this change: kernel wakeups after
`epoll`, `clock_gettime`, the yamux poll on the muxed connection), not the
codec: parity encode is now ~1.4% of frps samples.

## Limits

- One host, one flow, one shape (one-way 2048 MiB, tcpMux on), three pairs.
  Four flows were measured once per side (60.7 → 61.7 MiB/s) but not as
  interleaved pairs, so no 4-flow ratio is claimed here.
- XTCP's P2P transport is unchanged: it writes through `send_chunked`
  (`frp-core/src/xtcp_p2p.rs`), not through the socket driver, so it keeps
  emitting short tail segments. That path is a separate target.
- The VM is itself containerised (`veth` shows in profiles), so absolute rates
  are not a hardware ceiling.
- The carry holds at most `mss - 1` bytes, and at most one tick (10 ms) of
  latency is added to a stream that stops mid-segment. The buffer only ever
  grows to the largest write seen and never shrinks (`mem::take` + `truncate`),
  so a session can retain one bridge write's worth of capacity (~64 KiB at the
  default) for its lifetime.

## Reproduce

The harness is a throwaway on the measurement VM (not in the tree): it writes an
frps config on port 19100 with `kcp_bind_port = 19101` and an frpc config that
dials 19101 with `transport_protocol = "kcp"` and `tcpMux` on, starts
`abbench sink 19054`, waits for the proxy port 19056, then runs
`abbench stream 19056 <MiB> <flows>` and prints the rate plus CPU ticks. The
Result table compares `fe45f022` (before) against `2bcb1c99` (after):

```bash
# /root/bench/kcp4.sh <binary-dir> <label> <MiB>
bash /root/bench/kcp4.sh merged before 2048   # fe45f022
bash /root/bench/kcp4.sh c3     after  2048   # 2bcb1c99
```
