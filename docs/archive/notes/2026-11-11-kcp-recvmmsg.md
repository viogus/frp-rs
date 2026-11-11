# KCP: receive a burst of datagrams per wakeup

## 1. Why

The send side has been batched since `2026-11-11-kcp-sendmmsg.md`, but the
driver still woke up once per *received* datagram: a bulk stream at ~60 MiB/s
carries ~50k datagrams/s in each direction, which is 50k `recvfrom` calls and
50k `select!` iterations per second per process. On the four-vCPU VM the
profile put `KcpSocket::run` at 4% of frpc's samples and `clock_gettime` at
3.4%, both inside that loop.

## 2. What changed

`frp-core/src/kcp/socket.rs`:

- the select arm is now `_ = self.socket.readable()` followed by a drain loop
  (`drain_recv`) that keeps calling `recv_datagrams` until the socket reports
  `WouldBlock` or returns a short batch;
- `recv_datagrams` issues one `libc::recvmmsg` over up to 32 `mmsghdr`s on
  Linux (each into its own `DRIVER_RECV_BUF_SIZE` slot) and falls back to one
  `try_recv_from` elsewhere, so other platforms keep the previous
  one-datagram-per-wakeup behaviour;
- the ~200-line body of the old arm became `handle_datagram(&mut self, data:
  &[u8], src: SocketAddr)`; the six `continue`s that skipped the rest of the
  arm are `return`s, which is the same thing now that the arm is a function.

**A correctness trap worth recording**: the first version called `recvmmsg`
directly, without going through `UdpSocket::try_io`. A raw syscall does not
clear tokio's readiness, so `readable()` stayed ready, the `select!` picked
that arm every iteration, and the write arm never ran — sessions were created
and admitted but their handshake was never sent, so the proxy never came up
while both processes burned ~25k `recvmmsg` calls/s. Wrapping the call in
`socket.try_io(Interest::READABLE, ..)` restores the invariant: readiness is
cleared exactly when the batch comes back empty.

## 3. Result

One-flow 2048 MiB bulk stream, `tcpMux` + TLS, 4-vCPU AMD EPYC-Milan VM,
loopback, single-thread transfer, seven interleaved pairs of the same build
(`/root/bench/merged` vs the `recvmmsg` build), CPU ticks from
`/proc/<pid>/stat` (100 Hz):

| pair | before | after |
|---|---|---|
| 1 | 60.5 | 63.8 |
| 2 | 61.9 | 61.9 |
| 3 | 61.0 | 62.2 |
| 4 | 60.3 | 63.7 |
| 5 | 59.5 | 62.4 |
| 6 | 59.5 | 62.7 |
| 7 | 60.4 | 62.7 |
| mean | 60.4 | 62.8 |
| CPU ticks | 3.92k | 3.76k |

**+3.9% throughput, −4% CPU** on that series — about a sixteenth of what Go's
102 MiB/s still leads by, but it is the receive-side counterpart of the
`sendmmsg` change.

The shipped build also bounds one wakeup at `MAX_DRAIN_ROUNDS = 4` batches, so a
persistently full receive queue cannot starve the tick or the write arms. That
version, re-measured after the review on a busier VM (four pairs, same shape):

| pair | before | after |
|---|---|---|
| 1 | 57.5 | 64.4 |
| 2 | 57.8 | 63.1 |
| 3 | 59.4 | 63.3 |
| 4 | 59.2 | 65.1 |
| mean | 58.5 | 64.0 |
| CPU ticks | 4.05k | 3.71k |

**+9.4% throughput, −8% CPU** against a baseline that ran ~3% slower than in the
first series, so the two series bound the effect at +4-9% rather than agreeing
on one number; the sign and the CPU saving are stable across both.

## 4. Limits

- Batching is Linux-only. macOS, the BSDs and Windows keep one datagram per
  wakeup (`try_recv_from`), which is the pre-change behaviour.
- `RECV_BATCH = 32` slots of `DRIVER_RECV_BUF_SIZE` (1500 B) each: the driver holds
  48 KB of receive
  buffers, allocated once per socket even on platforms that only use the first
  slot (the allocation is not yet platform-sized).
- One wakeup drains at most `MAX_DRAIN_ROUNDS = 4` batches, so a persistently
  full receive queue cannot starve the driver's tick (KCP `update`, ACKs,
  retransmits) or its write arms. A packet that arrives between the syscall
  and the next `select!` simply wakes the driver again.
- The per-wakeup setup is four small `Vec`s for the `mmsghdr`, `iovec` and
  name arrays, against the 1-32 `recv_from` calls it replaces.
- Not measured: multi-flow streams, other transports, or a host without the
  containerised veth the VM runs on.

## 5. Reproduce

```bash
# on the VM
/root/bench/kcp3.sh rs recv-before 1 2048      # baseline build
# after building the branch into /root/recvbin:
/root/bench/vmcmp3.sh                          # 7 interleaved pairs
```

Scripts: `/root/vmcmp3.sh` (interleaved A/B with per-process CPU),
`/root/bench/kcp3.sh` (single run), `/root/bench/abbench` (sink/stream peer).
