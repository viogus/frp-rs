# The KCP driver's send syscalls were the mux-over-KCP ceiling

2026-11-23. Measured on a 4-vCPU Linux VPS, loopback, `frp-stress` `stream`/`sink`
shapes (one-way, 10 s, 8 streams unless noted, arms interleaved and order-flipped
per rep). Baseline: `main` at `b48ef8a7`. Candidate: the same tree plus a sender
thread for the KCP socket's UDP writes.

## The claim, and where it came from

mux-over-KCP ran at ~118 MiB/s where Go frp v0.72.0 ran at ~127. `perf record -t
<tid>` on the frps thread named `frp-kcp-driver` put **69.6% of that thread's
cycles inside `sendmmsg`** (`__sys_sendmmsg` 69.55 → `udp_sendmsg` 64.61 →
`ip_output` 34.73 → `__dev_queue_xmit` 30.67, with the loopback receive half
executed inside the same syscall), and `/proc/<pid>/task/*/stat` showed the whole
server at 1.03 cores with **0.83 of them in that one thread**. The KCP work the
driver does itself — `update`, `flush`, FEC — is the other ~30%.

A separate measurement closed the adjacent idea first: deeper write batching
cannot help, because 75% of write batches are closed by the producer's own
`Flush` (2,344 batches/s against 1,838 `Flush`/s), so flushes never queue.
`docs/archive/notes/2026-11-11-kcp-write-batching.md` records the `WRITE_BATCH`
history; this note assumes that cap is not the lever.

## The change

A `frp-kcp-send` OS thread per socket owns the datagram writes
(`frp-core/src/kcp/send_thread.rs`). The driver keeps computing, and hands each
run of datagrams — the `Vec<Vec<u8>>` a `force_flush` already produces — over a
bounded `sync_channel`. It must be a thread and not a `tokio::spawn`: the driver
runtime is `new_current_thread` and its own docs forbid extra tasks there
(`frp-core/src/kcp/driver_thread.rs:83`).

The load-bearing detail is the **single-producer** rule. When the channel is
full, the run is dropped; it is never sent from the driver. An inline fallback
was implemented first and measured **95.0 MiB/s against the baseline's 121.1**:
two producers on one socket interleave segments from different runs, KCP sees
reordering, and retransmissions amplify the traffic. A blocking `poll(2)` retry
in the worker did not fix it (still 95.0); dropping is what made the design
work. The worker only blocks on `WouldBlock` *within* one run, where it is still
the sole writer.

## Measured

Interleaved A/B pairs, MiB/s, `main` vs candidate:

| shape | before | after | delta | pairs positive |
|---|---|---|---|---|
| 8 streams, mux + TLS | 119.3 | 140.0 | **+17.4%** | 6/6 |
| 1 stream, mux + TLS | 108.3 | 133.7 | **+23.4%** | 3/3 |
| 8 streams, mux off, TLS on | 99.9 | 130.5 | +30.6% | 2/2 |
| 8 streams, mux off, TLS off | 99.8 | 134.8 | +35.0% | 2/2 |

Per-rep 8-stream numbers: before 122.7 / 123.8 / 118.8 / 118.4 / 112.5 / 119.3,
after 139.3 / 139.8 / 139.5 / 144.2 / 139.2 / 137.8. Against Go frp v0.72.0's
127.2 on the same shape, the tunnel moves from ~7% behind to ~10% ahead.

## What it costs

This buys parallelism, not efficiency, and the bill is visible in three places.

- **CPU per byte.** Server cores go from 1.06 to 1.72 at the higher rate, i.e.
  **0.0089 → 0.0122 cores per MiB (+38%)**. Client CPU per MiB improves
  (0.0113 → 0.0095) because the same cycles now move more data.
- **Aggregate capacity on a busy box.** Two independent frps+frpc pairs sum to
  173.0 and 175.2 MiB/s against the baseline's 186.9 and 178.4 (**−4.6% on
  average**). The win needs idle cores; a host already saturated by many client
  sockets goes slightly backwards.
- **Tail latency.** Echo RTT through the tunnel, 4 connections, 1500 samples of
  64 B: p50 unchanged (0.40-0.46 vs 0.36-0.45 ms) but **p99 0.92-1.20 →
  1.56-1.65 ms**, because the queue is FIFO and interactive traffic waits behind
  a bulk run.

The CPU increase is not the extra syscalls one would expect. Counting them on
frps over 8 s: `sendmmsg` 16,402 → 14,483 (fewer, and fuller: 43 → 60 datagrams
per call) but `recvmmsg` 28,690 → 65,082. The driver reaches the socket sooner
because it is no longer busy sending, so fewer datagrams have accumulated per
call. Accepting a partially filled batch and looping again cut `recvmmsg` by 12%
and changed neither throughput nor CPU, so the count is a symptom; the cost is
most likely socket-lock contention between the reader and the writer on one fd,
plus cross-core wakeups on loopback. Both are loopback artefacts to some degree,
which is why the aggregate test matters more than the single-pair one.

## Limits

One host, loopback, 4 vCPUs, one KCP socket carrying 8 streams, FEC 10+3, default
MTU 1400. The aggregate test spreads clients over separate frps processes; a
single frps serving many clients has the same thread topology but different
shared-state pressure, and was not measured. No real NIC was available, so the
kernel cost per datagram here (netfilter ~4.5% self on loopback) is not the
deployed one. The comparison is against `main` at `b48ef8a7` only — Go was
measured separately for context, not in the interleaved pairs.

## Reproduce

```bash
# build the candidate and drop it where the harness expects it
cargo build --release -p frps -p frpc
# 8 streams, mux + TLS, 6 interleaved pairs (order flips every rep)
RB=/root/bin-b GB=/root/bin-c MUX=true TLSE=true TRANSPORTS=kcp \
  bash /root/speed-ab.sh 6 10 8
# aggregate capacity: independent pairs on one box
bash /root/par-test.sh 2 8 10 /root/bin-c
# which thread burns the cycles
bash /root/thr.sh /root/bin-b          # per-thread CPU during one stream
bash /root/drv-prof.sh /root/bin-b     # perf record -t <frp-kcp-driver tid>
```

The harness scripts live on the benchmark host, not in this repo; `speed-ab.sh`
writes both arms' TOML (`MUX`/`TLSE`/`TRANSPORTS`) and `par-test.sh` takes the
binary directory as its fourth argument.
