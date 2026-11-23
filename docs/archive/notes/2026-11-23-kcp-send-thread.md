# The KCP driver's send syscalls were the mux-over-KCP ceiling

2026-11-23. Measured on a 4-vCPU Linux VPS, loopback, `frp-stress` `stream`/`sink`
shapes (one-way, 10 s, 8 streams unless noted, arms interleaved and order-flipped
per rep). Superseded numbers: the tables below are from a re-run of the final
tree (`/root/bin-e`); the first-pass measurements quoted in the commit message
agree within the run-to-run spread. Baseline: `main` at `b48ef8a7`. Candidate: the same tree plus a sender
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
(`frp-core/src/kcp/driver_thread.rs:66-68`).

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
| 8 streams, mux + TLS (6 pairs) | 119.3 | 140.0 | **+17.4%** | 6/6 (sign test p≈0.03) |
| 8 streams, mux + TLS (4 pairs, final tree) | 119.0 | 138.9 | **+16.7%** | 4/4 (p≈0.13) |
| 1 stream, mux + TLS (3 pairs) | 108.3 | 133.7 | +23.4% | 3/3 (p≈0.25) |
| 8 streams, mux off, TLS on (2 pairs) | 99.9 | 130.5 | +30.6% | 2/2 (p≈0.25) |
| 8 streams, mux off, TLS off (2 pairs) | 99.8 | 134.8 | +35.0% | 2/2 (p≈0.25) |

Only the six-pair row reaches p<0.05 on a sign test; the smaller rows are
consistently positive but not separable from a coin flip at that n, so read them
as "no row went the other way", not as measured magnitudes. Per-rep 8-stream
numbers, six-pair run: before 122.7 / 123.8 / 118.8 / 118.4 / 112.5 / 119.3,
after 139.3 / 139.8 / 139.5 / 144.2 / 139.2 / 137.8. Against Go frp v0.72.0's
127.2 on the same shape, the tunnel moves from ~6% behind (118 on the earlier
comparison run) to ~10% ahead.

## What it costs

This buys parallelism, not efficiency, and the bill is visible in three places.

- **CPU per byte.** Server cores go from 1.06 to 1.72 at the higher rate, i.e.
  **0.0089 → 0.0122 cores per MiB (+38%)**. Client CPU per MiB improves
  (0.0113 → 0.0095) because the same cycles now move more data.
- **Aggregate capacity on a busy box.** Interleaved, four reps of two
  independent frps+frpc pairs on the same box: baseline 186.1 / 187.1 / 184.6 /
  181.2 (mean **184.8**), candidate 170.7 / 175.9 / 171.8 / 181.3 (mean
  **174.9**) — **−5.3%**, three of four reps negative and one at parity. The win
  needs idle cores; a host already saturated by many client sockets goes
  backwards.
- **One thread per socket.** This adds a second OS thread per `KcpSocket`, on top
  of the driver thread — and with `tcpMux = false` every work connection dials
  its own socket, so the eight-stream shape above carries eight extra client
  threads. Nothing is pooled per host yet (see the TODO item).
- **Tail latency.** Echo RTT through the tunnel, 4 connections, 1500 samples of
  64 B: p50 unchanged (0.40-0.46 vs 0.36-0.45 ms) but **p99 0.92-1.20 →
  1.56-1.65 ms**, because the queue is FIFO and interactive traffic waits behind
  a bulk run.

The CPU increase is not the extra syscalls one would expect. Counting them on
frps over 8 s at the two arms' own rates (`116.7` and `138.9` MiB/s):
`sendmmsg` 16,402 → 15,819 — 4% fewer calls for 19% more bytes, i.e. roughly
**+17% datagrams per call** — but `recvmmsg` 28,690 → 65,989. The driver reaches the socket sooner
because it is no longer busy sending, so fewer datagrams have accumulated per
call. Accepting a partially filled batch and looping again cut `recvmmsg` by 12%
and changed neither throughput nor CPU, so the count is a symptom, not the cost.
**Why total CPU rises is not established**: nothing here measured lock contention
or per-thread cycles on the *after* side, and the +62% server cores have to
explain themselves. Two candidates, neither tested — socket-lock contention
between the reader and the writer on one fd, and cross-core wakeups on loopback —
which is why the aggregate test matters more than the single-pair one, and why
the TODO item is open. The note makes no claim past the numbers.

## Limits

One host, loopback, 4 vCPUs, one KCP socket carrying 8 streams, FEC 10+3, default
MTU 1400. **All numbers are Linux.** Off Linux the worker has no `sendmmsg`
(`send_udp_batch` returns 0 and each datagram takes its own `try_send_to`) and a
`WouldBlock` waits a fixed 5 ms slice, bounded per run by `MAX_STALLS` — so a
stalled socket costs up to 200 slices before the run is handed back to KCP. That
path is unmeasured here and is a plausible regression for macOS/Windows KCP
users; it needs its own A/B before this ships everywhere. The aggregate test spreads clients over separate frps processes; a
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
