# Deeper KCP write batching buys nothing

2026-11-23. Status: measured, **not adopted**. Closes the open question in
[`2026-11-11-kcp-write-batching.md`](2026-11-11-kcp-write-batching.md) §4: the
`WRITE_BATCH = 4` cap was "a guess with one measurement behind it", and going
deeper was never measured. It is measured now, and the answer is that the cap
was not the binding constraint — the producer's flush cadence is.

## 1. The claim being tested

A tcp-mux data frame reaches KCP as two writes — a 12-byte header and a body of
up to 64 KiB — because `KcpStream` implements only `poll_write`, so a vectored
write degrades to one buffer
([`2026-11-22-mux-write-path-vectored.md`](2026-11-22-mux-write-path-vectored.md),
`frp-core/src/kcp/stream.rs:272`). A count-based cap of 4 messages therefore
batches at most two frames per flush. A bytes-based budget was supposed to let
one batch cover several bridge chunks and cut the flush count by as much as the
producer's backlog allows. If the flush (`update()` + `flush()` + drain + FEC +
one `sendmmsg`) is where the driver spends its time, fewer flushes per byte
should raise throughput.

## 2. What was changed

`frp-core/src/kcp/socket.rs`, write arm only:

```rust
const WRITE_BATCH_MAX: usize = 32;      // was WRITE_BATCH = 4
const WRITE_BATCH_BYTES: usize = 1 << 20;
```

The arm fills the batch while `queue.len() < WRITE_BATCH_MAX` **and**
`queued_bytes < WRITE_BATCH_BYTES`. Everything else — the four-flush-per-batch
dedupe, the burst-end rule, the `Flush`-breaks-the-batch ordering — is untouched.
No wire change, so no compat risk.

## 3. Result: no measurable gain

One-flow-per-stream bulk shape, 8 streams, `tcpMux` + TLS over KCP, loopback on
the 4-vCPU test VM, `scripts/frp-stress` `stream`/`sink`. `old` = `b48ef8a7`
(`WRITE_BATCH = 4`), `new` = the same tree with the cap above; both binaries are
release builds of that tree, and each pair runs the two arms back to back with
the order flipped (A-then-B on odd reps, B-then-A on even).

| session | pair | ran first | old (MiB/s) | new (MiB/s) | Δ |
|---|---|---|---|---|---|
| 1 (8 s) | 1 | old | 127.4 | 121.7 | −4.5% |
| 1 (8 s) | 2 | new | 122.7 | 121.8 | −0.7% |
| 2 (10 s) | 1 | old | 119.8 | 128.1 | +6.9% |
| 2 (10 s) | 2 | new | 119.1 | 123.5 | +3.7% |
| 2 (10 s) | 3 | old | 119.3 | 123.6 | +3.6% |
| 2 (10 s) | 4 | new | 118.7 | 117.9 | −0.7% |
| | **mean** | | **121.2** | **122.8** | **+1.3%** |

Session 1 says −2.6% (0/2 pairs positive), session 2 says +3.4% (3/4 pairs
positive): the two sessions of the *same two binaries* disagree in sign, and the
pooled six-pair delta is +1.3%. The per-pair spread is ±6% and the standard
error of the mean delta is 1.7 points (t = 0.83, 95% CI −2.9%…+5.7%), so this
experiment **cannot resolve anything smaller than about ±6%** — it is not
evidence of zero. What rejects the change is §4's mechanism bound, not the A/B.
CPU is unchanged: at ~120 MiB/s frps burns 1.07 cores and frpc 1.36.

## 4. Why: the cap was never the binding constraint

Instrumenting the arm (cumulative counters, `frps` side, 124.1 MiB/s run,
straight 10 s of traffic):

| metric | value |
|---|---|
| batches | 23,444 |
| writes queued | 90,092 |
| application bytes through the arm | 1,182,700,436 |
| `WriteRequest::Flush` messages handled | 18,378 |
| mean depth | **3.8 writes/batch** |
| mean write size | **13.1 KB** (9.5 segments) |

Depth histogram, and — the part that matters — **why each batch ended**:

| queue depth | batches | share | | batch ended by | batches | share |
|---|---|---|---|---|---|---|
| 1 | 3,454 | 14.7% | | the 32-write / 1 MiB budget | **0** | **0%** |
| 2 | 1,980 | 8.4% | | the write channel going empty | 5,771 | 24.6% |
| 3 | 1,991 | 8.5% | | **a `Flush` arriving** | **17,673** | **75.4%** |
| 4 | 3,391 | 14.5% | | | | |
| 5 | 12,628 | **53.9%** | | | | |
| 6+ | **0** | 0% | | | | |

The cap of 32 writes / 1 MiB was reached **never**. Three quarters of batches
are closed by a `Flush` message, at depth 4 or 5 — i.e. the batch is one yamux
drain pass (two frames' header+body) plus the flush that yamux issues at
the end of that pass. The remaining quarter end when the channel momentarily
empties. Depth is set by what the producer emits per wakeup, not by what the
driver is willing to swallow: the 1 MiB budget sat ~16× above the largest batch
the workload ever produced (the largest is ~5 × 13.1 KB ≈ 65 KB, one bridge
chunk), and the *count* half of the cap is the only half that was ever under
test.

The 5-8 bucket is worth a footnote because it is where the old note's error
was: it is not "5-8 writes in 53% of batches" but **exactly 5, essentially
always** — this run's bucket sums to 63,141 writes over 12,628 batches, and an
earlier run of the same build summed to exactly 5 × 13,764 = 68,820, so at most
one batch in 23,444 reached 6 and none reached 7. (That earlier run: 25,961
batches, 99,204 writes, 22,777 flushes, histogram 15.5/8.1/8.1/15.2/53.0/0.)

So the change moved the ceiling from 4 (the old cap) to ~5 (the producer's
pass) and left the flush count where the 4-write cap had it — 1.8k `Flush`
messages/s over the run's 10 s, with 2.3k batches/s. Even taking the optimistic view that
the deeper cap cuts batches by a tenth (the 12,628 depth-5 batches would become
≥15,785 under a 4-write cap, so ~13% more batches), a tenth of the flush's 6.8%
is 0.7% of CPU — below this experiment's resolution, which is what §3 shows.

And the flush is not where the time goes. `perf` on frps over the same shape,
inclusive time:

| symbol | % of frps CPU |
|---|---|
| `handle_data_burst` | 71.8 |
| `flush_session_output` | 70.4 |
| `send_packets` | **63.7** |
| `force_flush` (`update` + `flush`) | **6.8** |
| yamux frame writer | 6.3 |
| `KcpSession::input` | 1.6 |
| `send_carry` | 1.1 |

The flush's own bookkeeping — the part batching amortises — is 6.8%. Its body is
63.7% `send_packets`, which is one `sendmmsg` per flush (`send_udp_batch`,
`frp-core/src/kcp/socket.rs:1161`) whose cost is kernel work per datagram. The
syscall counter reads 2,278 `sendmmsg` per second against ~94.6k data
segments/s, i.e. **~54 datagrams per call** once 10+3 FEC is counted, so the
datagram count is what costs, and batching writes does not change how many
datagrams a byte of payload becomes. Control: `iperf3 -u` on loopback sustains
1.68-1.70 Gbit/s (≈200 MiB/s) of 1376-byte datagrams, and this KCP shape moves
124 MiB/s of payload = 1.3 Gbit/s of datagrams with FEC — 78% of the
single-flow UDP ceiling, before TLS and FEC work on top.

One asymmetry the write arm cannot touch: this flush bill is **larger on the
client**, which is also the busier process. In §6's 14 s run `frpc` handled
247,477 `Flush` messages (≈18k/s) for 339 KB of writes, with every one of its
9,941 batches at depth 1 — there is nothing for a deeper cap to merge there —
while burning 1.36 cores to frps's 1.07.

## 5. What would move this number instead

All of these change the **datagram count per MiB**, which is the quantity the
profile says is being paid for; none is reachable from the write arm:

- FEC parity: 10+3 costs 1.3× datagrams. Go parity for the default, and it is
  not user-configurable here either — the shard counts are fixed at
  `frp-core/src/kcp/kcp_compat.rs:103-104` and no config key reaches them.
- Larger MTU: a 1400-byte MTU already landed (−4.0% CPU/MiB, six pairs);
  `MAX_KCP_MTU` (`frp-core/src/kcp/config.rs:44`) bounds what is left.
- Per-datagram kernel cost: `nf_hook_slow` + `nft_match_eval` +
  `nf_conntrack_in` (4.5% self) is netfilter on the loopback path, not frp-rs
  code, and does not exist on a real host with a shorter rule set.
- The client's empty-flush rate (§6): skipping `force_flush` when a session has
  neither queued data nor a pending ACK is worth ~1% of frps but is aimed at the
  side that is actually saturated.

## 6. Side observation, not measured further

On the receiving end the `Flush` traffic dwarfs the data: in the same run `frpc`
handled **247,477** `Flush` requests for 339 KB of writes (9,941 batches, every
one of depth 1). Each `Flush` runs `flush_carry` + `force_flush` even when the
session has nothing queued (`handle_flush`, `frp-core/src/kcp/socket.rs:376`,
has no emptiness guard; `force_flush`, `frp-core/src/kcp/session.rs:650`, always
runs `update()` → send-buffer scan). That is ~18k wakeups/s to move ~30 KB/s,
and it is the client's flush path, not the batch depth, that this shape pays
for. Filed as an observation; nothing was changed.

## 7. Reproduce

Two release builds of the same tree (`b48ef8a7` vs `b48ef8a7` + §2), `frps` with
`kcpBindPort` and `[transport] tcpMux = true`, `frpc` with `protocol = "kcp"` +
`tcpMux = true` on a `tcp` proxy, a `frp-stress sink` behind it, then:

```bash
frp-stress --scenario stream --streams 8 --duration 10 --json-out out.json
```

which prints `mbps` and `failed_streams`; the A/B harness (unversioned, gc
`/root/kcp-batch-ab.sh`, args `reps duration streams [A_DIR B_DIR]`) interleaves
the arms and flips the order per rep. §4's counters come from a temporary
`FRP_KCP_STATS=1` build that bumps atomics in `handle_data_burst` and the write
arm and prints them once a second; it was not kept. The `perf` table is a
release build with `CARGO_PROFILE_RELEASE_STRIP=false
CARGO_PROFILE_RELEASE_DEBUG=1` under `perf record -g --call-graph dwarf` during
the same 8-stream run, and the syscall counts are
`perf stat -e syscalls:sys_enter_sendmmsg,syscalls:sys_enter_recvmmsg`.

## 8. Limits

- One host (4 vCPU VM), loopback only, one shape: a single `tcp` proxy, 8
  streams, FEC at its fixed 10+3, TLS on. A different frame mix (small
  interactive writes, many proxies) could present a deeper queue than 5 — the
  point here is the bulk shape, which is the one the earlier `+4.0%` claim was
  measured on.
- Both A/B arms are release builds of the same source except for the two
  constants, but the *harness* is unversioned and the run order, the binaries
  and the counters are recorded only in this note.
- §3's resolution is ±6%; §4's verdict rests on the mechanism bound, not on the
  A/B being flat.
- The counters were read from the process's cumulative atomics at the moment of
  the last one-second tick, so they lag the end of the stream by <1 s.
