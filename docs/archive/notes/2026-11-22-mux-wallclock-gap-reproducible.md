# The tcpMux wall-clock gap is real, and it is not CPU

2026-11-22, second pass. Measurement only — no code changed.

## Why this note exists

`docs/archive/notes/2026-11-22-streaming-shape-rust-vs-go.md` recorded the
`tcpMux = true` cell as *unresolved*: 0.92× in the first pass, 1.42× in a
validation run, so the note declined to call it either way. That was a load
artifact, not a property of the code. Re-run on a quiet host, with the arms
interleaved and the order flipped every rep, the cell reproduces at **0.89×**
with ~1% spread, and it does so while frp-rs spends **29% less CPU per byte**
than Go. This note supersedes the "unresolved" reading.

## Numbers

`scripts/stream-vs-go.sh` (shipped in #666), 3 reps × 10 s, 64 KiB one-way
writes, one saturating stream per connection, arms interleaved, order flipped
per rep, macOS arm64 loopback, load < 2 on 8 cores. MiB/s; MiB/CPU-s is
`mbps × duration / cpu‑seconds` from `ps -o time` deltas.

#### Eight streams

| arm | frp-rs MiB/s | Go frp MiB/s | wall ratio | frp-rs MiB/CPU-s | Go MiB/CPU-s | CPU ratio |
| --- | --- | --- | --- | --- | --- | --- |
| `tcpMux = false` | 1780 / 1795 / 1780 (**1789**) | 1483 / 1534 / 1546 (**1521**) | **1.18×** | 597 / 591 / 599 (**596**) | 477 / 478 / 484 (**480**) | **1.24×** |
| `tcpMux = true` | 652 / 659 / 665 (**659**) | 771 / 727 / 721 (**740**) | **0.89×** | 395 / 394 / 402 (**397**) | 282 / 283 / 280 (**282**) | **1.41×** |

#### One stream

| arm | frp-rs MiB/s | Go frp MiB/s | wall ratio (median) | frp-rs MiB/CPU-s | Go MiB/CPU-s |
| --- | --- | --- | --- | --- | --- |
| `tcpMux = false` | 994 / 988 / 928 | 1068 / 582 / 1069 | 0.93× | 549 | 526 |
| `tcpMux = true` | 729 / 314 / 696 | 723 / 729 / 727 | 0.96× | 454 | 318 |

Each one-stream arm has one outlier (Go 582, frp-rs 314), so the one-stream row
is read by median; the eight-stream arms spread ~1% and are read by mean.

## What it says

- Without mux, frp-rs is ahead on both axes at eight streams (+18% wall, +24%
  CPU efficiency per byte, i.e. 20% less CPU for the same byte).
- With mux, frp-rs is **behind on wall-clock (11% at eight streams, ~4% at
  one) and far ahead on CPU** (29% less CPU per byte at eight streams, 43% at
  one). A tunnel that moves fewer bytes per second while burning less CPU is
  waiting, not computing: the mux path is limited by something that serialises
  work rather than by work volume.
- The most likely serialisation is the one this repo already has a name for:
  each stream's `poll_write` queues a frame to the connection driver
  (`vendor/yamux/src/connection/stream.rs:388-444`, `StreamCommand::SendFrame`
  at `:439-442`), and the driver is one task per connection — so eight streams
  share one wake-and-flush loop, where Go's yamux hands the same work to a
  per-stream writer goroutine under a connection write lock. That is a
  hypothesis to test, not a finding: nothing here measures where the wall-clock
  goes.

## What it does not establish

- Loopback, one machine, one client process. Window growth and RTT sampling
  behave differently at 30 ms.
- No per-task accounting: `ps` gives process CPU, which cannot separate
  protocol work from the driver wake.
- The eight-stream Go arms show more variance than frp-rs's (727-771 against
  652-665), so the 0.89× carries roughly ±3%.
- This does not re-open `keep/yamux-inline-write-v2`. That experiment removes a
  hop now measured at 4 µs on a ping-pong (`docs/archive/notes/2026-11-22-yamux-inline-write-no-longer-applies.md`);
  whether a hop that cheap can cost 11% of a saturating eight-stream throughput
  is exactly what the next measurement has to answer, with the shape that shows
  the gap rather than the shape that was used to size it.

## Follow-up: the shape of the limit, not the size of the gap

A separate session tried to localise the gap on a **different, loaded** host
(load 6-13 on 8 cores), where it did not reproduce: rust mux 477/446 vs Go 361/361
MiB/s, i.e. frp-rs ahead in the same cell. So the numbers above stand only for a
quiet host, and the localisation below is about *where the work sits*, not about
how big the deficit is.

Four things that host did establish, all structural:

1. **The server impl dominates the pairing.** 8-stream mux medians: rust srv +
   rust cli **663**, rust srv + Go cli **561**, Go srv + rust cli **471**, Go srv
   + Go cli **431** MiB/s. The client implementation moves the result 9-18%; the
   server implementation 40%. A deficit in this cell is a *server-side ingress*
   question first.
2. **More client workers do not help.** `worker_threads` 1 / 8 / default →
   564-574 / 535-646 / 503-588 MiB/s, CPU flat — inside noise. Whatever limits
   the cell is inside one task, not in how tasks are shared out.
3. **That task is saturated and not blocked.** `sample` on an unstripped frpc
   during the cell: 8 tokio workers, one busy; with `worker_threads = 1` the
   single worker held 4353/4353 samples with only 153 (3.5%) in `park_internal`.
   Top self frames: `__sendto` (23% of the worker's samples), ring
   `aes_gcm_dec`, rustls `vecbuf Vec::resize`, `__recvfrom`, `_platform_memmove`.
   No lock spinning, no park. So the per-byte path (decrypt, resize, copy,
   syscall) runs on **one** thread and never exceeds ~1 core.
4. **Splitting the streams across connections restores little.** 1 conn × 1
   stream 729, 1 conn × 8 streams 664, 8 conns × 1 stream 778/755 MiB/s (summed).
   A 17% recovery at 8x the connections, so the per-connection driver is not a
   hard serialisation point — the work itself is.

Read together with the CPU column above, the picture is: frp-rs does all
per-stream byte work on one connection task (≈1 core, 397 MiB/CPU-s), Go spreads
it over per-stream goroutines (≈2.6 cores at 740 MiB/s, 282 MiB/CPU-s). The
deficit is therefore *parallelism of the per-byte work*, not the 4 µs frame hop
and not a lock. The next measurement is a per-stream offload experiment: hand the
decrypted payload of each stream to its own task before the bridge copy, and see
whether throughput follows the extra cores.

## Third machine: a 4-core Linux VPS, where it does not reproduce

Same harness, same configs, no frp on the same box as the load generator
(loopback there too). Four pairings x 2 reps x 8 streams x 10 s, `tcpMux = true`
everywhere, CPU is both processes:

| pairing | MiB/s (2 reps) | MiB/CPU-s |
| --- | --- | --- |
| rust srv + rust cli | 650 / 707 (**679**) | 295 / 321 |
| rust srv + Go cli | 722 / 686 (**704**) | 328 / 298 |
| Go srv + rust cli | 492 / 649 (**571**) | 234 / 295 |
| Go srv + Go cli | 536 / 525 (**531**) | 243 / 238 |

On that box frp-rs is **ahead, not behind**, in both the same-impl and the
mixed rows, and it still spends fewer CPU-seconds per byte. So the 0.89x above
is not "the mux path": it is the mux path **on an 8-core macOS host**, where the
same code loses 11% of wall-clock while using less CPU. Two things follow.

First, the previous section's "server impl dominates" reading came from a
different machine with a different pairing; on this one the Go server is the
slow side and the client impl barely moves the result. Neither statement
generalises, and both are now labelled with the box they were measured on.

Second, two candidate explanations survive and neither is measured: macOS
per-wakeup cost (`__sendto`/`__recvfrom` self time, kqueue vs epoll), or
oversubscription on 8 cores with a load generator that is itself an 8-task
process. A Linux run cannot separate them; a Mac run with fewer streams than
cores, or with the load generator pinned to other cores, could.

One retraction, recorded because it cost a detour: a first pass on the macOS
host reported `rust frpc + Go frps + tcpMux = true` failing at login with
`unexpected EOF`. It does not reproduce: on this VPS the same pairing registers
and streams. The local failure was the client starting before the Go server had
bound its port with `loginFailExit` on — a harness ordering bug, not a
compatibility defect.
