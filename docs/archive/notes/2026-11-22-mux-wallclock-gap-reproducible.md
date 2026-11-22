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

**Eight streams**

| arm | frp-rs MiB/s | Go frp MiB/s | wall ratio | frp-rs MiB/CPU-s | Go MiB/CPU-s | CPU ratio |
|---|---|---|---|---|---|---|
| `tcpMux = false` | 1780 / 1795 / 1780 (**1789**) | 1483 / 1534 / 1546 (**1521**) | **1.18×** | 597 / 591 / 599 (**596**) | 477 / 478 / 484 (**480**) | **1.24×** |
| `tcpMux = true` | 652 / 659 / 665 (**659**) | 771 / 727 / 721 (**740**) | **0.89×** | 395 / 394 / 402 (**397**) | 282 / 283 / 280 (**282**) | **1.41×** |

**One stream**

| arm | frp-rs MiB/s | Go frp MiB/s | wall ratio (median) | frp-rs MiB/CPU-s | Go MiB/CPU-s |
|---|---|---|---|---|---|
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
