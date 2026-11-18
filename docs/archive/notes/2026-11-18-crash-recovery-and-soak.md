# Crash recovery and soak: no leaks, and UDP transports take 20-40 s to notice a dead peer

**Status:** verification round, no product change.
**Measured:** 2026-11-18 on the dedicated 4-vCPU EPYC-Milan VM (`ssh gc`), commit
`a9536417`, release build, one proxy (`tcp`, `localPort = 19054`,
`remotePort = 19056`), 64 MiB or 4096 MiB transfers from `abbench`.

The throughput round closed with every shape at or ahead of Go frp v0.72.0 (see
[`2026-11-16-rust-vs-go-throughput.md`](2026-11-16-rust-vs-go-throughput.md)).
This round asked the next question: does the process stay healthy while the peer
disappears, and how fast does service come back?

## 1. Soak: 40 connect/transfer/drop cycles plus one 4 GiB flow

Default configuration (`tcp` + TLS + `tcpMux`), 40 cycles of
"connect → send 64 MiB → drop" per process, with a 4 GiB flow running
throughout. Sampled from `/proc/<pid>/{fd,task,status,stat}`.

| Sample | frps fd | frps thr | frps RSS | frpc fd | frpc thr | frpc RSS |
|---|---|---|---|---|---|---|
| baseline (idle, one proxy) | 13 | 6 | 9 680 KB | 10 | 6 | 8 528 KB |
| after 10 cycles | 15 | 6 | 13 084 KB | 12 | 6 | 14 760 KB |
| after 20 cycles | 15 | 6 | 13 020 KB | 12 | 6 | 13 672 KB |
| after 40 cycles | 15 | 5 | 13 484 KB | 12 | 5 | 15 208 KB |
| settled (3 s idle) | 13 | 5 | 13 212 KB | 10 | 5 | 12 712 KB |

File descriptors and threads return to the baseline, and RSS settles within
~4 MB of it. No warnings, no panics.

## 2. Server crash: how long until traffic flows again

The harness kills `frps` with `SIGKILL`, restarts it, then polls the proxied
port every 100 ms until it accepts again (`/root/bench/recover.sh`).

The client's reconnect delay is the Go-compatible fast backoff
(`frp-client/src/service/session.rs:327`, cap 20 s). With eight consecutive
crashes the series is:

```
203ms 457ms 1866ms 3890ms 7874ms 14782ms 20000ms 20000ms
```

all eight cycles recovered, the last two after the cap, and the client's
file descriptors/threads/RSS were still 13/5/9 416 KB afterwards. Zero panics.

## 3. UDP transports: detection is the cost, not the reconnect

`SIGKILL` of `frps` sends no reset for KCP or QUIC, so the client keeps
transmitting into a void until its own dead-link/idle timer expires. Same
harness, five crash cycles per transport, frp-rs against Go frp v0.72.0:

| Transport | frp-rs recovered | frp-rs latency | Go recovered | Go latency |
|---|---|---|---|---|
| `tcp` | 5/5 | 239 / 467 / 812 / 1 830 / 4 339 ms | — | (reset-based, immediate) |
| `kcp` | 2/5 within 60 s | 18 980 / 20 600 ms | 2/5 within 60 s | 29 059 / 30 464 ms |
| `quic` | 5/5 | 29 810-39 675 ms | 5/5 | 29 848-40 060 ms |

Transfers after recovery ran at the usual rates (TCP 783-1 343 MiB/s, KCP
171-173 MiB/s, QUIC 366-505 MiB/s), so this is detection latency, not a broken
session afterwards.

Two readings:

- **Parity.** Go shows the same 20-40 s behaviour on both UDP transports, so
  frp-rs is not slower at noticing a dead peer; the cost is the transport's own
  idle/dead-link timer plus the 20 s backoff cap.
- **Tunable where it matters.** QUIC exposes `transport.quic.maxIdleTimeout`
  (`docs/config.md`), so an operator who prefers a faster failover to a
  more tolerant idle timeout can trade one for the other. KCP's dead-link
  detection has no knob on either implementation.

A user who needs sub-second recovery after a server restart should run `tcp`
(the reset wakes the client immediately) or shorten the QUIC idle timeout.

## Limits

- One process per side on one host; loopback and `veth`, no WAN.
- Crash-only failure mode. Slow-failure injection (a peer that stops reading,
  a black-holed path, a half-open socket) is not covered here — the TLS record
  layer stall in [`2026-11-16-websocket-tls-stall.md`](2026-11-16-websocket-tls-stall.md)
  was found by measurement, not by this soak.
- The 4 GiB flow shared the host with the churn cycles, so its 357 MiB/s is a
  contended figure, not a throughput measurement.
