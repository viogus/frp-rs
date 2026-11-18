# Crash recovery and soak: no leaks, and UDP transports take 19-40 s to notice a dead peer

**Status:** verification round, no product change.
**Measured:** 2026-11-18 on the dedicated 4-vCPU EPYC-Milan VM (`ssh gc`), commit
`a9536417`, release build, one proxy (`tcp`, `localPort = 19054`,
`remotePort = 19056`), 32 MiB or 64 MiB transfers from `abbench`, plus one
4096 MiB flow.

The throughput round closed with every row of the 24-row comparison matrix at or
ahead of Go frp v0.72.0 (see
[`2026-11-16-rust-vs-go-throughput.md`](2026-11-16-rust-vs-go-throughput.md)).
This round asked the next question: does the process stay healthy while the peer
disappears, and how fast does service come back?

## 1. Soak: 40 connect/transfer/drop cycles plus one 4 GiB flow

Default configuration (`tcp` + TLS + `tcpMux`), 40 cycles of
"connect → send 64 MiB → drop" per process, with a 4 GiB flow running
throughout (357 MiB/s while it shared the host with the churn). Sampled from
`/proc/<pid>/{fd,task,status,stat}`.

| Sample | frps fd | frps thr | frps RSS | frpc fd | frpc thr | frpc RSS |
|---|---|---|---|---|---|---|
| baseline (idle, one proxy) | 13 | 6 | 9 680 KB | 10 | 6 | 8 528 KB |
| after 10 cycles | 15 | 6 | 13 084 KB | 12 | 6 | 14 760 KB |
| after 20 cycles | 15 | 6 | 13 020 KB | 12 | 6 | 13 672 KB |
| after 40 cycles | 15 | 5 | 13 484 KB | 12 | 5 | 15 208 KB |
| settled (3 s idle) | 13 | 5 | 13 212 KB | 10 | 5 | 12 712 KB |

File descriptors return exactly to the baseline and RSS settles 3.5 MB (frps)
and 4.2 MB (frpc) above it. The thread count ends one lower on both sides
(6 → 5): one runtime worker retired after the churn. No warnings, no panics.

## 2. Server crash: how long until traffic flows again

The harness kills `frps` with `SIGKILL`, restarts it, then polls the proxied
port every 100 ms until it accepts again (`/root/bench/recover.sh`).

With eight consecutive crashes the delay the client logs for each reconnect is
the Go-compatible fast backoff (`frp-client/src/backoff.rs:73-111`: 200 ms fast
retries, then doubling with ±10% jitter, capped at 20 s):

```
203ms 457ms 1866ms 3890ms 7874ms 14782ms 20000ms 20000ms
```

all eight cycles recovered, the last two after the cap, and afterwards the
client held 13 file descriptors (one live control connection plus the
reconnect machinery), 5 threads and 9 416 KB RSS. Zero panics.

## 3. UDP transports: detection is the cost, not the reconnect

`SIGKILL` of `frps` sends no reset for KCP or QUIC, so the client keeps
transmitting into a void until its own dead-link/idle timer expires. Five crash
cycles per transport:

| Transport | frp-rs recovered | frp-rs latency | Go frp v0.72.0 recovered | Go latency |
|---|---|---|---|---|
| `tcp` (frp-rs only) | 5/5 | 239 / 467 / 812 / 1 830 / 4 339 ms | not run | — |
| `kcp` | 2/5 within 60 s | 18 980 / 20 600 ms | 2/5 within 60 s | 29 059 / 30 464 ms |
| `quic` | 5/5 | 29 810-39 675 ms | 5/5 | 29 848-40 060 ms |

Three of the five KCP cycles did not recover inside the 60 s window on either
implementation, so the KCP figure is "19-21 s when it recovers, otherwise beyond
60 s" — not a bounded band. Transfers after recovery (one flow, 32 MiB per rep,
`tcpMux = false`, TLS at its default) ran at 783-1 343 MiB/s for `tcp`,
171-173 MiB/s for `kcp` and 366-505 MiB/s for `quic`; the rep is short enough
that these rates are not comparable to the throughput round's table, whose KCP
row peaks at 128 MiB/s with a 1024 MiB rep.

Two readings:

- **QUIC parity, KCP inconclusive.** Go lands in the same 29.8-40.1 s band on
  QUIC; on KCP both implementations missed the window in three of five cycles,
  and frp-rs's two recoveries (19.0 / 20.6 s) were faster than Go's (29.1 /
  30.5 s). The cost is the transport's own idle/dead-link timer plus the 20 s
  backoff cap, and KCP's dead-link threshold is a hardcoded constant on both
  sides (`frp-core/src/kcp/protocol.rs:71`, `const KCP_DEADLINK: u32 = 20;`).
- **Tunable where it matters.** The QUIC idle timeout is configurable: client
  `[quic]`, server `[transport.quic]`, field `maxIdleTimeout`, default 30 s
  (`frp-core/src/config/client.rs:367`, `frp-core/src/config/server.rs:1152`),
  so an operator who prefers faster failover to a more tolerant idle timeout
  can trade one for the other.

A user who needs sub-second recovery after a server restart should run `tcp`
(the reset wakes the client immediately) or shorten the QUIC idle timeout.

## 4. Matrix re-run at the shipped default

`scripts/bench-vs-go.py` with `MIB=1024 BLOCKS=3` and no `WORKERS` override, so
both arms use their shipped defaults (frp-rs: one client worker per core;
Go: `GOMAXPROCS`): **21 rows faster, 3 indistinguishable, 0 behind**,
`dropped=0`. The three ties are KCP at 1.05x (TLS on, no `tcpMux`, one flow),
0.99x (no TLS, `tcpMux` on, four flows) and 0.99x (TLS on, `tcpMux` on, four
flows). The two rows recorded as behind before the client-default change now
read 1.39x (`websocket` + TLS, four flows) and 1.26x (`tcp` + TLS, no
`tcpMux`, four flows).

## Limits

- One process per side on one host; loopback and `veth`, no WAN. Every row is a
  single run: the TCP arms show how much that matters (4.3 s tail over five
  spaced cycles against a 20 s tail in the eight-crash burst).
- Crash-only failure mode. Slow-failure injection (a peer that stops reading, a
  black-holed path, a half-open socket) is not covered — the TLS record-layer
  stall in [`2026-11-16-websocket-tls-stall.md`](2026-11-16-websocket-tls-stall.md)
  was found by measurement, not by this soak.
- The 4 GiB flow shared the host with the churn cycles, so its 357 MiB/s is a
  contended figure, not a throughput measurement.
