# 2026-11-19 — `[transport.kcp] deadLink`: measurements behind the knob

Status: shipped. Entry point: `docs/deployment.md` § "KCP dead-link bound".

## Symptom

A KCP session was torn down after 20 retransmissions of one segment. The number
came from kcp-go (`const KCP_DEADLINK: u32 = 20`) and was unreachable: the state
machine had `set_maximum_resend_times`, nothing called it, and no config key
existed. On a black-holed peer the client therefore kept a dead session until
something else noticed.

## What the bound can and cannot do

The state machine tears a session down once a segment has been transmitted
`dead_link` times, and the initial transmission already consumes one count. So
`deadLink = 5` tolerates four retransmissions, and 1 dies on the first write
while 2 dies on the first retransmission — values the loader refuses.

The second constraint is that a session must *try* to write before the bound can
fire. That makes the transport's keepalive cadence, not the bound, the dominant
term at the defaults.

## Method

4-vCPU Linux VM (EPYC-Milan), `ssh gc`, both binaries from this branch.
Server `frps.toml`: `bindPort = 19100`, `kcpBindPort = 19102`,
`vhostHTTPPort = 19101`, `[transport] tcpMux = false`, `[transport.kcp]
deadLink = <N>`. Client `frpc.toml`: `serverPort = 19102`, `transport.protocol =
"kcp"`, `tcpMux = false`, `[transport.kcp] deadLink = <N>`,
`heartbeatInterval = 1` for the isolated runs, proxy `mx` 19054 → 19056.
`frps` was frozen with `SIGSTOP` mid-transfer of a 4096 MiB stream; the client log
line `KCP session dead link` was timestamped against the freeze.

## Results

| run | pacing traffic | `deadLink` | declared dead after |
|---|---|---|---|
| isolated | `heartbeatInterval = 1` | 5 | **0.7 s** |
| isolated | `heartbeatInterval = 1` | 20 | **3.8 s** |
| defaults | heartbeat / yamux PING | 5 | ~28 s |
| defaults | heartbeat / yamux PING | 20 | ~31 s |

`deadLink = 1` was used as a liveness check that the wiring works at all: the
session died during connect (`Login failed … transport error: KCP TLS connect:
KCP session removed`), which is why the shipped floor is 3.

Under `tcpMux = true` the client heartbeat is disabled (`heartbeat_interval`
normalises to `-1`) and yamux's fixed 10 s PING is the only traffic; under
`tcpMux = false` the 30 s client heartbeat is. The ~28-31 s tails sit near the
30 s heartbeat window, which is what a freeze has to land inside.

## What was not established

- **False-positive rate on a lossy path.** 5 % `netem` loss on `lo` made the
  transfers hang past 1800 s without the knob mattering, so the loss experiment
  was abandoned rather than reported. A bound of 3-4 with ordinary reordering is
  a plausible false-kill risk and is not measured here.
- Visitor dials and the XTCP proxy's P2P plane keep 20; they build their KCP
  configs outside the config layer (`frp-client/src/visitor.rs`,
  `frp-client/src/nat_hole.rs`).
- How a Go peer behaves: it keeps its own 20, so the knob only shortens the
  frp-rs side.

## Where the code lives

`frp-core/src/lib.rs` (`KCP_DEAD_LINK_DEFAULT`, `KCP_DEAD_LINK_MIN`),
`frp-core/src/kcp/config.rs` (`KcpConfig.dead_link`),
`frp-core/src/kcp/session.rs` (applied in `with_chunk_pool`),
`frp-core/src/kcp/mod.rs` (`kcp_config_from_dead_link`, `kcp_client_config`),
`frp-core/src/config/server.rs` (`KcpOptions`), `frp-core/src/config/strict.rs`,
`frp-core/src/config/restart_only.rs`, `frp-server/src/service/listeners.rs`,
and the client chain `control.rs` → `service/session.rs` → `work_conn.rs`.
