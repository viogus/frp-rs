# 2026-11-19 — KCP driver-side liveness probe

Status: shipped. Entry point: `docs/deployment.md` § "KCP dead-link bound".

## Symptom

A KCP session is declared dead on a retransmission bound (`[transport.kcp]
deadLink`, default 20), but the bound only fires when the session has a segment
in flight or a queued write. A peer that vanished while the tunnel was idle
therefore went unnoticed until the application next wrote: with `tcpMux = false`
the client heartbeat (30 s) was the only traffic, so a frozen `frps` was
declared dead at ~28-31 s regardless of `deadLink`. Tuning the bound did not
help, because nothing was being sent to trip it.

## Change

The driver now asks a quiet session for the peer's window
(`IKCP_CMD_WASK`), which the peer answers with `IKCP_CMD_WINS`. Both commands
are part of the KCP wire format that kcp-go implements, so this adds no new
message and no incompatibility — it makes silence observable.

- `frp-core/src/kcp/protocol.rs`: `Kcp::request_window_probe()` sets
  `KCP_ASK_SEND`; the existing `flush()` emits the WASK.
- `frp-core/src/kcp/session.rs`: `should_probe` (nothing in flight, quiet for
  `PROBE_IDLE_MS`, and not probed inside this interval), `request_probe` (queues
  the WASK and counts it), `probe_expired` (`PROBE_MAX_UNANSWERED` consecutive
  answers missing). Any inbound datagram — including the WINS answer — clears
  the count in `note_inbound`.
- `frp-core/src/kcp/socket.rs`: the 10 ms driver tick probes and expires
  sessions; expiry removes the session with
  `KCP session dead link (unanswered window probes)`.
- `PROBE_IDLE_MS = 500`, `PROBE_MAX_UNANSWERED = 3`: a live peer that loses one
  datagram is not killed, a frozen one is noticed in about a second.

A session is only probed when `wait_snd() == 0`, so a session carrying data is
still handled by the retransmission bound and a probe never competes with
payload for the driver's flush.

## Measurements

4-vCPU Linux VM (EPYC-Milan), `ssh gc`. Configs: server `bindPort = 19100`,
`kcpBindPort = 19102`, `tcpMux = false`; client `serverPort = 19102`,
`transport.protocol = "kcp"`, `tcpMux = false`, proxy 19054 → 19056. Default
client heartbeat (30 s). `frps` frozen with `SIGSTOP` mid-transfer of a 4096 MiB
stream; detection = first `dead link` line after the freeze.

| arm | `deadLink` | freeze | detected after |
|---|---|---|---|
| before (no probe) | 5 | 15 s | **>15 s** (none) |
| before (no probe) | 5 | 15 s | **>15 s** (none) |
| with probe | 5 | 15 s | **1.05 s / 1.15 s** |
| with probe | 20 | 8 s | **1.15 s / 1.05 s** |

The bound no longer matters for detection speed — which is the point: the probe
supplies the traffic the bound needs.

Cost, 60 s with only a control connection and no proxies:

| arm | frps ticks | frpc ticks | dead-link lines |
|---|---|---|---|
| before | 40 | 39 | 0 |
| with probe | 41 | 36 | 0 |

Throughput, single KCP flow, 512 MiB, `tcpMux = false` (two reps each): before
107.2 / 119.1 MiB/s, with probe 116.0 / 115.6 MiB/s — unchanged. Probes only
fire when the send queue is empty, so bulk transfer never emits one.

Live-idle behaviour: a TCP connection through the proxy held open for 60 s with
no traffic still echoed a payload sent after the idle period, and the session
was not reaped.

Go interoperability: `scripts/compat-test.sh` against Go frp v0.72.0 → 86
passed, 0 failed (includes the KCP scenarios), so a Go peer answers our WASK the
same way.

## An observed non-false positive

During a 60 s soak with no traffic, the server logged one dead link: the
client's on-demand work connection had been abandoned by the client after its
10 s `StartWorkConn` timeout
(`frp-client/src/work_conn.rs`: "read error: timed out waiting for StartWorkConn"),
so the server's session had no peer left. Declaring it dead one second later is
the desired behaviour; the log line says "unanswered window probes" rather than
"retransmission limit" so the two causes stay distinguishable.

## What was not established

- Whether a very lossy path can drop three consecutive WASK/WINS pairs. One
  datagram being lost is tolerated by design; three in a row would need a
  sustained loss rate, and the earlier attempt to build a loss harness ended
  without a usable series (`docs/archive/notes/2026-11-19-kcp-dead-link.md`).
- The probe interval and count are constants, not settings. They were chosen
  from the table above; exposing them would add config surface for a knob with
  no measured second use.
- Only the frp-rs side probes. A Go peer keeps its own behaviour, so a Go
  client still notices an frp-rs `frps` via its heartbeat.
