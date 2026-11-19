# 2026-11-19 — KCP driver-side liveness probe

Status: shipped. Entry point: `docs/deployment.md` § "KCP dead-link bound".

## Symptom

A KCP session is declared dead on a retransmission bound (`[transport.kcp]
deadLink`, default 20), but the bound only fires when the session has a segment
in flight. A peer that vanished while the tunnel was idle therefore went
unnoticed until the application next wrote: with `tcpMux = false` the client
heartbeat (30 s) was the only traffic, so a frozen `frps` was declared dead at
~28-31 s regardless of `deadLink`. Tuning the bound did not help, because
nothing was being sent to trip it. Anything that lives on the KCP transport
therefore carried a ~30 s blind spot.

## Change

The driver now asks a quiet session for the peer's window (`IKCP_CMD_WASK`),
which the peer answers with `IKCP_CMD_WINS`. Both commands are part of the KCP
wire format that kcp-go implements, so this adds no new message and no
incompatibility — it makes silence observable, and a Go peer answers without any
configuration of its own.

- `frp-core/src/kcp/protocol.rs`: `Kcp::request_window_probe()` sets
  `KCP_ASK_SEND`; the existing `flush()` emits the WASK. `in_flight()` exposes
  the in-flight segment count (`snd_buf`), which is what "nothing in flight"
  has to mean.
- `frp-core/src/kcp/session.rs`: `should_probe` (nothing in flight, quiet for
  `PROBE_IDLE_MS`, and not probed inside this interval), `request_probe` (queues
  the WASK and counts it), `probe_expired(now)` (`PROBE_MAX_UNANSWERED`
  consecutive answers missing **and** the last probe has had its own interval).
  Any inbound datagram — including the WINS answer — clears the count in
  `note_inbound`.
- `frp-core/src/kcp/socket.rs`: the 10 ms driver tick probes and expires
  sessions; expiry removes the session with
  `KCP session dead link (unanswered window probes)`.
- `frp-core/src/kcp/config.rs` / `frp-core/src/config/server.rs`:
  `liveness_probe` / `[transport.kcp] probe` (default `true`), plumbed through
  `DialOptions` and the listener like `deadLink`.
- `PROBE_IDLE_MS = 500`, `PROBE_MAX_UNANSWERED = 3`: probes leave at 0.5 s,
  1.0 s and 1.5 s after the session goes quiet, and the tear-down waits one
  more interval so the third answer can still arrive — about **2 s** after the
  peer's last datagram. One or two dropped probes cost nothing; zero answers
  do.

The gate is "nothing in flight", not "nothing waiting to be sent": data parked
in `snd_queue` behind a zero peer window never reaches the wire, so
`wait_snd() > 0` there while the retransmission bound can never fire. Probing on
an empty `snd_buf` covers that state too.

## Measurements

4-vCPU Linux VM (EPYC-Milan), `ssh gc`. Configs: server `bindPort = 19100`,
`kcpBindPort = 19102`, `tcpMux = false`; client `serverPort = 19102`,
`transport.protocol = "kcp"`, `tcpMux = false`, proxy 19054 → 19056. Default
client heartbeat (30 s). `frps` frozen with `SIGSTOP` mid-transfer of a 4096 MiB
stream; detection = first `dead link` line after the freeze.

| arm | `deadLink` | freeze | detected after |
|---|---|---|---|
| before (no probe) | 5 | 15 s | **>15 s** (none, two reps) |
| before (no probe) | 5 | 15 s | **>15 s** (none, two reps) |
| with probe | 5 | 15 s | **1.05 s / 1.15 s** |
| with probe | 20 | 8 s | **1.15 s / 1.05 s** |

The bound no longer matters for detection — which is the point: the probe
supplies the traffic the bound needs.

Cost, 60 s idle:

| scenario | probing on | probing off |
|---|---|---|
| control connection only | 41 / 36 ticks | 40 / 39 ticks |
| 200 proxies (`tcpMux = false`) | 44 / 40 ticks | 43 / 39 ticks |

(`ticks` are `utime+stime` from `/proc/<pid>/stat` for `frps` / `frpc`.) Two
datagrams per second per idle session per end, plus an O(sessions) scan the
driver already ran, is invisible at 200 sessions.

Throughput, one KCP flow, 512 MiB, `tcpMux = false`: 116.0 / 115.6 MiB/s with
probing against 107.2 / 119.1 without — inside the run-to-run spread, which is
expected: probes only fire on a session with nothing in flight.

Live-idle behaviour: a TCP connection through the proxy held open for 60 s with
no traffic still echoed data afterwards, and the session was not reaped.

## The trade-off this cannot avoid

The probe is unsolicited inbound traffic. Where that direction is legitimately
closed — the usual case being a client whose UDP mapping expired — a perfectly
healthy peer looks silent **to the side that is sending the probes**, which
then reaps the session. The peer only notices at its next keepalive, so the
cost is one reconnect per NAT mapping lifetime instead of nothing. Note the
asymmetry: the NATed side's own probes still leave, so it is normally the
*public* side that reaps, not the NATed one.

Reproduced on the VM by blocking `frps`→client UDP (`iptables -I OUTPUT -p udp
--sport 19102 -j DROP`) for 5 s on an established idle tunnel:

| probing | dead-link lines during the 5 s black hole | end-to-end recovery after unblock |
|---|---|---|
| on | 3 | 0.9 s |
| off | 0 | 0.6 s |

The end-to-end recovery is similar because the client's own retransmission bound
also fires once its data stops being ACKed; the observable difference is that
with probing on the server throws away healthy sessions. Hence the knob:
`probe = false` on the side whose probes cannot get through — normally the
public side — and `true` on the NATed side, whose probes both reach the peer and
keep the mapping refreshed. KCP has no NAT traversal of its own, so there is no
probe that both traverses a closed mapping and reaches the peer — this is a
choice, not a bug that can be fixed downstream.

## Tests

- `frp-core/src/kcp/session.rs`: quiet session probes after the idle interval
  and not inside it; an inbound datagram clears the count; a session with data
  in flight is not probed; the request flushes as a `KCP_CMD_WASK` segment; the
  last probe gets its own interval before expiry.
- `frp-core/src/kcp/socket.rs`: `the_driver_reaps_a_silent_peer_and_keeps_an_answering_one`
  drives a real `KcpSocket` against two raw-UDP stub peers (one answers WASK
  with WINS, one never answers) and asserts the silent session's read channel
  closes within 6 s while the answering one stays open. Mutation check: with
  the probe block disabled (`if false && …`) the test fails at the 6 s timeout,
  so deleting the tick wiring can no longer pass the suite.
- `frp-core/src/config/tests.rs`: the parsed `[transport.kcp]` values reach the
  listener config, including an absent `probe` key leaving it on.

## What was not established

- The multi-session cost was measured at 200 sessions on a 4-vCPU box; a
  deployment with thousands of idle KCP sessions would scale the scan linearly
  and was not measured.
- The NAT behaviour is modelled with `iptables` on loopback, not with a real
  NAT whose mapping lifetime is minutes; the reconnect frequency in the field
  will follow the operator's NAT timeout.
- The visitor dials and the XTCP proxy's P2P plane build their own KCP configs
  and do not expose `[transport.kcp]`, so they keep probing on (they are the
  same defaults).
