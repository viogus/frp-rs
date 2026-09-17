# Bounded Channels: KCP, Proxy, and Project-Wide

**Date:** 2026-07-15
**Status:** Design approved
**Go frp v0.70 compat:** Yes — matches Go frp channel patterns exactly

## Motivation

The codebase uses `mpsc::unbounded_channel()` for 25+ channels across KCP, server
control, SSH, NAT hole, client service, and mux subsystems. Unbounded channels
allow a slow or malicious peer to exhaust server memory by flooding the channel
faster than the consumer drains it. Go frp v0.70 uses bounded channels with
explicit backpressure throughout — Rust must match this behavior for both
security and wire compatibility.

## Design Principles

1. **Go frp compat**: bounded channels, `try_send` (Go `select/default`) on
   producer side, `recv` with timeout on consumer side.
2. **Reactor safety**: KCP UDP event loop is a single `tokio::select!`. Any
   blocking branch blocks ALL session I/O and UDP recv. All KCP socket channels
   use `try_send` — no blocking send.
3. **Spawned tasks can block**: proxy control handlers, client service handlers
   run in dedicated async tasks. `send().await` is safe here.
4. **Drop semantics**: dropped messages must be handled gracefully. KCP drops
   are recovered by protocol retransmission. Proxy work connection drops cause
   `GetWorkConn` timeout → client retries. Admin reload drops are logged and
   the caller retries.

## Channel Inventory

### KCP Subsystem (frp-core/src/kcp/)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `write_tx`/`write_rx` | 256 | `try_send` | Drop packet, KCP retransmits | Go frp uses unbuffered per-conn Go channel; 256 is safe ceiling |
| `read_tx`/`read_rx` (per-session) | 256 | `try_send` | Drop packet, KCP retransmits | Per-session channel; 256 queued reads before backpressure |
| `accept_tx`/`accept_rx` | 256 | `try_send` | Reject new session | 256 backlogged accepts = severely overloaded |
| `register_tx`/`register_rx` | 64 | `try_send` | Return error to dial_kcp | Outbound dials are rare (poolCount typically 1-5) |
| `accept_notify_tx`/`accept_notify_rx` | 256 | `try_send` | Skip (session ages out of timeout set naturally) | Notification is best-effort; 30s fallback handles drops |

**Write backlog fix**: existing `AtomicUsize` backlog counter currently
increments AFTER dequeue (measures "processing" not "queued"). Fix: increment
before `try_send`, decrement on `Err(Full)`. Combined with bounded channel,
this gives double-layer backpressure — AtomicUsize gate at KcpStream level,
mpsc capacity at socket level.

### Server Control Subsystem (frp-server/src/control/)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `internal_tx`/`internal_rx` | 1024 | `send().await` | Backpressure on caller | Spawned task; blocking is safe. 1024 = 32 clients × 32 ops each |
| `workConnCh` (new, per-control) | `poolCount + 10` | `try_send` | Return "pool full" error | Exact Go frp match: `make(chan *proxy.WorkConn, poolCount+10)` with `select/default` |
| `pending_requests` (existing VecDeque) | implicit via workConnCh | N/A | Requests timeout via `user_conn_timeout` | Bounded by pool size — no separate limit needed |

`workConnCh` replaces the current `work_pool: VecDeque<WorkConn>`. New flow:
- `RegisterWorkConn`: `try_send` into channel. If full, discard work conn with
  error (Go compat: `select/default` returns error).
- `GetWorkConn`: `tokio::time::timeout(user_conn_timeout, rx.recv())`. On
  timeout, return error to caller (Go compat: `select { case <-ch / case
  <-time.After }`).
- Pool priming: send `poolCount` × `ReqWorkConn` on startup, exactly like Go's
  `Start()` goroutine.

### Client Subsystem (frp-client/src/)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `visitor_tx`/`visitor_rx` | 64 | `send().await` | Backpressure | Visitor creation is infrequent |
| `xtcp_tx`/`xtcp_rx` | 64 | `try_send` | Drop stale notification | XTCP is best-effort NAT traversal |
| `reload_tx`/`reload_rx` | 4 | `send().await` | Block | Admin-only, 1-2 concurrent max |
| `health_tx`/`health_rx` | 16 | `try_send` | Drop (next tick re-sends) | Periodic health check; loss is self-healing |
| `stop_tx`/`stop_rx` | 1 | `send().await` | N/A | Shutdown is critical, single producer |
| `vnet_tun_tx` (per-VNet) | 256 | `try_send` | Drop packet | IP networks drop under congestion |

### SSH Gateway (frp-server/src/ssh_gateway.rs)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `frame_tx`/`frame_rx` | 64 | `try_send` | Drop frame (TCP retransmits) | SSH runs over TCP; drops recover |
| `work_tx`/`work_rx` | 16 | `send().await` | Backpressure | Work conn requests are rare (1 per SSH session) |

### NAT Hole (frp-server/src/nathole/)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `sid_ch` | 64 | `send().await` | Block | Session-scoped, short-lived |

### TCP Mux (frp-core/src/mux.rs)

| Channel | Capacity | Send | On full | Rationale |
|---------|----------|------|---------|-----------|
| `tx`/`rx` (OpenRequest) | 256 | `try_send` | Drop stream creation request | yamux connection handles drops via keepalive |

## Error Handling

All `try_send` failures log at `warn!` level with channel name + current
capacity. Consumers that use `tokio::time::timeout(recv)` log at `debug!`
on timeout (normal operation under load) and `warn!` when channel is closed
(teardown).

## Testing

- **Unit**: each bounded channel with `try_send` → verify `Err(Full)` after
  capacity reached, verify `recv` drains correctly.
- **Integration**: KCP soak test: 60s run with high packet loss, verify no
  panics, no memory growth beyond channel capacities.
- **Stress**: connection flood test: rapid accept/close of KCP sessions, verify
  `accept_tx` full gracefully rejects without blocking UDP recv.

## Implementation Order

1. KCP socket channels (highest risk, highest impact)
2. Write backlog fix (unblocks KCP bounded channels)
3. Server control `workConnCh` (Go compat)
4. Client subsystem
5. SSH gateway + NAT hole + mux
6. Integration/soak tests

## File Impact

- `frp-core/src/kcp/socket.rs` — bounded channels, peer_session_counts IpAddr
- `frp-core/src/kcp/listener.rs` — accept notify channel
- `frp-core/src/kcp/stream.rs` — write_backlog fix
- `frp-core/src/kcp/session.rs` — read_tx capacity
- `frp-server/src/control/mod.rs` — workConnCh, internal_tx capacity
- `frp-server/src/control/proxy_ops.rs` — internal_tx usage
- `frp-server/src/state.rs` — ControlTx struct update
- `frp-client/src/service.rs` — bounded channels
- `frp-client/src/visitor.rs` — bounded channels
- `frp-client/src/work_conn.rs` — bounded channels
- `frp-client/src/admin.rs` — bounded channels
- `frp-client/src/health.rs` — bounded channels
- `frp-server/src/ssh_gateway.rs` — bounded channels
- `frp-server/src/nathole/controller.rs` — bounded channels
- `frp-core/src/mux.rs` — bounded channels
