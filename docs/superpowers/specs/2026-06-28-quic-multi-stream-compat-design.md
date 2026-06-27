# QUIC Multi-Stream Go↔Rust Compatibility

**Date:** 2026-06-28
**Status:** approved
**Scope:** Enable `test_g2r_quic` and `test_r2g_quic` compat tests

## Problem

Go frp (quic-go) uses a single QUIC connection with multiple bidirectional streams: stream 0 = control, additional streams = work connections. Rust frp-rs (quinn) treats each QUIC connection as a single stream — `QuicListener::accept()` returns one stream per connection, and `dial_quic()` opens one stream per connection. Work connections on additional streams are silently dropped.

Two affected test paths:
- **test_g2r_quic**: Go frpc opens work conns as new streams on the control QUIC connection → Rust frps only sees the first stream
- **test_r2g_quic**: Rust frpc dials new QUIC connections for work conns → Go frps expects new streams on the existing connection

## Design

### New type: `QuicConnection` (`frp-core/src/quic.rs`)

Wraps `quinn::Connection` to expose multi-stream operations:

```rust
pub struct QuicConnection {
    conn: quinn::Connection,
}

impl QuicConnection {
    pub async fn accept_bi(&self) -> io::Result<QuicStream>;
    pub async fn open_bi(&self) -> io::Result<QuicStream>;
}
```

### API changes

| Function | Before | After |
|----------|--------|-------|
| `QuicListener::accept()` | `-> QuicStream` | `-> (QuicStream, QuicConnection)` |
| `dial_quic()` | `-> QuicStream` | `-> (QuicStream, QuicConnection)` |

### Server accept loop (`frp-server/src/service.rs`)

After accepting a QUIC connection and dispatching the first stream:
- If `Login`: call `handle_control()`, then spawn a drain loop calling `conn.accept_bi()` to accept remaining streams. Each additional stream reads `NewWorkConn` and dispatches via `handle_work_conn_inner()`.
- If `NewWorkConn`: dispatch directly (existing behavior).

The `QuicConnection` stays alive in the spawned task. Stream-accept loop runs until `accept_bi()` returns error (connection closed).

### Client login (`frp-client/src/control.rs`)

`login()` return type: `(IoStream, String, Option<YamuxSession>, Option<QuicConnection>)`.

QUIC path: call `dial_quic()` directly, wrap `QuicStream` in `IoStream::Quic(...)`, return `QuicConnection`.

### Client work connections (`frp-client/src/service.rs`)

`spawn_work_conn()` gains parameter `quic_conn: Option<Arc<QuicConnection>>` — same pattern as `yamux: Option<Arc<YamuxSession>>`.

Priority in work conn acquisition:
1. If `quic_conn` is Some → `quic_conn.open_bi().await` → `IoStream::Quic(stream)`
2. Else if `yamux` is Some → `yamux.open_stream().await` → `IoStream::Yamux(stream)`
3. Else → `dial_server(&opts).await` (existing TCP/TLS/KCP path)

Service stores `quic_conn` alongside `yamux` in its state, passes to each `spawn_work_conn()` call.

### Transport layer (`frp-core/src/transport.rs`)

`dial_server()` QUIC path: call `dial_quic()`, return `IoStream::Quic(stream)`. The `QuicConnection` is returned separately by the caller (`login()`) which calls `dial_quic()` before delegating to `dial_server()` for other transports.

### Compat test unguard (`scripts/compat-test.sh`)

Uncomment `test_g2r_quic` and `test_r2g_quic` in the runner. KCP tests remain guarded (separate change for kcp-go session layer).

## Files changed

| File | Change | Est. lines |
|------|--------|-----------|
| `frp-core/src/quic.rs` | Add `QuicConnection`, refactor accept/dial | +45 / −10 |
| `frp-core/src/transport.rs` | QUIC dial path returns connection | ~15 |
| `frp-server/src/service.rs` | Multi-stream accept + drain loop | ~35 |
| `frp-client/src/control.rs` | Login returns QuicConnection | ~25 |
| `frp-client/src/service.rs` | spawn_work_conn open_bi path | ~30 |
| `scripts/compat-test.sh` | Unguard QUIC tests | 2 lines |
| **Total** | | **~140** |

## Testing

- `cargo build --release` — verify compilation
- `cargo test --workspace` — unit tests pass
- `bash scripts/compat-test.sh --test go-to-rust-quic --verbose` — Go→Rust QUIC
- `bash scripts/compat-test.sh --test rust-to-go-quic --verbose` — Rust→Go QUIC
- Full compat suite: `bash scripts/compat-test.sh` — no regressions (38/38 → 40/40)

## Out of scope

- KCP Go↔Rust compat (separate design — requires kcp-go session layer implementation)
- QUIC multiplexing for V2 protocol (V2 is separate workstream on `feature/v2-protocol`)
