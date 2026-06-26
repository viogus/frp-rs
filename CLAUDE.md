# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / Test / Lint

```bash
cargo build                  # Build all crates
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
cargo run --bin frps -- -c frps.toml
cargo run --bin frpc -- -c frpc.toml
RUST_LOG=debug cargo run --bin frps -- -c frps.toml  # Enable debug logging
```

- No `cargo check` variation needed — use `cargo build` for the full workspace.
- Tests live inline (`#[cfg(test)] mod tests`), no separate test crates.

## Architecture: Beyond the README

The README gives a solid overview. The sections below cover details that reading a single file won't reveal.

### Wire Protocol

**V1** (fully implemented): 9-byte header — 1 byte type + 8 bytes big-endian payload length (max 64 KiB) — followed by UTF-8 JSON payload. Defined in `frp-core/src/protocol.rs`.

**V2** (stubs only): 7-byte magic `FRP\0\x02\r\n` + different framing. `detect_v2_magic` and `write_v2_magic` exist but no V2 frame read/write is implemented.

Message type bytes and structs live in `frp-core/src/msg.rs`. The `FrpMessage` enum is `#[serde(untagged)]` — serde matches the first variant whose fields intersect the JSON, which means ordering of the enum variants matters.

### Authentication (Note: README is outdated)

Auth uses **MD5(token + timestamp)** → hex string (NOT HMAC-SHA256 as the README states). This matches Go frp v0.69.1 behavior — the switch from HMAC-SHA256 to MD5 happened in commit `78f9394`. See `frp-core/src/auth.rs`.

### Encryption Key Derivation

Uses **PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16)** for AES-128-CFB control encryption. Go frp v0.69.1 pre-built binary uses PBKDF2 salt `"frp"` (NOT `"crypto"` — the golib source says `"crypto"` but the Go frp binary was compiled with salt `"frp"`). See `frp-core/src/encryption.rs`.

### Server Architecture: The InternalMsg Channel

The server's core is a pattern of cross-task message passing (`frp-server/src/service.rs`):

```
AppState
  ├── run_id_to_ctl_tx: HashMap<run_id, ControlTx>   // routes work conns to correct handler
  ├── proxy_manager: ProxyManager                     // global proxy registry
  ├── used_ports: HashSet<u16>                        // port allocation tracking
  ├── sk_index: HashMap<sk, proxy_name>              // STCP secret-key → proxy lookup
  └── vhost_manager: VhostManager                     // HTTP VHost routing
```

**Connection dispatch** (`service.rs`, accept loop):
- Every new TCP connection reads one frame. If it's `Login` → `handle_control()`. If it's `NewWorkConn` → `handle_work_conn_inner()` (looks up `run_id_to_ctl_tx`, forwards the stream via `InternalMsg::NewWorkConn`).

**Control handler** (`control.rs`): the most complex file. Runs a `tokio::select!` loop with:
1. **Biased** `internal_rx.recv()` — prioritized to reduce proxy connection latency
2. `read_msg_v1(&mut reader)` — inbound messages from the client

Internal message variants drive the work connection lifecycle:
- `ProxyUserConn` / `VisitorConn` → check `work_pool` → if empty, send `ReqWorkConn` and push to `pending_requests`
- `NewWorkConn` → if `pending_requests` is non-empty, pop and bridge immediately; otherwise push to `work_pool`

**Bridging** (`assign_work_to_proxy` in `control.rs`): sends `StartWorkConn` over the work connection, writes any pre-read bytes (from HTTP VHost parsing), then either uses `tokio::io::copy_bidirectional` (plain) or `bridge::bridge_encrypted` (AES-256-GCM framed).

### Encryption

`frp-core/src/encryption.rs`: AES-256-GCM with a key derived via SHA-256 from the auth token (`encryption_key` in `AppState`). Encrypted bridge uses a 4-byte big-endian length prefix framing (`bridge.rs`).

`derive_key` is called in `Service::new()` with `auth_cfg.token` — the encryption key derives from the auth token, not a separate secret.

### Transport Abstraction

`IoStream` (`frp-core/src/transport.rs`) is a unified enum over `TcpStream`, `TlsStream<TcpStream>`, `DuplexStream` (KCP placeholder), and `WebSocketStream`. The `WsByteStream` adapter wraps WebSocket binary messages into `AsyncRead`/`AsyncWrite` so the V1 protocol can operate over WebSocket without changes.

`IoStream::into_split()` returns `Box<dyn AsyncRead>` / `Box<dyn AsyncWrite>` — the work connection bridge uses this to erase the concrete stream type.

### Config Normalization

`frp-core/src/config.rs` includes a full Go→Rust config compatibility layer:

- `[common]` sections are flattened to the top level
- `auth_method` / `auth_token` → nested under `[auth]`
- `log_file` / `log_level` → nested under `[log]`
- `web_server_*` → nested under `[web_server]`
- `tcp_mux` → nested under `[transport]`
- Client-side: `protocol` → `transport_protocol`, `serverAddr` → `server_addr`, `auth.token` → top-level `token`
- TOML values are converted via `toml_to_json()` to `serde_json::Value`, then deserialized into config structs

### Placeholder / Stub Code

- `TcpMux` (`frp-core/src/mux.rs`): empty struct, commented-out yamux dependency
- `dashboard.rs` and `vhost.rs` mods declared in `frp-server/src/lib.rs` but contain minimal scaffolding
- KCP, QUIC, WebSocket work connections: handled as match arms that log a warning and return
- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README says `false` for frpc.toml — be aware the code default is `true`

### Workspace Dependencies

Cargo workspace uses `resolver = "2"` with `[workspace.dependencies]` for all crates. Adding a new dependency: add to workspace level, then reference by name (no version) in sub-crates.
