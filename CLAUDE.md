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

## Development Workflow (mandatory)

Every feature, fix, and test change follows three rules:

1. **Worktree** — create a git worktree (`EnterWorktree`) before any file modification. Never edit directly on the main branch.
2. **Subagents** — dispatch work to subagents (`Agent` or `Workflow` tool). One subagent per logical task, review between tasks.
3. **Compat tests** — after any protocol, transport, encryption, or proxy change, run the cross-compatibility test suite:
   ```bash
   bash scripts/compat-test.sh --verbose
   ```
   CI gate: `.github/workflows/compat.yml` must stay green. Download Go frp first if needed:
   ```bash
   bash scripts/download-go-frp.sh
   ```

## Architecture: Beyond the README

The README gives a solid overview. The sections below cover details that reading a single file won't reveal.

### Wire Protocol

**V1** (fully implemented): 9-byte header — 1 byte type + 8 bytes big-endian payload length (max 64 KiB) — followed by UTF-8 JSON payload. Defined in `frp-core/src/protocol.rs`.

**V2** (stubs only): 7-byte magic `FRP\0\x02\r\n` + different framing. `detect_v2_magic` and `write_v2_magic` exist but no V2 frame read/write is implemented.

Message type bytes and structs live in `frp-core/src/msg.rs`. The `FrpMessage` enum is `#[serde(untagged)]` — serde matches the first variant whose fields intersect the JSON, which means ordering of the enum variants matters.

### Authentication

Auth uses **MD5(token + timestamp)** → hex string. Matches Go frp v0.69.1 behavior — Go frp switched from HMAC-SHA256 to MD5 in commit `78f9394`. See `frp-core/src/auth.rs`.

### Encryption Key Derivation

Uses **PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16)** for AES-128-CFB control encryption. Go frp v0.69.1 pre-built binary uses PBKDF2 salt `"frp"` (NOT `"crypto"` — the golib source says `"crypto"` but the Go frp binary was compiled with salt `"frp"`). See `frp-core/src/encryption.rs`.

### Server Architecture: The InternalMsg Channel

The server's core is a pattern of cross-task message passing (`frp-server/src/service.rs`):

```
AppState
  ├── run_id_to_ctl_tx: HashMap<run_id, ControlTx>   // routes work conns to correct handler
  ├── proxy_manager: ProxyManager                     // global proxy registry
  ├── used_ports: HashSet<u16>                        // port allocation tracking
  ├── sk_index: HashMap<sk, proxy_name>              // STCP/XTCP secret-key → proxy lookup
  ├── vhost_manager: VhostManager                     // HTTP VHost routing
  ├── nat_hole: Arc<NatHoleCoordinator>              // XTCP NAT hole punch session mgmt
  ├── oidc_verifier: Option<Arc<OidcVerifier>>       // OIDC token verification
  └── oidc_subjects: HashMap<sub, proxy_name>        // OIDC subject → proxy routing
```

**Connection dispatch** (`service.rs`, accept loop):
- Every new TCP connection reads one frame. Dispatch by message type:
  - `Login` → `handle_control()` (new control connection)
  - `NewWorkConn` → `handle_work_conn_inner()` (routes to control handler via `run_id`)
  - `NewVisitorConn` → `handle_visitor_conn_inner()` (STCP visitor, looks up `sk_index`)
  - `NatHoleVisitor` → `handle_nat_hole_visitor()` (XTCP hole punch, fresh-connection path)
- WebSocket connections on main port also dispatch the same message types after upgrade.

**Control handler** (`control.rs`): the most complex file. Runs a `tokio::select!` loop with:
1. **Biased** `internal_rx.recv()` — prioritized to reduce proxy connection latency
2. `read_msg_v1(&mut reader)` — inbound messages from the client

Internal message variants drive the work connection lifecycle:
- `ProxyUserConn` / `VisitorConn` → check `work_pool` → if empty, send `ReqWorkConn` and push to `pending_requests`
- `NewWorkConn` → if `pending_requests` is non-empty, pop and bridge immediately; otherwise push to `work_pool`
- `UdpNeedsWorkConn` → triggers work connection creation for UDP proxy
- `NatHoleClient` → forwarded to provider control handler to initiate NAT hole punch
- `WriteNatHoleSid` / `WriteNatHoleReport` → forwarded to visitor via control channel (Go frp compat path)
- `Shutdown` → old control handler stops when superseded by new connection with same run_id

**Bridging** (`assign_work_to_proxy` in `control.rs`): sends `StartWorkConn` over the work connection, writes any pre-read bytes (from HTTP VHost parsing), then either uses `tokio::io::copy_bidirectional` (plain) or `bridge::bridge_encrypted` (AES-128-CFB + Snappy, 4-byte BE length prefix framing).

### Encryption

**Control connection:** AES-128-CFB. Key derived via PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16). See `frp-core/src/encryption.rs`.

**Encrypted bridge (data plane):** AES-128-CFB streaming with Snappy compression (applied first: compress → encrypt). Framing: 4-byte big-endian length prefix + 16-byte IV + CFB-encrypted payload. See `frp-core/src/bridge.rs`.

`derive_key` is called in `Service::new()` with `auth_cfg.token` — the encryption key derives from the auth token, not a separate secret.

Note: Go frp v0.69.1 golib source says salt `"crypto"` but the pre-built binary uses salt `"frp"`. This codebase uses `"frp"` for binary compatibility.

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

### XTCP NAT Hole Punching

`frp-server/src/nat_hole.rs`: `NatHoleCoordinator` manages hole-punch sessions.

Two paths for visitor connections:
1. **Fresh TCP connection** (accept loop): visitor sends `NatHoleVisitor` on a new connection. Writer stored in session for `NatHoleSid`/`NatHoleReport` forwarding.
2. **Control connection** (Go frp compat): Go frpc v0.69.1 sends `NatHoleVisitor` on its existing control channel. Uses `InternalMsg::WriteNatHoleSid`/`WriteNatHoleReport` for forwarding.

Flow: Visitor→Server(NatHoleVisitor) → Server→Provider(NatHoleClient via InternalMsg) → Provider→Server(NatHoleSid) → Server→Visitor(NatHoleSid forwarded) → ... → Provider→Server(NatHoleReport) → session complete.

**Status:** Server-side (phase 1) complete. Provider-side NAT detection (QUIC-based, phase 2) not yet implemented — needed for full Go frp v0.69.1 XTCP compat.

### Transport Status

- **TCP**: fully implemented (control + work connections, TLS, WebSocket upgrade)
- **WebSocket**: control and visitor connections work on main port; work connection dial not yet implemented
- **KCP**: accept loop + message dispatch working; work connection dial not yet implemented
- **QUIC**: accept loop + message dispatch working (requires TLS cert); work connection dial not yet implemented
- **TcpMux** (`frp-core/src/mux.rs`, 258 lines): full yamux implementation — server and client mode, keepalive, stream accept/spawn
- **Dashboard** (`frp-server/src/dashboard.rs`, 86 lines): basic status API with axum (version, uptime, client/proxy counts)
- **VHost** (`frp-server/src/vhost.rs`, 394 lines): HTTP/HTTPS VHost routing with Host header parsing, SNI, pre-read byte forwarding

### Gotchas

- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README example shows `false` — be aware the code default is `true`
- `#[serde(untagged)]` on `FrpMessage` enum — ordering matters for serde matching, but V1 protocol dispatches by type byte first via `deserialize_v1()`, so untagged matching is not involved in wire deserialization

### Workspace Dependencies

Cargo workspace uses `resolver = "2"` with `[workspace.dependencies]` for all crates. Adding a new dependency: add to workspace level, then reference by name (no version) in sub-crates.
