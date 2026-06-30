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

### Binary Variants

Three size tiers via feature flags:

```bash
# Full (all features)
cargo build --release -p frps -p frpc
# → frps (~4.8MB), frpc (~3.7MB)

# Tiny (no heavy protocols: QUIC/KCP/WS/SSH/OIDC/dashboard; keeps TLS)
cargo build --release -p frps -p frpc --no-default-features --features tiny
# → frps-tiny (~2.7MB), frpc-tiny (~2.3MB)

# Micro (core only: no TLS, compression, chacha20, HTTP proxy, tcp-mux)
cargo build --release -p frps -p frpc --no-default-features --features micro
# → frps-micro (~1.6MB), frpc-micro (~1.7MB)
```

Feature flags across crates:
| Feature | Crate | Removes |
|---------|-------|---------|
| `quic` | frp-core | QUIC transport (quinn, ~1MB) |
| `kcp` | frp-core | KCP transport (kcp) |
| `websocket` | frp-core/server | WebSocket transport (tokio-tungstenite) |
| `oidc` | frp-core | OIDC auth (jsonwebtoken, reqwest) |
| `ssh` | frp-server | SSH gateway (russh, rand 0.10) |
| `dashboard` | frp-server | Metrics/status API (prometheus, axum) |
| `tls` | frp-core/server/client | TLS encryption (rustls, webpki-roots) |
| `compression` | frp-core | Snappy bridge compression (snap) |
| `chacha20` | frp-core | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | frp-server | HTTP proxy plugin (reqwest) |
| `tcp-mux` | frp-core/server/client | yamux stream multiplexing (~80KB) |

All features default ON. `quic` implies `tls`. `oidc` implies `reqwest`. `ssh` implies `rand`.

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

**V2** (fully implemented): 7-byte magic `FRP\0\x02\r\n` + different framing. V2 frame read/write (`write_v2_frame_raw`/`read_v2_frame_raw`), message dispatch (`write_msg_v2`/`read_msg_v2`), AEAD encryption (`v2_handshake.rs`: ClientHello/ServerHello, HKDF key derivation, `crypto.rs`: AeadAlgorithm trait for AES-256-GCM/ChaCha20-Poly1305), and capability negotiation all implemented. V2 compat tests guard behind `GO_FRP_V2=1` (require source-built Go frp; auto-detect locally, skip in CI).

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
- `NatHoleSidOnWorkConn` → sends StartWorkConn+NatHoleSid on pooled work conn to notify provider of XTCP visitor; if pool empty, queues in `pending_nat_hole_sids` + sends `ReqWorkConn` (Go frp compat: server is pure relay, provider does own STUN)
- `WriteNatHoleSid` / `WriteNatHoleResp` / `WriteNatHoleReport` → forwarded to visitor via control channel (Go frp compat path)
- `Shutdown` → old control handler stops when superseded by new connection with same run_id

**Bridging** (`assign_work_to_proxy` in `control.rs`): sends `StartWorkConn` over the work connection, writes any pre-read bytes (from HTTP VHost parsing), then either uses `tokio::io::copy_bidirectional` (plain) or `bridge::bridge_encrypted` (AES-128-CFB + Snappy, 4-byte BE length prefix framing).

### Encryption

**Control connection:** AES-128-CFB. Key derived via PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16). See `frp-core/src/encryption.rs`.

**Encrypted bridge (data plane):** AES-128-CFB streaming with Snappy compression (applied first: compress → encrypt). Framing: 4-byte big-endian length prefix + 16-byte IV + CFB-encrypted payload. See `frp-core/src/bridge.rs`.

`derive_key` is called in `Service::new()` with `auth_cfg.token` — the encryption key derives from the auth token, not a separate secret.

**XTCP P2P encryption:** Go frp encrypts hole-punched P2P connections with PBKDF2-SHA1(SecretKey, salt="frp", iter=64, keylen=16) → AES-128-CFB. Both provider and visitor P2P paths use `bridge_encrypted` with `derive_key(&sk)` when `use_encryption` is true. The `sk` (secret key) is the proxy's `sk` field from `ProxyConfig`, NOT the auth token — this is stored in `ProxyRuntimeInfo` for access in NAT hole punch handler paths.

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

`frp-server/src/nathole/`: `NatHoleCoordinator` manages hole-punch sessions. Module structure:
- `mod.rs` — module root, `NAT_HOLE_TIMEOUT = 10s`
- `controller.rs` — session management, provider registration, `build_nat_hole_response()`
- `classify.rs` — NAT feature classification (EasyNAT vs HardNAT, behavior detection)
- `analysis.rs` — 5-mode behavior table, score-based `Analyzer` with success feedback

Two paths for visitor connections:
1. **Fresh TCP connection** (accept loop): visitor sends `NatHoleVisitor` on a new TCP connection. Server creates session, sends `NatHoleSidOnWorkConn` internal msg → provider control handler writes `StartWorkConn`+`NatHoleSid` on work conn. Provider does STUN, sends `NatHoleClient` on control, server runs NAT analysis, sends `NatHoleResp` to both sides.
2. **Control connection** (Go frp compat): Go frpc v0.69.1 sends `NatHoleVisitor` on its existing control channel. Server creates session with `create_session_with_ctl`, spawns task that waits for provider's `NatHoleClient` on control, runs NAT analysis (classify + analyzer), and sends `NatHoleResp` to both sides via `InternalMsg::WriteNatHoleSid`/`WriteNatHoleResp`/`WriteNatHoleReport`.

Flow: Visitor→Server(NatHoleVisitor) → Server→Provider(NatHoleSidOnWorkConn → StartWorkConn+NatHoleSid on work conn) → Provider does STUN → Provider→Server(NatHoleClient on control) → Server NAT analysis → Server→Visitor(NatHoleResp) + Server→Provider(NatHoleResp) → both sides TCP simultaneous open → bridge p2p → Provider→Server(NatHoleReport) → session complete.

**Status:** Fully implemented. Server operates as pure relay (no server-side STUN — provider and visitor each do their own STUN). Both sides use TCP simultaneous open for hole punching. Provider-side (`frp-client/src/service.rs`) reads StartWorkConn+NatHoleSid from work conn, does STUN, sends NatHoleClient on control, reads NatHoleResp, TCP simultaneous open → bridge to local. Visitor-side (`frp-client/src/visitor.rs`) handles `NatHoleVisitor` → PreCheck + STUN + full NatHoleVisitor → TCP simultaneous open → bridge to user. STCP fallback if hole punch fails (uses `fallback_to` config field to point at separate STCP proxy, matching Go frp architecture). e2e test in `frp-server/tests/xtcp_hole_punch.rs`.

**XTCP P2P bridging:** After successful hole punch, P2P TCP connection uses conditional `bridge_encrypted` (when `use_encryption=true` + `sk` non-empty) or `bridge_plain` (otherwise). Encryption key derived from proxy's `sk` (SecretKey) via `derive_key()` — same derivation as control connection but uses SecretKey instead of auth token. `ProxyRuntimeInfo.sk` stores the SecretKey for access in NAT hole punch handler paths (`NatHoleClient` and `NatHoleResp` handlers in service.rs, visitor P2P path in visitor.rs). Both sides derive the same key from the shared SecretKey, matching Go frp's `wrapWorkConn`/`wrapVisitorConn`.

### Transport Status

- **TCP**: fully implemented (control + work connections, TLS, WebSocket upgrade)
- **WebSocket**: fully implemented — dial, accept, message dispatch (control + work connections)
- **KCP**: fully implemented — dial, accept, message dispatch (control + work connections)
- **QUIC**: fully implemented — dial, accept, message dispatch (requires TLS cert on server)
- **TcpMux** (`frp-core/src/mux.rs`, 258 lines): full yamux implementation — server and client mode, keepalive, stream accept/spawn
- **Dashboard** (`frp-server/src/dashboard.rs`, 86 lines): basic status API with axum (version, uptime, client/proxy counts)
- **VHost** (`frp-server/src/vhost.rs`, 394 lines): HTTP/HTTPS VHost routing with Host header parsing, SNI, pre-read byte forwarding

### Gotchas

- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README example shows `false` — be aware the code default is `true`
- `#[serde(untagged)]` on `FrpMessage` enum — ordering matters for serde matching, but V1 protocol dispatches by type byte first via `deserialize_v1()`, so untagged matching is not involved in wire deserialization
- `ProxyRuntimeInfo` must include `sk: String` field — XTCP P2P encryption derives its AES-128 key from the proxy's SecretKey via `derive_key(&sk)`. Adding new fields to `ProxyRuntimeInfo` requires updating all construction sites: `Service::new()`, `do_reload()` in `reload.rs`, and any other future sites.

### Testing & Tooling

- **Benchmarks**: `cargo bench -p frp-core` (9 groups: key derivation, compression, cipher stream, STUN, V1+V2 protocol all-types, bridge plain/encrypted/compressed, bandwidth limiter) + `cargo bench -p frp-server` (nathole classify + analysis). CI: `cargo bench --workspace --no-run` build-check in `ci.yml`.
- **Property/fuzz tests**: proptest-based config normalization (`frp-core/src/config.rs`, 14 tests) and V1/V2 protocol frame fuzzing (`frp-core/src/protocol.rs`, 13 tests, 0 panics found).
- **Stress tests**: `scripts/stress-test.sh` runs frps + frpc under load with connection churn, monitored via `scripts/frp-stress/`. Weekly CI run in `stress-test.yml`.
- **Cross-compat tests**: `scripts/compat-test.sh` — 40 default + 2 guarded (XTCP 16-test pairwise matrix, V2 `GO_FRP_V2=1`). Runs on every push via `compat.yml`. XTCP compat runs daily on VPS via `xtcp-compat.yml`.

### Dependency Policy (mandatory)

**No new dependencies without explicit justification.** Every new crate added to the workspace must have a documented reason covering:

1. **Why it's needed** — what problem it solves that existing deps cannot
2. **Why the alternative was rejected** — why an existing dep can't be used (e.g., ring for crypto, data_encoding for encoding)
3. **Binary size impact** — approximate cost to frps/frpc release binary

Pre-approved tech stack. Use these unless strong reason to deviate:

| Domain | Crate | Notes |
|--------|-------|-------|
| Async runtime | `tokio` | net, io-util, time, sync, macros, rt-multi-thread, signal |
| Serialization | `serde` + `serde_json` | derive feature |
| Config | `toml` | 0.8 |
| Crypto (general) | `ring` | 0.17 — SHA256, AES-256-GCM, HKDF, HMAC |
| Crypto (Go compat) | `aes` + `cfb-mode`, `pbkdf2` + `sha1`, `md-5` | AES-128-CFB, PBKDF2-SHA1, MD5 — ring lacks these |
| Crypto (V2 XChaCha20) | `chacha20poly1305` | ring only has ChaCha20 (96-bit nonce), V2 needs XChaCha20 (192-bit) |
| TLS | `rustls` + `tokio-rustls` + `rustls-pemfile` + `rustls-platform-verifier` | ring backend, tls12, native cert verifier |
| SSH | `russh` | ring backend (NOT aws-lc-rs), features: ring+rsa only |
| HTTP client | `reqwest` | rustls-tls only (no json, no socks features) |
| HTTP server | `axum` | dashboard, admin auth |
| WebSocket | `tokio-tungstenite` | |
| Encoding | `data_encoding` | BASE64 (also: `hex` for debug logging) |
| Compression | `snap` | Snappy, pure Rust |
| QUIC | `quinn` | |
| KCP | `kcp` | |
| TcpMux | `yamux` | |
| OIDC/JWT | `jsonwebtoken` | |
| Logging | `tracing` + `tracing-subscriber` + `tracing-appender` | env-filter |
| Error handling | `anyhow` + `thiserror` | |
| Random | `rand` | 0.8 |
| Misc | `bytes`, `uuid`, `futures-util`, `tokio-util`, `socket2`, `prometheus` | |

**Removed and banned** (do not reintroduce without approval):
- `aws-lc-sys` / `aws-lc-rs` — replaced by ring (russh default → ring feature)
- `hmac` — dead dependency, ring covers HMAC
- `base64` — replaced by data_encoding
- `sha2` — replaced by ring
- `aes-gcm` — replaced by ring (AES-256-GCM)
- `hkdf` — replaced by ring (HKDF-SHA256)
- `hickory-resolver` — replaced by custom DNS-over-UDP client
- `lazy_static` — replaced by `std::sync::LazyLock` (stable since Rust 1.80)
- `libc` — dead direct dependency (transitively available via quinn→core-foundation on macOS)

### Workspace Dependencies

Cargo workspace uses `resolver = "2"` with `[workspace.dependencies]` for all crates. Adding a new dependency: add to workspace level, then reference by name (no version) in sub-crates.
