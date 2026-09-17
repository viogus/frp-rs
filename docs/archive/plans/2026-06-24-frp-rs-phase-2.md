# frp-rs Phase 2: Operations & Advanced Features

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add operational tooling (Dashboard), wire up encryption/compression in the bridge, implement P2P proxy types (STCP/XTCP), and add alternative transports (KCP, QUIC).

**Architecture:** Each feature lives in its own module or extends an existing one. The Dashboard is a standalone HTTP server embedded in frps. Encryption/compression wraps the existing bridge. STCP/XTCP use a visitor/secret-key model separate from TCP proxying. KCP/QUIC add new transport protocol variants.

**Tech Stack:** Rust, tokio, axum (for Dashboard), aes-gcm + flate2 (already wired), kcp2 or similar (for KCP), quinn (for QUIC).

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `frp-server/src/dashboard.rs` | **New** — HTTP routes, API handlers, HTML templates | Create |
| `frp-server/src/service.rs` | Wire Dashboard listener when configured | Modify |
| `frp-core/Cargo.toml` | Add `axum`, `tower` deps | Modify |
| `Cargo.toml` | Add workspace deps | Modify |
| `frp-core/src/bridge.rs` | **New** — bridge layer for encryption/compression wrappers | Create |
| `frp-server/src/control.rs` | Use encrypted bridge when `use_encryption` is set | Modify |
| `frp-client/src/service.rs` | Use encrypted bridge when `use_encryption` is set | Modify |
| `frp-core/src/msg.rs` | Add `NewVisitorConn`, `NewVisitorConnResp` message types | Modify |
| `frp-server/src/visitor.rs` | **New** — STCP/XTCP visitor handling | Create |
| `frp-core/src/transport.rs` | Add KCP/QUIC transport variants | Modify |

---

## Plan Breakdown

This covers 5 independent subsystems. Each can be implemented as a separate project:

### Plan A: Dashboard / Web API

**Goal:** Embed a web-based monitoring dashboard in frps that shows active proxies, clients, and traffic stats, matching the Go frp dashboard functionality.

**Key components:**
1. **Dashboard HTTP server** — axum-based HTTP server with routes
2. **API endpoints** — GET /api/status, GET /api/proxies, GET /api/traffic
3. **HTML frontend** — Static HTML/JS served from embedded assets
4. **Status provider** — Shared state in `AppState` for collecting metrics

**Integration points:**
- `frp-server/src/dashboard.rs` — New module with axum router and handlers
- `frp-server/src/service.rs` — Start dashboard listener when `web_server.port > 0`
- `frp-server/src/control.rs` — Collect connection stats (bytes transferred, active connections)
- `AppState` — Add `dashboard_state: Arc<DashboardState>` with shared counters

**Dependencies needed:** `axum`, `tower-http`, `tokio-util`

**Files to modify:**
- Create: `frp-server/src/dashboard.rs`
- Modify: `frp-server/src/service.rs` (start dashboard server)
- Modify: `frp-server/src/control.rs` (collect traffic stats)
- Modify: `frp-core/src/lib.rs` (add dashboard state types)
- Modify: `Cargo.toml` (add axum, tower deps)

**REST API:**

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Server version, uptime, client count |
| `/api/proxies` | GET | List all proxies with status |
| `/api/clients` | GET | List connected clients |
| `/api/stats` | GET | Traffic stats (bytes in/out, active conns) |
| `/` | GET | HTML dashboard page |

---

### Plan B: Bridge Encryption / Compression

**Goal:** Wire the already-implemented `frp_core::encryption` module into the actual proxy data path so `use_encryption` and `use_compression` config flags take effect.

**Current state:** `frp_core::encryption` module exists with `encrypt()`, `decrypt()`, `compress()`, `decompress()` functions and tests. But they're not called anywhere in the bridge.

**Approach:** Create an encryption/compression stream wrapper that's inserted between the work connection and the `copy_bidirectional` call. The wrapper:
- On write: compresses → encrypts (or just encrypts, depending on flags)
- On read: decrypts → decompresses

**Key design:** The wrapper implements a simple length-prefixed frame protocol over the work connection:
```
[4-byte length (big-endian)] [encrypted payload of that length]
```
This ensures AES-GCM (which is not a stream cipher) works correctly with the TCP stream.

**Files to modify:**
- Create: `frp-core/src/bridge.rs` — `EncryptedStream` / `CompressedStream` wrappers
- Modify: `frp-server/src/control.rs` — wrap work_conn when proxy has use_encryption
- Modify: `frp-client/src/service.rs` — wrap work_conn when proxy has use_encryption

**Key functions:**
```rust
// frp-core/src/bridge.rs
pub struct EncryptedStream<S> { ... }
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for EncryptedStream<S> { ... }
impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for EncryptedStream<S> { ... }

pub struct CompressedStream<S> { ... } 
// Read: decompress   Write: compress
```

**Integration in `assign_work_to_proxy`:**
After sending `StartWorkConn`, the bridge function gets the work connection. Before calling `copy_bidirectional`, wrap the work connection:
```rust
let mut stream: Box<dyn AsyncRead + AsyncWrite + Unpin + Send> = 
    if use_encryption { Box::new(EncryptedStream::new(work, &key)) } 
    else { Box::new(work) };
```

**Dependencies needed:** Already present (`aes-gcm`, `flate2`, `sha2`)

---

### Plan C: STCP / XTCP / SUDP (P2P Proxy)

**Goal:** Implement secret TCP (STCP) and P2P TCP (XTCP) proxy types that enable direct connections between frpc instances without routing all traffic through the server.

**Architecture:**
- **STCP:** frp server stores a "visitor" proxy that connects to another client's "secret" proxy. The visitor connects to the server, and the server bridges it to the secret proxy's work connection. Authentication via `sk` (secret key) field.
- **XTCP:** Same as STCP but uses UDP hole punching for direct P2P connection after initial signaling through the server.

**Message types needed:**
- `NewVisitorConn` (type byte `b'v'`) — already defined in msg.rs
- `NewVisitorConnResp` (type byte `b'3'`) — already defined in msg.rs

**Files to modify:**
- Create: `frp-server/src/visitor.rs` — Visitor manager, STCP/XTCP routing
- Modify: `frp-server/src/control.rs` — Handle `NewVisitorConn` messages
- Modify: `frp-client/src/control.rs` — Add visitor registration
- Modify: `frp-core/src/msg.rs` — Add visitor message struct fields (if needed)
- Modify: `frp-server/src/service.rs` — Wire visitor module
- Modify: `frp-client/src/service.rs` — Handle STCP/XTCP proxy configs

**STCP flow:**
1. Client A registers a STCP proxy with `sk = "shared-secret"`
2. Client B registers a STCP visitor proxy with the same `sk`
3. Server matches the visitor to the secret proxy via `sk`
4. When a user connects to the visitor, server bridges to the secret proxy's work connection

---

### Plan D: KCP / QUIC Transport

**Goal:** Add KCP and QUIC as alternative transport protocols alongside TCP and WebSocket.

**KCP:** Fast reliable protocol over UDP. Use the `kcp` crate (or `kcp2`).
- New `TransportProtocol::Kcp` variant
- New `IoStream::Kcp(...)` variant
- `dial_server` and `accept` functions for KCP

**QUIC:** Use the `quinn` crate.
- New `TransportProtocol::Quic` variant (already exists as placeholder)
- QUIC listener/dial for control connections
- Much more complex than KCP (TLS 1.3 mandatory, connection migration, etc.)

**Files to modify:**
- `frp-core/src/transport.rs` — Add KcpStream, QuicStream variants, dial/accept
- `frp-core/Cargo.toml` — Add `kcp` / `quinn` deps
- `frp-server/src/service.rs` — Start KCP/QUIC listeners when configured

**Dependencies:** `kcp2` for KCP, `quinn` for QUIC, `rustls` (already present for QUIC's TLS)

**Note:** KCP is the simpler of the two and should be implemented first. QUIC requires significantly more infrastructure.

---

### Plan E: HTTPS VHost

**Goal:** Extend the existing HTTP VHost listener to also handle HTTPS connections by terminating TLS and then applying the same Host-based routing logic.

**Approach:** 
1. When `vhost_https_port > 0` and `tls_cert_file` is configured, start a separate TLS-wrapped TCP listener
2. Accept TLS connections, complete the TLS handshake
3. Read the HTTP request from the decrypted stream
4. Extract the Host header (same function as HTTP VHost)
5. Route to the proxy

**Files to modify:**
- Modify: `frp-server/src/vhost.rs` — Add `run_vhost_https_listener()` using the existing TLS acceptor
- Modify: `frp-server/src/service.rs` — Start HTTPS listener when configured
- Modify: `frp-core/src/transport.rs` — Reuse `build_tls_acceptor` (already done)

**Key insight:** The HTTPS listener is identical to the HTTP listener, except it wraps each accepted connection with TLS before reading the HTTP request. The routing logic is shared.

---

## Execution Priority

The subsystems are independent. Recommended order:

1. **Plan B (Bridge Encryption)** — Smallest effort, deps already present, highest security impact
2. **Plan A (Dashboard)** — Most visible feature, moderate effort
3. **Plan E (HTTPS VHost)** — Small extension of existing code
4. **Plan C (STCP/XTCP)** — Moderate effort, new proxy types
5. **Plan D (KCP/QUIC)** — Largest effort, new transport layer
