# Developer Guide

frp-rs is a native Rust implementation of [frp](https://github.com/fatedier/frp), a reverse proxy that exposes services on private networks to the public internet. This guide covers the codebase architecture and development workflow for contributors.

## 1. Workspace Overview

The project is a Cargo workspace with six crates arranged in a layered dependency graph:

```
frps ──────────────► frp-server ──────► frp-core
(server binary)      (server logic)      (shared library)
                       │                   ▲
                       └──► frp-vnet ──────┘
                            (virtual net)

frpc ──────────────► frp-client ──────► frp-core
(client binary)      (client logic)      (shared library)
                       │                   ▲
                       └──► frp-vnet ──────┘
                            (virtual net)
```

Dependencies flow **upward** through this diagram (binaries depend on logic crates, which depend on the shared library):

| Crate | Purpose | Key Modules |
|-------|---------|-------------|
| **frp-core** | Shared library with no internal workspace dependencies | Protocol framing (`protocol.rs`), message types (`msg.rs`), config parsing (`config/`), transport abstraction (`transport/`), auth (`auth.rs`), encryption (`encryption.rs`), bridge (`bridge.rs`), mux (`mux.rs`), QUIC (`quic.rs`), KCP (`kcp/`), STUN (`stun.rs`), V2 handshake (`v2_handshake.rs`), cipher streams (`cipher_stream.rs`) |
| **frp-server** | Server logic -- control handler, proxy registration, connection bridging | Service + accept loop (`service.rs`), control handler (`control/mod.rs`), proxy management (`proxy.rs`), bridge assignment (`control/bridge.rs`), proxy registration (`control/proxy_ops.rs`), NAT hole punching (`nathole/`), VHost routing (`vhost.rs`), dashboard + admin API (`dashboard.rs`), SSH gateway (`ssh_gateway.rs`), TCPMux (`tcpmux.rs`), config reload (SIGUSR1, `service.rs`), state (`state.rs`), handlers (`handlers.rs`) |
| **frp-client** | Client logic -- service lifecycle, control connection, local bridging | Client service (`service.rs`), work connections (`work_conn.rs`), visitor mode (`visitor.rs`), admin API (`admin.rs`), health checks (`health.rs`), client plugins (`plugin/`) |
| **frps** | Server binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_server::Service::run()` |
| **frpc** | Client binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_client::Service::run()` |

`frp-core` has no dependencies on other workspace crates -- it defines the wire protocol, message types, and transport primitives that both server and client use. The `frp-server` and `frp-client` crates contain the protocol logic but no `main()` functions; binaries live in `frps/` and `frpc/`.

**External documentation:** The project also maintains:
- [`docs/config.md`](config.md) -- full configuration reference
- [`docs/proxies.md`](proxies.md) -- proxy type guide (TCP, UDP, HTTP, HTTPS, STCP, XTCP, SUDP, TCPMux)
- [`docs/client-plugins.md`](client-plugins.md) -- client plugin reference (http_proxy, socks5, static_file, unix_domain_socket, http2https, https2http, https2https, http2http, tls2raw)
- [`docs/deployment.md`](deployment.md) -- deployment guide (systemd, Docker, VPS)
- [`docs/go-frp-compat-audit.md`](go-frp-compat-audit.md) -- full Go frp compatibility audit

## 2. Architecture Deep-Dive

### Server Connection Lifecycle

The server's accept loop (`frp-server/src/service.rs`, `Service::run()`) is a mixed-mode dispatcher that handles all supported transports on a single port:

```
                   ┌──────────┐
                   │ listener │  (TcpListener on bind_port)
                   └────┬─────┘
                        │ accept()
                        ▼
              ┌──────────────────┐
              │ detect_and_strip │  (MSG_PEEK-based: TLS 0x17/0x16,
              │ _magic()         │   WebSocket GET, or plain V1)
              └────────┬─────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
    ConnectionType  ConnectionType  ConnectionType
       ::Tls           ::WebSocket    ::Plain
         │                 │              │
         ▼                 ▼              ▼
    TLS handshake     WebSocket       read_msg_v1()
    (optional         upgrade            │
    yamux wrap)          │          dispatch by
         │            read_msg_v1()  type byte:
         │               │           ┌─────────────────┐
         │          dispatch by      │ Login            │──► handle_control()
         │          type byte:       │ NewWorkConn      │──► handle_work_conn_inner()
         │          (same as plain)  │ NewVisitorConn   │──► handle_visitor_conn_inner()
         │                           │ NatHoleVisitor   │──► handle_nat_hole_visitor()
         ▼                           └─────────────────┘
    (same dispatch)
```

Each accepted connection spawns a `tokio::spawn` task. `detect_and_strip_magic()` peeks at the first bytes to classify the connection type without consuming data -- bytes are replayed via `PreReadStream`. The function also detects V2 magic (`FRP\0\x02\r\n`) for QUIC streams.

**TLS connections** get additional processing:
- **TLS-only mode** (`tls_only: true`): non-TLS connections are rejected
- **SNI-based HTTPS proxy routing** happens only on the **`vhost_https_port` listener** (`vhost.rs`, `extract_sni_from_client_hello`): the server peeks at the ClientHello for the SNI hostname, looks up the VHostManager, and routes the raw TLS stream directly to the HTTPS proxy handler. The **main port does NOT sniff SNI** — round-13 Go parity: it reads only the 0x17/0x16 TLS marker to detect TLS vs plain (a wildcard https route must not hijack frpc TLS control logins)
- **TCPMux over TLS** (`tcp_mux: true`): after TLS handshake, the stream is wrapped in a yamux multiplexer. The first yamux stream is the control channel; subsequent streams carry work connections

**Additional listeners** are started alongside the main accept loop when their ports are configured:
- WebSocket listener (separate port, `websocket_port`)
- KCP listener (`kcp_bind_port`)
- QUIC listener (`quic_bind_port`, requires `tls_enable`)
- HTTP VHost listener (`vhost_http_port`)
- HTTPS VHost listener (`vhost_https_port`)
- TCPMux HTTP CONNECT listener (`tcpmux_httpconnect_port`)
- SSH tunnel gateway (`ssh_tunnel_gateway.bind_port`)
- Dashboard HTTP server (`web_server.port`)

Each listener follows the same pattern: accept connection, read one frame, dispatch by message type.

### InternalMsg Channel

The server's core is cross-task message passing via `InternalMsg` channels. The state is shared through `AppState`:

```
AppState
  ├── run_id_to_ctl_tx: DashMap<run_id, ControlTx>  // routes work conns to correct handler (lock-free reads)
  ├── proxy_manager: ProxyManager                     // global proxy registry
  ├── used_ports: HashSet<u16>                        // port allocation tracking
  ├── sk_index: HashMap<sk, proxy_name>              // STCP/XTCP secret-key to proxy lookup
  ├── vhost_manager: VhostManager                     // HTTP VHost routing
  ├── nat_hole: Arc<NatHoleCoordinator>              // XTCP NAT hole punch session mgmt
  ├── oidc_verifier: Option<Arc<OidcVerifier>>       // OIDC token verification
  └── oidc_subjects: HashMap<sub, proxy_name>        // OIDC subject to proxy routing
```

`ControlTx` contains an `mpsc::UnboundedSender<InternalMsg>` -- when a proxy listener accepts a user connection, it sends an `InternalMsg::ProxyUserConn` through this channel. The control handler's `select!` loop receives it and dispatches it to the right work connection.

**InternalMsg variants** and their flow:

```
ProxyUserConn      ──► work_pool empty? ──yes──► ReqWorkConn + push to pending_requests
  (proxy listener                     ──no───► pop work_conn, send StartWorkConn, bridge
   accepted user)

NewWorkConn        ──► pending_requests non-empty? ──yes──► pop request, bridge immediately
  (client sent new                      ──no───► push to work_pool (up to pool_cap)
   work connection)

NatHoleSidOnWorkConn ──► pending_nat_hole_sids? ──yes──► pop, write StartWorkConn+NatHoleSid on work_conn
  (XTCP visitor     ──► work_pool empty? ──yes──► push to pending_nat_hole_sids + ReqWorkConn
   arrived, notify                     ──no───► pop work_conn, write StartWorkConn+NatHoleSid
   provider)

UdpNeedsWorkConn   ──► work_pool empty? ──yes──► push to pending_udp + ReqWorkConn
  (UDP proxy needs                     ──no───► pop work_conn, assign_udp_work_conn
   work connection)

VisitorConn        ──► work_pool empty? ──yes──► ReqWorkConn + push to pending_requests
  (STCP visitor                       ──no───► pop work_conn, send StartWorkConn, bridge
   arrived)

Shutdown           ──► old control handler stops (superseded by new connection with same run_id)
```

### Control Handler select! Loop

The control handler (`frp-server/src/control/mod.rs`, `handle_control()`) is the most complex file. After login, it enters a `tokio::select!` loop:

```rust
tokio::select! {
    internal = internal_rx.recv() => {
        // Process InternalMsg variants:
        // - NewWorkConn: defer to pending_nat_hole_sids → pending_udp → pending_requests → work_pool
        // - VisitorConn: pop work_pool or queue
        // - ProxyUserConn: pop work_pool or ReqWorkConn
        // - Shutdown: break loop
        // - UdpNeedsWorkConn: pop work_pool or queue
        // - NatHoleSidOnWorkConn: deliver sid or queue
        // - WriteNatHoleSid/WriteNatHoleResp/WriteNatHoleReport: forwarded to visitor via control
    }

    msg = read_ctl_msg(&mut reader, v2) => {
        // Process inbound client messages:
        // - NewProxy: register proxy, start listeners
        // - CloseProxy: unregister proxy, stop listeners
        // - Ping: update last_ping, send Pong
        // - NewWorkConn: same as internal NewWorkConn (client proactively sent)
        // - UDPPacket: route to correct UDP socket
        // - NatHoleClient: NAT analysis → NatHoleResp to both sides
        // - NatHoleReport: session complete
        // - VisitorConn: STCP visitor on control channel (Go frp compat)
        // - NatHoleVisitor: XTCP visitor on control channel (Go frp compat)
    }
}
```

The loop is deliberately **FAIR** — no `biased` keyword: an always-ready
internal queue must not starve control reads (heartbeat pings, Shutdown).
Internal messages represent real user traffic, so they get priority via the
queue discipline itself; fairness is pinned by a regression test in
`control/mod.rs` (asserts no `biased;` in the loop and bounded control p99
under internal pressure).

### Work Connection Pooling

The server maintains a work connection pool per client:

- **`pool_cap`**: `login.pool_count + 10` (extra 10 from `WORK_POOL_EXTRA`)
- **`work_pool`**: `VecDeque<IoStream>` -- idle work connections
- **`pending_requests`**: `VecDeque<PendingRequest>` -- user connections waiting for a work conn

When a proxy listener accepts a user:
1. Pop from `work_pool` if non-empty -- send `StartWorkConn` + bridge immediately
2. If `work_pool` is empty, send `ReqWorkConn` to client + push to `pending_requests` (timeout: 10s)

When a new work connection arrives:
1. Pop from `pending_requests` if non-empty -- bridge immediately
2. If no pending requests, push to `work_pool` (if below `pool_cap`)

**Bridging** (`control/bridge.rs`, `assign_work_to_proxy`): after sending `StartWorkConn` with proxy metadata (encryption flag, compression flag), the server bridges the user connection to the work connection using either `tokio::io::copy_bidirectional_with_sizes` with the 32 KiB `BUFFER_SIZE` (plain, overridable via `FRP_BRIDGE_BUF_KB`) or `bridge::bridge_encrypted` (AES-128-CFB + Snappy, streaming — a single 16-byte IV then continuous ciphertext, no per-frame length prefix).

### NAT Hole Punching (XTCP)

XTCP enables direct peer-to-peer connections between two frpc clients behind NAT. The server coordinates the control plane (NAT classification, 5-mode behavior recommendation, session management) but never relays XTCP data and sends no probe packets — provider and visitor each do their own STUN.

```
Visitor                Server                    Provider
   │                      │                          │
   │──NatHoleVisitor─────►│                          │
   │                      │─NatHoleSidOnWorkConn────►│  (via internal channel)
   │                      │  (StartWorkConn+NHSid    │
   │                      │   on work connection)    │
   │                      │                          │──STUN────► STUN servers
   │                      │                          │◄────────── (discovers external addr)
   │                      │◄──NatHoleClient─────────│  (reports STUN results)
   │                      │                          │
   │                      │──NAT analysis───────────│  (classify + analyzer)
   │                      │                          │
   │◄──NatHoleResp───────│                          │
   │                      │──NatHoleResp────────────►│
   │                      │                          │
   │◄══ MakeHole UDP probing ══►│  (5-mode DetectBehavior: sender probes
   │   (sender/receiver roles,   │   assisted+candidate addrs, TTL, port
   │    candidate/random ports)  │   scanning; winner socket selected)
   │                      │                          │
   │◄══ KCP+yamux P2P data plane ═►│  (runs on the winning socket)
   │   (encrypted bridge to local) │
   │                      │                          │
   │                      │◄──NatHoleReport─────────│  (session complete)
```

Two paths for visitor connections:

1. **Fresh TCP connection** (primary): visitor sends `NatHoleVisitor` on a new TCP connection. Server creates session, sends `NatHoleSidOnWorkConn` internal msg. Provider control handler writes `StartWorkConn`+`NatHoleSid` on work conn. Provider does STUN, sends `NatHoleClient` on control, server runs NAT analysis, sends `NatHoleResp` to both sides.

2. **Control connection** (Go frp compat): Go frpc v0.71.0 sends `NatHoleVisitor` on its existing control channel. Server creates session with `create_session_with_ctl`, spawns task waiting for provider's `NatHoleClient` on control, runs NAT analysis, and sends `NatHoleResp` to both sides.

**NAT analysis** (`frp-server/src/nathole/analysis.rs`): 5-mode behavior table with score-based `Analyzer`. Each mode tests how the NAT behaves for different address/port combinations. The analyzer learns from success feedback -- successful hole punches increase the score for the modes that predicted the correct behavior.

**STCP fallback**: if hole punch fails (e.g., both sides behind symmetric NAT), the visitor falls back to an STCP proxy specified by the `fallback_to` config field.

**XTCP P2P data plane**: after the hole punch, the P2P stream runs on the
socket that received the peer's detect reply (Go `result.lConn` semantics —
only that socket has a working NAT mapping). Two transports are supported,
selected by the `protocol` field (visitor decides; empty protocol is
normalized to `"quic"` — Go `EmptyOr` parity; **`"quic"` is the default**):
- **QUIC** (`protocol="quic"`, default): the punched socket is handed
  directly to quinn (`xtcp_p2p_connect_quic` — no yamux, QUIC multiplexes
  streams itself), self-signed TLS + InsecureSkipVerify, ALPN `frp`. The
  visitor is the QUIC client, the provider the QUIC server. Requires the
  `quic` feature (default ON). Go visitors with `protocol="quic"`
  interoperate: Go frp v0.71.0 sends `"ip:port"` as the QUIC SNI, which
  upstream rustls 0.23 rejects — frp-rs vendors rustls (0.23.43 at
  `vendor/rustls`) with a server-side patch that treats an invalid SNI as
  "no SNI" (see `docs/superpowers/notes/2026-08-04-xtcp-quic-sni-compat.md`
  §6; drop the patch when the workspace moves past rustls 0.23).
- **KCP + yamux** (`protocol="kcp"`): the punched UDP socket runs KCP
  (`XtcpP2pStream`) with yamux on top.

The persistent XTCP tunnel session (`frp-core/src/xtcp_session.rs`,
round-11 keepTunnelOpenWorker parity): one hole-punched QUIC/yamux session
per proxy is reused across user connections instead of re-punching per
connection; the visitor re-signals `startTunnel` on every error path, and
the budget clamps to `min(20s, fallbackTimeoutMs)`.

**XTCP P2P encryption**: after hole punch, the P2P stream is bridged to the
local service with `bridge_encrypted` when `use_encryption=true` and `sk` is
non-empty. The key is derived via `PBKDF2-SHA1(sk, salt="frp", iter=64,
keylen=16)` -- using the proxy's SecretKey (not the auth token). Probe
packets (NatHoleSid) use the same derivation; without a secret key, Rust↔Rust
probes use the `"frp"` magic. Both sides derive the same key from the shared
SecretKey.

**Module structure** (`frp-server/src/nathole/`):
- `mod.rs` -- module root, `NAT_HOLE_TIMEOUT = 10s`
- `controller.rs` -- session management, provider registration, `build_nat_hole_response()`
- `classify.rs` -- NAT feature classification (EasyNAT vs HardNAT, behavior detection)
- `analysis.rs` -- 5-mode behavior table, score-based `Analyzer` with success feedback

### Wire Protocol

**V1** (fully implemented in `frp-core/src/protocol.rs`):

```
┌───────────┬────────────────────────────────┬──────────────────────┐
│ 1 byte    │ 8 bytes (big-endian)           │ N bytes (max 10 KiB) │
│ type      │ payload length (i64)           │ UTF-8 JSON           │
└───────────┴────────────────────────────────┴──────────────────────┘
```

9-byte header followed by JSON payload. `read_v1_frame()` reads the header, validates length <= 10 KiB (10_240, matching Go frp), then reads the payload. `deserialize_v1()` dispatches by type byte to the correct `FrpMessage` variant.

Message type bytes (from `frp-core/src/msg.rs`):

| Byte | Constant | Message |
|------|----------|---------|
| `o` | `TYPE_LOGIN` | Login |
| `1` | `TYPE_LOGIN_RESP` | LoginResp |
| `p` | `TYPE_NEW_PROXY` | NewProxy |
| `2` | `TYPE_NEW_PROXY_RESP` | NewProxyResp |
| `c` | `TYPE_CLOSE_PROXY` | CloseProxy |
| `w` | `TYPE_NEW_WORK_CONN` | NewWorkConn |
| `r` | `TYPE_REQ_WORK_CONN` | ReqWorkConn |
| `s` | `TYPE_START_WORK_CONN` | StartWorkConn |
| `v` | `TYPE_NEW_VISITOR_CONN` | NewVisitorConn |
| `3` | `TYPE_NEW_VISITOR_CONN_RESP` | NewVisitorConnResp |
| `h` | `TYPE_PING` | Ping |
| `4` | `TYPE_PONG` | Pong |
| `u` | `TYPE_UDP_PACKET` | UDPPacket |
| `i` | `TYPE_NAT_HOLE_VISITOR` | NatHoleVisitor |
| `n` | `TYPE_NAT_HOLE_CLIENT` | NatHoleClient |
| `m` | `TYPE_NAT_HOLE_RESP` | NatHoleResp |
| `5` | `TYPE_NAT_HOLE_SID` | NatHoleSid |
| `6` | `TYPE_NAT_HOLE_REPORT` | NatHoleReport |
| `7` | `TYPE_CLOSE_PROXY_RESP` | CloseProxyResp |
| `8` | `TYPE_ERROR` | Error |

The `FrpMessage` enum is `#[serde(untagged)]` -- serde matches the first variant whose fields intersect the JSON. In wire deserialization this is not an issue because the type byte is matched first via `deserialize_v1()`, which dispatches to the correct struct before deserialization.

**V2** (fully implemented in `frp-core/src/protocol.rs`):

V2 uses 7-byte magic `FRP\0\x02\r\n` + different framing with numeric type IDs (u16). Full AEAD encryption with capability negotiation via `frp-core/src/v2_handshake.rs` and `frp-core/src/crypto.rs` (AES-256-GCM or ChaCha20-Poly1305, HKDF-SHA256 key derivation). V2 frame read/write (`read_v2_frame_raw`/`write_v2_frame_raw`), message dispatch (`read_msg_v2`/`write_msg_v2`), and `deserialize_v2()` all fully operational. V2 compat tests run against the Go frp v0.71.0 pre-built binary.

Encryption in the control handler is protocol-aware: V1 uses AES-128-CFB (`CipherStream`), V2 with AEAD keys wraps the stream in `AeadStream` after LoginResp.

### Encryption

**Control connection:** AES-128-CFB. Key derived via `PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16)`. Implemented in `frp-core/src/encryption.rs`.

**Encrypted bridge (data plane):** AES-128-CFB streaming with Snappy compression (compress first, then encrypt). Framing: one random 16-byte IV written before the first ciphertext block, then a continuous CFB stream (no per-frame length prefix). Implemented in `frp-core/src/bridge.rs`.

**V2 control:** AEAD (AES-256-GCM or ChaCha20-Poly1305). Keys derived via HKDF-SHA256 from the transcript hash. Implemented in `frp-core/src/crypto.rs`.

**Important:** Go frp golib source says PBKDF2 salt `"crypto"` but the pre-built binary uses salt `"frp"` (verified against the v0.70.1 and v0.71.0 binaries). This codebase uses `"frp"` for binary compatibility.

### Authentication

Auth uses `MD5(token + timestamp)` -> hex string. Matches Go frp v0.71.0 behavior (Go frp switched from HMAC-SHA256 to MD5 in commit `78f9394`). See `frp-core/src/auth.rs`.

OIDC authentication is also supported when the `oidc` feature is enabled. The server verifies JWTs against an OIDC provider and maps subjects to proxy names.

### Transport Abstraction

`IoStream` (`frp-core/src/transport/`) is a type-erased newtype over a
boxed trait object — the 11-variant enum is gone:

```rust
pub struct IoStream(Box<dyn Transport>);
```

Each transport implements the `Transport` trait (`AsyncRead + AsyncWrite +
Unpin + Send + 'static` plus the consuming methods) in its own file under
`frp-core/src/transport/`: `tcp.rs` (`TcpStream`), `tls.rs`
(`TlsTransport`), `kcp.rs` (`KcpStream`), `quic.rs` (`QuicStream`),
`websocket.rs` (`WsByteStream`, manual RFC 6455 framing — tungstenite was
removed 2026-08-09), `yamux.rs` (`YamuxStream`), `cipher.rs`
(`CipherStream<S>`), `aead.rs` (`AeadStream`), `ssh_channel.rs`
(`SshChannelTransport`), `pre_read.rs` (`PreReadTransport`),
`buffered_read.rs` (`BufferedReadTransport`). IoStream's constructors are
named after the old variants (`IoStream::Tcp(stream)`, …) so construction
sites read identically.

`into_split()` returns the boxed `(BoxedReadHalf, BoxedWriteHalf)` halves
(the old static `ReadHalf`/`WriteHalf` enums are deleted; QUIC uses quinn's
native halves). The `WebSocket` wrapper exposes binary messages as
`AsyncRead`/`AsyncWrite` so the V1 protocol operates over WebSocket
without changes. `try_tcp`/`try_tcp_mut` downcast to the raw `TcpStream`
for the Linux `splice(2)` fast path; `is_yamux_wrappable` is false for QUIC
only.

**Config normalization** (`frp-core/src/config/`): full Go to Rust config compatibility layer. TOML values are converted via `toml_to_json()` to `serde_json::Value`, then deserialized into config structs. Legacy fields like `[common]`, `auth_method`, `log_file`, `web_server_*` are normalized.

### Gotchas

- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README example shows `false`
- `#[serde(untagged)]` on `FrpMessage` enum -- ordering matters for serde matching, but V1 protocol dispatches by type byte first, so it is not involved in wire deserialization
- `ProxyRuntimeInfo` must include `sk: String` field -- XTCP P2P encryption derives its AES-128 key from the proxy's SecretKey. Adding new fields to `ProxyRuntimeInfo` requires updating all construction sites
- **No new dependencies without explicit justification** -- see the dependency policy in CLAUDE.md for the pre-approved tech stack and banned crates

## 3. Adding a New Proxy Type

This section walks through adding a new proxy type called `myproxy`:

### Step 1: Config Parsing (if needed)

If the new proxy type requires new config fields, add them to the proxy config struct in `frp-core/src/config/`. Existing proxy config fields are shared across all proxy types in `ProxyConfig` -- if your proxy type reuses those fields, no config changes are needed.

### Step 2: Register in ProxyManager

In `frp-server/src/control/proxy_ops.rs`, the `handle_new_proxy` function registers proxies in `ProxyManager`. Most proxy types reuse the existing registration logic. If your proxy type needs special registration:

- **Port allocation**: the function already handles port allocation via `allocate_port_multi()`. SUDP proxies get special shared-port handling.
- **sk_index**: STCP/XTCP proxies register in `sk_index` for secret-key routing. Add your proxy type here if it uses sk-based routing.
- **VHost routing**: HTTP/HTTPS proxies register in `VhostManager`. Add your proxy type here if it uses domain-based routing.
- **TcpMux routing**: TCPMux proxies register in `TcpMuxManager`.

### Step 3: Add Listener Setup

In `frp-server/src/control/proxy_ops.rs`, after proxy registration, the function spawns a listener task. The existing `listen_and_proxy()` helper starts TCP listeners for tcp/http/https/stcp/tcpmux proxy types. UDP proxies use `listen_and_proxy_udp()`.

For a new proxy type that needs a different listener pattern:
1. Add a branch in the proxy type match after registration
2. Spawn a `tokio::spawn` task that binds a `TcpListener` on the allocated port
3. On accept, send `InternalMsg::ProxyUserConn` with the user connection and pre-read bytes

Example pattern (simplified from existing code):

```rust
let listener = TcpListener::bind(&addr).await?;
let internal_tx_clone = internal_tx.clone();
tokio::spawn(async move {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = internal_tx_clone.send(InternalMsg::ProxyUserConn {
                    proxy_name: name.clone(),
                    user_conn: IoStream::Tcp(stream),
                    pre_read: vec![],
                });
            }
            Err(_) => break,
        }
    }
});
```

### Step 4: Implement Bridging Logic

The bridging is handled automatically by the control handler's `InternalMsg::ProxyUserConn` path -- it pops a work connection from the pool, sends `StartWorkConn`, and bridges. No special bridging code is needed for basic TCP-like proxy types.

If your proxy type needs special bridging (e.g., HTTP host header rewriting, protocol-specific framing), add the logic in `frp-server/src/control/bridge.rs`. The existing `assign_work_to_proxy` function handles plain vs encrypted bridging and pre-read byte forwarding.

For the client side, proxy type handling is in `frp-client/src/service.rs` and `frp-client/src/work_conn.rs` -- the client reads `StartWorkConn` to know which local service to connect to.

## 4. Building and Feature Flags

### Quick Reference

```bash
cargo build                  # Debug build (all crates)
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
```

### Binary Variants

Four size tiers via feature flags. QUIC and SSH are default; dashboard is opt-in:

```bash
# Default (SSH + QUIC included; no dashboard; keeps TLS, KCP, WS, compression)
cargo build --release -p frps -p frpc
# → frps (~5.3MB), frpc (~4.5MB)

# Full (all features; dashboard the main opt-in on top of default)
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"
# → frps (~5.7MB), frpc (~4.5MB)

# Tiny (no QUIC/KCP/WS/SSH/OIDC/dashboard/compression; keeps TLS)
cargo build --release -p frps -p frpc --no-default-features --features tiny
# → frps-tiny (~3.3MB), frpc-tiny (~3.2MB)

# Micro (core only: no TLS, compression, chacha20, HTTP proxy, tcp-mux)
cargo build --release -p frps -p frpc --no-default-features --features micro
# → frps-micro (~2.3MB), frpc-micro (~2.2MB)
```

> Sizes measured 2026-08-08 (macOS arm64) with the declared release profile
> (fat-LTO, opt-level=z, strip=symbols, panic=abort). The local
> `.cargo/config.toml` override was removed 2026-08-09 — local release
> builds use the declared profile. Only CI workflows write
> `lto=false opt-level=2` on runners (build speed) and come out ~70% larger
> (measured 2026-08-09: 9.1MB vs 5.3MB).

The binaries are named `frps`/`frpc` (default/full), `frps-tiny`/`frpc-tiny`, and `frps-micro`/`frpc-micro` respectively.

### Feature Flags

| Feature | Crate | What it removes |
|---------|-------|-----------------|
| `quic` | frp-core | QUIC transport (quinn) — **default ON** (was opt-in) |
| `kcp` | frp-core | KCP transport (in-tree, kcp-go v5.6.13 aligned) |
| `websocket` | frp-core/server | WebSocket transport (manual RFC 6455 framing, no tungstenite since 2026-08-09) |
| `oidc` | frp-core | OIDC auth (jsonwebtoken, hyper via `http-client`) |
| `ssh` | frp-server | SSH gateway (russh, rand 0.10) |
| `dashboard` | frp-server | Metrics/status API (prometheus, axum) |
| `admin` | frp-client | frpc admin API (axum) — opt-in since 2026-08-09 |
| `http2http` | frp-client | HTTP/2 (h2) support for the https2http/https2https plugins; implies `tls` |
| `tls` | frp-core/server/client | TLS encryption (rustls — **vendored** at `vendor/rustls` 0.23.43 with an SNI patch, see below) |
| `compression` | frp-core | Snappy bridge compression (snap) |
| `chacha20` | frp-core | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | frp-server | HTTP proxy plugin (hyper/http-client) — server-side opt-in |
| `tcp-mux` | frp-core/server/client | yamux stream multiplexing (**vendored** at `vendor/yamux`, see below) |
| `vnet` | frp-core/server/client | L3 VPN / TUN device routing — opt-in |
| `admin-auth` | frp-core | shared admin auth helpers (token/basic) |
| `mimalloc` | frps/frpc | mimalloc global allocator — opt-in |
| `mem-profile` | frp-core/server/client | CountingAlloc + MEMPROFILE emitter (dev only; **exclusive with `mimalloc`**) |
| `profiling` | frp-core | profiling gate (dev only) |
| `otel` | frp-core/server/client | OpenTelemetry tracing + OTLP export — opt-in |
| `debug-logs` | frp-core | debug/trace logging (dev only) |

frps default ON: `websocket`, `kcp`, `quic`, `oidc`, `tls`, `http-proxy`, `compression`, `chacha20`, `tcp-mux`, `ssh`. frpc default ON: `websocket`, `kcp`, `quic`, `oidc`, `tls`, `compression`, `chacha20`, `tcp-mux`, `http2http` (**no `admin`** since 2026-08-09). Opt-in: `admin`, `dashboard`, `vnet`, `otel`, `mimalloc`, dev-only flags (`debug-logs`, `mem-profile`, `profiling`). `quic` implies `tls`. `oidc` implies `http-client` (hyper). `ssh` implies `rand`. `mem-profile` is mutually exclusive with `mimalloc` (cfg-exclusive global-allocator guards).

### Release Profile

```toml
# Cargo.toml
[profile.release]
opt-level = "z"       # Optimize for size
lto = "fat"           # Link-time optimization across all crates
codegen-units = 1     # Single codegen unit for better optimization
strip = "symbols"     # Strip debug symbols
panic = "abort"       # Abort on panic (smaller binary, no unwind tables)
```

After `cargo build --release`, further compress with UPX:

```bash
upx --best --lzma target/release/frps target/release/frpc
```

## 5. Debugging

### RUST_LOG Levels

The project uses `tracing` for structured logging. Available levels: `error`, `warn`, `info`, `debug`, `trace`.

```bash
# Debug logging for everything
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Target-specific logging
RUST_LOG=frp_server::control=debug cargo run --bin frps -- -c frps.toml

# Trace-level for wire protocol inspection
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml

# Multiple targets
RUST_LOG=frp_server=debug,frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

Key tracing targets:
- `frp_core::protocol` -- V1 frame writes (`trace` level includes full JSON payloads)
- `frp_server::service` -- connection accept, TLS handshake, dispatch
- `frp_server::control` -- control handler lifecycle, internal message routing, heartbeat
- `frp_server::control::bridge` -- work connection bridging
- `frp_core::transport` -- connection type detection, magic byte stripping
- `frp_server::nathole` -- NAT hole punch session lifecycle
- `frp_client::service` -- client lifecycle, proxy registration
- `frp_client::work_conn` -- work connection management

### Inspecting Wire Protocol

Enable trace-level logging for `frp_core::protocol` to see every frame sent and received:

```bash
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

This outputs the type byte, payload length, and full JSON content for each V1 frame. For hex dumps of the raw bytes, use an external tool like `tcpdump` or `wireshark`:

```bash
# Capture frp traffic on loopback
sudo tcpdump -i lo -A -s 0 port 7000

# Capture with hex dump
sudo tcpdump -i lo -X -s 0 port 7000
```

### Common Issues

**"Connection reset by peer" on startup:**
- Check that `bind_port` is not already in use
- Verify the server and client `token` match
- Check that `server_addr` is reachable from the client

**Proxy connections time out:**
- Check `heartbeat_timeout` -- client must ping within this interval
- Check `pool_count` -- if too low, proxy connections queue and expire after 10s
- Verify firewall allows traffic on proxy ports

**Enrypted bridge corruption:**
- Both sides must agree on `use_encryption` and `use_compression`
- The encryption key derives from the auth token -- mismatched tokens = corrupted bridge

**TLS handshake failures:**
- TLS requires valid cert/key files (`tls_cert_file`, `tls_key_file`)
- When `tls_only` is true, non-TLS connections are rejected
- WebSocket over TLS requires the client to connect with `wss://` and `transport_protocol = "wss"`

**XTCP hole punch failures:**
- Both provider and visitor need public internet access for STUN
- Symmetric NAT on both sides usually prevents hole punching -- STCP fallback is needed
- Check that `sk` is set and identical on both provider and visitor proxies

## 6. Testing

### Unit Tests

Unit tests live inline in `#[cfg(test)] mod tests` blocks within source files. Integration tests live in the `frp-server/tests/` and `frp-client/tests/` directories (see "Writing New Tests" below).

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p frp-core
cargo test -p frp-server
cargo test -p frp-client

# Run a specific test by name
cargo test -p frp-core -- protocol::tests

# Run with output (show println! and tracing)
cargo test -- --nocapture

# Run ignored tests (e.g., tests requiring network access)
cargo test -- --ignored
```

### Cross-Compatibility Tests

The compat test suite verifies Go frp <-> Rust frp interop across all proxy types and transport protocols:

```bash
# Full suite (86 run_test scenarios, 2 of which are gated on Go frp V2)
bash scripts/compat-test.sh --verbose

# Filter by proxy type and direction
bash scripts/compat-test.sh tcp g2r     # TCP proxy, Go client -> Rust server
bash scripts/compat-test.sh xtcp        # All XTCP tests
bash scripts/compat-test.sh transport   # Transport protocol tests only

# Filter by direction
bash scripts/compat-test.sh g2r         # All Go->Rust tests
bash scripts/compat-test.sh r2g         # All Rust->Go tests
```

The compat tests require Go frp binaries. Download them first:

```bash
bash scripts/download-go-frp.sh
```

This downloads Go frp v0.71.0 binaries to `scripts/go-frp/`. The CI gate is `.github/workflows/compat.yml`.

### XTCP CI Tests

XTCP tests require public internet (for STUN) and run on a VPS:

```bash
# Setup VPS (one-time)
bash scripts/vps-setup.sh

# Run XTCP tests on VPS
bash scripts/remote-frps.sh xtcp
```

XTCP CI uses sharded matrix jobs (`.github/workflows/xtcp-compat.yml`) with per-shard directories for isolation. 17 tests covering the 2x2 implementation matrix (Go/Rust server × Go/Rust client) plus QUIC-data-plane and encrypted variants.

### Writing New Tests

Follow these conventions:

1. **Inline tests**: add to the relevant source file's `#[cfg(test)] mod tests`
2. **Integration tests**: add to `frp-server/tests/` or `frp-client/tests/`
3. **Use `test_utils`**: each crate may provide test helpers for spawning servers/clients
4. **Avoid port conflicts**: use port `0` for auto-allocation or pick unique ports
5. **Clean up**: ensure spawned tasks/processes are killed on test completion

### Benchmarks

Criterion micro-benchmarks in `frp-core/benches/crypto_bridge.rs` (8 groups) and `frp-server/benches/nathole.rs` (2 groups):

```bash
# Run all benchmarks (slow — runs each bench many times)
cargo bench -p frp-core
cargo bench -p frp-server

# Quick compile-time check (used in CI)
cargo bench --workspace --no-run

# Run specific groups
cargo bench -p frp-core -- protocol_all_types
cargo bench -p frp-core -- bridge
cargo bench -p frp-server -- nat_analysis
```

CI gate: `cargo bench --workspace --no-run` in `.github/workflows/ci.yml` ensures benchmarks don't bit-rot.

### Stress Tests

Long-running load test (`scripts/stress-test.sh`) that runs frps + frpc under connection churn:

```bash
bash scripts/stress-test.sh
```

Monitors memory, connection counts, and throughput. Runs weekly in CI via `.github/workflows/stress-test.yml`. The `scripts/frp-stress/` crate contains the load generator (not part of the main workspace).

### Property & Fuzz Tests

Proptest-based tests verify correctness under adversarial inputs:
- **Config normalization** (`frp-core/src/config/`): 9 proptest! blocks — idempotency, flat↔nested equivalence, camelCase→snake_case
- **Protocol fuzzing** (`frp-core/src/protocol.rs`): 6 fuzz tests + 35 regular tests — all 256 V1 type bytes × arbitrary payloads, V2 arbitrary type IDs, truncated frames, magic detection

## 7. Release Process

### Version Bumping

**frp-rs 自身版本号严格对齐 Go frp 的发布号** (mandatory): the version
equals the current compat target Go frp release — currently **0.71.0** — and
bumps only when Go frp releases a new number. Update the version in ALL
sync locations:

```bash
# All crates share the same version
# Update in:
#   Cargo.toml (workspace)
#   frp-core/Cargo.toml
#   frp-server/Cargo.toml
#   frp-client/Cargo.toml
#   frps/Cargo.toml
#   frpc/Cargo.toml
#   frp-core/src/lib.rs  (VERSION constant)
#   scripts/download-frp-rs.sh  (default version)
#   README.md
```

Exception: `frp-vnet` stays independent at `0.1.0`.

### Building Release Binaries

The release workflow (`.github/workflows/release.yml`) cross-compiles for 13 targets:

- **Linux**: x86_64, aarch64, armv7, arm, i686, riscv64gc — glibc builds for all six, musl only for x86_64/aarch64/armv7 (built with `cargo zigbuild`)
- **macOS**: x86_64, aarch64 -- native builds
- **Windows**: x86_64, aarch64 -- native builds

Each target produces three variants: full, tiny, and micro.

To build locally for your platform:

```bash
# Full
cargo build --release -p frps -p frpc

# Tiny
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro
cargo build --release -p frps -p frpc --no-default-features --features micro
```

### UPX Compression

After building, compress with UPX for additional size reduction (optional):

```bash
upx --best --lzma target/release/frps target/release/frpc
```

UPX is not required -- the release profile already produces compact binaries via `opt-level=z`, `lto=fat`, and `strip=symbols`.

### Docker Image Publication

The Docker image is built from source in a multi-stage build (`docker/Dockerfile.source`):

```bash
# Build for frps (from repo root)
docker build --build-arg FRP_COMPONENT=frps -t frps:latest -f docker/Dockerfile.source .

# Build for frpc
docker build --build-arg FRP_COMPONENT=frpc -t frpc:latest -f docker/Dockerfile.source .
```

Also available: `frps-tiny`, `frpc-tiny`, `frps-micro`, `frpc-micro` variants. The release workflow (`.github/workflows/docker.yml`) builds and pushes multi-arch images for all 6 variants. The image uses a `scratch` base (~2 MB total) with a musl-static binary.

### Triggering a Release

Releases are triggered by pushing a version tag or manually via workflow dispatch:

```bash
# Tag and push (triggers .github/workflows/release.yml)
git tag v0.71.0
git push origin v0.71.0
```

The release workflow:
1. Builds all 13 targets (9 Linux via cargo-zigbuild + 2 macOS + 2 Windows)
2. Packages each as `.tar.gz` (Linux/macOS) or `.zip` (Windows)
3. Creates a GitHub Release with auto-generated notes
4. Uploads all artifacts

The Docker workflow runs separately (`.github/workflows/docker.yml`) and can be triggered manually or on release.

## Dependency Policy

**No new dependencies without explicit justification.** Every new crate must document:

1. **Why it is needed** -- what problem it solves that existing deps cannot
2. **Why the alternative was rejected** -- why an existing dep cannot be used
3. **Binary size impact** -- approximate cost to frps/frpc release binary

**Pre-approved tech stack** (use these unless strong reason to deviate):

| Domain | Crate |
|--------|-------|
| Async runtime | `tokio` |
| Serialization | `serde` + `serde_json` |
| Config | `toml` 0.8 |
| Crypto (general) | `ring` 0.17 |
| Crypto (Go compat) | `aes` + `cfb-mode`, `pbkdf2` + `sha1`, `md-5` |
| Crypto (V2 XChaCha20) | `chacha20poly1305` |
| TLS | `rustls` + `tokio-rustls` + `rustls-platform-verifier` — **vendored** at `vendor/rustls` 0.23.43 via `[patch.crates-io]` with a one-line SNI patch (`ServerNamePayload::Invalid` → treat as no-SNI) for Go XTCP QUIC visitor compat; delete the vendored copy when upgrading to rustls ≥0.24 (native `invalid_sni_policy`) |
| SSH | `russh` (ring backend, NOT aws-lc-rs) |
| HTTP client | `hyper` + `hyper-rustls` + `hyper-util` (inline `frp_core::http_client`; OIDC/proxy/plugin — no reqwest) |
| HTTP server | `axum` |
| WebSocket | manual RFC 6455 framing (in-tree `websocket.rs`; `tokio-tungstenite` removed 2026-08-09) |
| Encoding | inline `frp_core::base64` (encode/decode) + `frp_core::hex_encode` |
| Compression | `snap` |
| QUIC | `quinn` |
| TcpMux | `yamux` 0.14 — **vendored** at `vendor/yamux` via `[patch.crates-io]` with four patches (per-stream RST on stream-cap hit, lost-wakeup `sender_wu` fix, receive-window cap, body-buffer pools) |
| OIDC/JWT | `jsonwebtoken` |
| Logging | `tracing` + `tracing-subscriber` + `tracing-appender` |
| Error handling | `anyhow` + `thiserror` |
| Random | `rand` 0.8 |
| Misc | `bytes`, `uuid`, `futures-util`, `tokio-util`, `socket2`, `prometheus` |

**Banned** (do not reintroduce without approval): `aws-lc-sys`, `aws-lc-rs`, `hmac`, `base64`, `sha2`, `aes-gcm`, `hkdf`, `hickory-resolver`, `lazy_static`, `data-encoding`, `hex`, `tokio-tungstenite`. Note: `libc` is an **active** direct dependency (frp-core Linux `splice(2)`, frp-vnet TUN ioctl), not banned. "Banned" means no direct dependency — several still exist transitively via the SSH feature chain (russh → ssh-key).

Workspace dependencies use `resolver = "2"` with `[workspace.dependencies]` for all crates. To add a new dependency: add to the workspace level, then reference by name (no version) in sub-crates.
