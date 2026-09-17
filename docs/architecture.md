# frp-rs Architecture

The single canonical "how frp-rs works" document. For the user-facing guide see
the [README](../README.md); for the contributor workflow (debugging, testing,
releasing) see [developing.md](developing.md); for the rules an agent must not
break see [CLAUDE.md](../CLAUDE.md).

> Consolidated from three documents that each described the same subsystems
> (`architecture.md`, `technical-details.md`, and §2 of `developing.md`).
> `technical-details.md` is now a redirect stub.

---

## Overview

```
                    ┌──────────────────┐
                    │  Public Network   │
                    └──────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │         frps (server)        │
              │  bind_port: 7000            │
              │  proxy ports: 6000-9999     │
              └──────────────┬──────────────┘
                             │
              ┌──────────────┴──────────────┐
              │         frpc (client)        │
              │  server_addr: ...:7000      │
              └──────────────┬──────────────┘
                             │
              ┌──────────────┴──────────────┐
              │   Local service (e.g. SSH)   │
              │  127.0.0.1:22               │
              └─────────────────────────────┘
```

The project is a Cargo workspace with six crates arranged in a layered
dependency graph. Dependencies flow **upward** (binaries depend on logic crates,
which depend on the shared library):

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

| Crate | Purpose | Key Modules |
|-------|---------|-------------|
| **frp-core** | Shared library with no internal workspace dependencies | Protocol framing (`protocol.rs`), message types (`msg.rs`), config parsing (`config/`), transport abstraction (`transport/`), auth (`auth.rs`), encryption (`encryption.rs`), bridge (`bridge.rs`), mux (`mux.rs`), QUIC (`quic.rs`), KCP (`kcp/`), STUN (`stun.rs`), V2 handshake (`v2_handshake.rs`), cipher streams (`cipher_stream.rs`) |
| **frp-server** | Server logic — control handler, proxy registration, connection bridging | Service + accept loop (`service.rs`), control handler (`control/mod.rs`), proxy management (`proxy.rs`), bridge assignment (`control/bridge.rs`), proxy registration (`control/proxy_ops.rs`), NAT hole punching (`nathole/`), VHost routing (`vhost.rs`), dashboard + admin API (`dashboard.rs`), SSH gateway (`ssh_gateway.rs`), TCPMux (`tcpmux.rs`), config reload (SIGUSR1, `service.rs`), state (`state.rs`), handlers (`handlers.rs`) |
| **frps** | Server binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_server::Service::run()` |
| **frp-client** | Client logic — service lifecycle, control connection, local bridging | Client service (`service.rs`), work connections (`work_conn.rs`), visitor mode (`visitor.rs`), admin API (`admin.rs`), health checks (`health.rs`), client plugins (`plugin/`) |
| **frpc** | Client binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_client::Service::run()` |
| **frp-vnet** | L3 VPN / TUN device routing, used by the `virtual_net` proxy and visitor plugins | `controller.rs` (VnetController, RouteTable), `router.rs`, `virtual_client.rs`, `tun*.rs`, `msg.rs` |

`frp-core` defines the wire protocol, message types, and transport primitives
that both ends use. `frp-server` and `frp-client` contain the protocol logic but
no `main()` functions; the binaries live in `frps/` and `frpc/`.

**Crate dependency graph:**

```
frpc -> frp-client -> frp-core
frps -> frp-server -> frp-core
```

---

## Project Structure

```
frp-rs/
  Cargo.toml              Workspace manifest
  frp-core/               Shared library
    Cargo.toml
    src/
      lib.rs              Error types, Result, VERSION
      cli.rs              CLI argument parsing (shared by frps + frpc)
      admin_auth.rs       HTTP Basic Auth middleware (admin API / dashboard)
      auth.rs             MD5 token authentication + OIDC verification
      bridge.rs           Encrypted/compressed data bridge (streaming CFB)
      cipher_stream.rs    AES-128-CFB streaming encrypt/decrypt (CipherReader/CipherWriter)
      config/             TOML/YAML/JSON/INI config structs + Go→Rust compat normalization
      config_store.rs     Runtime config store (client proxy/visitor CRUD)
      encryption.rs       Key derivation (PBKDF2-SHA1) + Snappy compression
      crypto.rs           V2 AEAD algorithms (AES-256-GCM / XChaCha20-Poly1305)
      v2_handshake.rs     V2 ClientHello/ServerHello + capability negotiation
      kcp/                KCP transport (protocol, mod, session, socket, stream, listener, config)
      kcp_compat.rs       KCP interop helpers
      metrics.rs          ProxyMetricsRegistry + ConnGuard (per-proxy counters)
      msg.rs              Wire protocol message structs
      mux.rs              TCP multiplexing (yamux)
      protocol.rs         V1/V2 frame read/write
      transport/          transport.rs → directory: tcp.rs, tls.rs, kcp.rs, quic.rs,
                          websocket.rs (manual RFC 6455), yamux.rs, cipher.rs, aead.rs,
                          ssh_channel.rs, pre_read.rs, buffered_read.rs — IoStream
                          is a Box<dyn Transport> newtype
      udp_binary.rs       V2 UDP packet binary codec (frame type 19, Go v0.71.0)
      xtcp_session.rs     Persistent XTCP tunnel session (keepTunnelOpenWorker parity)
      xtcp_p2p.rs         XTCP MakeHole hole punching (Go frp semantics)
      stun.rs             STUN client for NAT traversal
      proxy_protocol.rs   HAProxy PROXY protocol header builder
      bandwidth.rs        Token-bucket bandwidth limiter
      buffer_pool.rs      Reusable bridge buffers (FRP_BRIDGE_BUF_KB)
      base64.rs, crc32c.rs, http_client.rs, snappy_stream.rs, control_sink.rs
      backoff.rs, logging.rs, system.rs, splice.rs, mem_profile.rs, profiling.rs,
      feature_gate.rs, unsafe_features.rs, internal_listener.rs
  frp-server/             Server library
    Cargo.toml
    src/
      lib.rs
      service.rs          Accept loop, connection dispatch, SIGUSR1 reload
      state.rs            AppState, InternalMsg, run_id → control routing
      handlers.rs         Connection dispatch helpers (work/visitor/NAT hole)
      registry.rs         ProxyManager registry + port allocation
      proxy.rs            ProxyInfo, proxy registration
      control/
        mod.rs            Per-client control handler, select loop
        dispatch.rs       Inbound control message dispatch
        login.rs          Login handshake + run_id
        pool.rs           Work connection pool + pending request queue
        proxy_ops.rs      NewProxy/CloseProxy handler, listen_and_proxy
        bridge.rs         Encrypted/plain bridge (+ proxy auth)
        nathole.rs        NAT hole punch over the control channel
      vhost.rs            HTTP/HTTPS VHost routing + Host/SNI parsing
      vhost_h2c.rs        HTTP/2 cleartext (h2c) decode/re-encode
      tcpmux.rs           TCPMux HTTP CONNECT domain routing
      dashboard.rs        Dashboard web UI + REST API (v1/v2)
      ssh_gateway.rs      SSH tunnel gateway (tcpip-forward / forwarded-tcpip)
      store.rs            Dashboard proxy persistence (frps_store.json)
      plugin/             Server HTTP plugins (mod.rs, http.rs)
      metrics/            Prometheus gauges + /metrics rendering (mod.rs, prom.rs)
      nathole/            XTCP NAT hole punch coordinator (controller, classify, analysis)
      event.rs, lock.rs
  frps/                   Server binary
    Cargo.toml
    src/main.rs, main-tiny.rs, main-micro.rs
  frp-client/             Client library
    Cargo.toml
    src/
      lib.rs
      service.rs          Login, proxy registration, message/select loop,
                          work connection spawning, health checks, UDP work conns
      control.rs          ControlConnection, login handshake, hostname resolution
      work_conn.rs        Work connection dial + local service bridge
      proxy.rs            NewProxy message builder, local TCP connect, bridge
      proxy_runtime.rs    Runtime proxy state (ProxyRuntimeInfo)
      visitor.rs          STCP/XTCP visitor listener + fallback
      reload.rs           Config snapshot + SIGUSR1 hot reload
      health.rs           TCP/HTTP health checks
      admin.rs            Admin REST API server (status, config, reload, stop, metrics)
      store.rs            Runtime proxy/visitor store (admin API CRUD)
      util.rs
      plugin/
        mod.rs            Plugin dispatch
        http.rs, socks5.rs, static_file.rs, unix_socket.rs
        http2http.rs, http2https.rs, https2http.rs, https2https.rs, tls2raw.rs
        context.rs, visitor.rs
  frpc/                   Client binary
    Cargo.toml
    src/main.rs, main-tiny.rs, main-micro.rs
  frp-vnet/               L3 VPN / TUN device routing
    Cargo.toml
    src/
      lib.rs              vnet control protocol + crate root
      controller.rs       VnetController, RouteTable, per-vnet routing
      router.rs           Packet router
      virtual_client.rs   Virtual client (provider side)
      tun.rs, tun_linux.rs, tun_macos.rs, tun_windows.rs
      msg.rs              vnet control message types
  docker/                 Docker build infrastructure
    Dockerfile.source      Multi-stage image (builds from Rust source)
    build.sh               Release binary download + verification script
    entrypoint.c           Minimal static entrypoint (FRP_MODE, conf path)
    README.md              Docker build documentation
  scripts/
    compat-test.sh         Go↔Rust cross-compatibility test suite (86 regular + 17 XTCP scenarios)
  frps.toml               Example server config
  frpc.toml               Example client config
  CLAUDE.md               Claude Code project instructions
  README.md               This file
```

---

## Wire Protocol

frp-rs implements both the **V1** and **V2** frp wire protocols.

### V1 Frame Format

```
+---------+------------------+------------------+
| 1 byte  |     8 bytes      |   variable       |
| Type    | Payload Length   | JSON Payload     |
|         | (big-endian i64) |                  |
+---------+------------------+------------------+
```

- **Type byte** identifies the message kind.
- **Length** is a big-endian 64-bit integer, capped at 10 KiB
  (`V1_MAX_MSG_LENGTH` = 10_240, matching Go frp). V2 framing raises the payload
  cap to 64 KiB.
- **Payload** is UTF-8 JSON serialized via serde_json.

`read_v1_frame()` reads the header, validates the length against 10 KiB, then
reads the payload. `deserialize_v1()` dispatches by type byte to the correct
`FrpMessage` variant. Defined in `frp-core/src/protocol.rs`.

After login, the server reads the first frame from every new TCP connection to
dispatch it: a `Login` frame means a new control connection; a `NewWorkConn`
frame is a work connection, routed to the correct control handler via `run_id`.

### Message Types

| Type Byte | Constant | Message | Direction | Purpose |
|-----------|----------|---------|-----------|---------|
| `o` | `TYPE_LOGIN` | Login | Client → Server | Authenticate and register |
| `1` | `TYPE_LOGIN_RESP` | LoginResp | Server → Client | Login result + run_id |
| `p` | `TYPE_NEW_PROXY` | NewProxy | Client → Server | Register a new proxy |
| `2` | `TYPE_NEW_PROXY_RESP` | NewProxyResp | Server → Client | Proxy registration result |
| `c` | `TYPE_CLOSE_PROXY` | CloseProxy | Client → Server | Unregister a proxy |
| `w` | `TYPE_NEW_WORK_CONN` | NewWorkConn | Client → Server | Announce a work connection (with run_id for routing) |
| `r` | `TYPE_REQ_WORK_CONN` | ReqWorkConn | Server → Client | Request a work connection |
| `s` | `TYPE_START_WORK_CONN` | StartWorkConn | Server → Client | Assign a work connection to a specific proxy |
| `h` | `TYPE_PING` | Ping | Bidirectional | Keepalive heartbeat |
| `4` | `TYPE_PONG` | Pong | Bidirectional | Heartbeat response |
| `u` | `TYPE_UDP_PACKET` | UDPPacket | Bidirectional | Encapsulated UDP data |
| `v` | `TYPE_NEW_VISITOR_CONN` | NewVisitorConn | Client → Server | STCP/XTCP visitor connection |
| `3` | `TYPE_NEW_VISITOR_CONN_RESP` | NewVisitorConnResp | Server → Client | Visitor connection result |
| `i` | `TYPE_NAT_HOLE_VISITOR` | NatHoleVisitor | Client → Server | NAT hole punch visitor |
| `n` | `TYPE_NAT_HOLE_CLIENT` | NatHoleClient | Client → Server | NAT hole punch client (STUN candidates) |
| `m` | `TYPE_NAT_HOLE_RESP` | NatHoleResp | Server → Client | NAT hole punch response (peer candidates) |
| `5` | `TYPE_NAT_HOLE_SID` | NatHoleSid | Server → Client | NAT hole SID assignment |
| `6` | `TYPE_NAT_HOLE_REPORT` | NatHoleReport | Client → Server | NAT hole detection report |
| `7` | `TYPE_CLOSE_PROXY_RESP` | CloseProxyResp | Server → Client | **Rust-only** — proxy close acknowledgment |
| `8` | `TYPE_ERROR` | Error | Server → Client | **Rust-only** — protocol error message |

> **Rust-only types (`7`, `8`)**: frp-rs extensions not present in Go frp
> v0.71.0. Go frp treats unknown message types as errors. Only send them on
> Rust↔Rust connections after capability negotiation. The payload structs live
> in `frp-core/src/msg.rs`.

The `FrpMessage` enum is `#[serde(untagged)]` — serde matches the first variant
whose fields intersect the JSON, so enum variant ordering matters in general. On
the wire this is not an issue: `deserialize_v1()` matches the type byte first
and dispatches to the correct struct before deserialization.

### V2

V2 uses a 7-byte magic `FRP\0\x02\r\n` followed by different framing with
numeric type IDs (u16). It provides full AEAD encryption with capability
negotiation via `frp-core/src/v2_handshake.rs` (ClientHello/ServerHello, HKDF
key derivation) and `frp-core/src/crypto.rs` (the `AeadAlgorithm` trait for
AES-256-GCM / ChaCha20-Poly1305). V2 frame read/write
(`read_v2_frame_raw`/`write_v2_frame_raw`), message dispatch
(`read_msg_v2`/`write_msg_v2`) and `deserialize_v2()` are fully operational.

Encryption in the control handler is protocol-aware: V1 uses AES-128-CFB
(`CipherStream`), while V2 with AEAD keys wraps the stream in `AeadStream` after
LoginResp. V2 compat tests run against the Go frp v0.71.0 pre-built binary.

**UDP packet binary codec (V2, Go frp v0.71.0)**: UDPPacket payloads use a
compact binary codec (`binary-v1`) when negotiated via the V2 handshake's
`udpPacketCodecs` capability; V1 stays JSON, and V2 falls back to JSON UDPPacket
(type 13) when not negotiated. Codec: `frp-core/src/udp_binary.rs`
(`EncodeUDPPacketBinary`/`DecodeUDPPacketBinary`), frame type 19
`V2_TYPE_UDP_PACKET_BINARY`, negotiated in `v2_handshake.rs` and carried on V2
UDP/SUDP work-conn data planes (`read_msg_v2_with_udp_codec`/
`write_msg_v2_with_udp_codec` in `protocol.rs`). The Rust-only V2 extension types
were renumbered to 21/22 to stay clear of Go's new type 19.

---

## Server Connection Lifecycle

The server's accept loop (`frp-server/src/service.rs`, `Service::run()`) is a
mixed-mode dispatcher that handles all supported transports on a single port:

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

Each accepted connection spawns a `tokio::spawn` task. `detect_and_strip_magic()`
peeks at the first bytes to classify the connection type without consuming data —
bytes are replayed via `PreReadStream`. The function also detects V2 magic
(`FRP\0\x02\r\n`) for QUIC streams.

**TLS connections** get additional processing:

- **TLS-only mode** (`tls_only: true`): non-TLS connections are rejected.
- **SNI-based HTTPS proxy routing** happens only on the **`vhost_https_port`
  listener** (`vhost.rs`, `extract_sni_from_client_hello`): the server peeks at
  the ClientHello for the SNI hostname, looks up the VHostManager, and routes the
  raw TLS stream directly to the HTTPS proxy handler. The **main port does NOT
  sniff SNI** — Go parity: it reads only the 0x17/0x16 TLS marker to detect TLS
  vs plain, so a wildcard https route cannot hijack frpc TLS control logins.
- **TCPMux over TLS** (`tcp_mux: true`): after the TLS handshake the stream is
  wrapped in a yamux multiplexer. The first yamux stream is the control channel;
  subsequent streams carry work connections.

**Additional listeners** are started alongside the main accept loop when their
ports are configured:

- WebSocket listener (separate port, `websocket_port`)
- KCP listener (`kcp_bind_port`)
- QUIC listener (`quic_bind_port`, requires `tls_enable`)
- HTTP VHost listener (`vhost_http_port`)
- HTTPS VHost listener (`vhost_https_port`)
- TCPMux HTTP CONNECT listener (`tcpmux_httpconnect_port`)
- SSH tunnel gateway (`ssh_tunnel_gateway.bind_port`)
- Dashboard HTTP server (`web_server.port`)

Each listener follows the same pattern: accept connection, read one frame,
dispatch by message type. Note the **KCP** handler checks the V2 magic first and
then does TLS detect → TLS accept → tcpMux → V2/V1, which is functionally
equivalent to Go frps' order (`service.go:670-710`) and interops with Go frpc.
Getting this order wrong was the root cause of both "invalid V1 message length"
(a yamux SYN parsed as FRP) and TLS rejection bugs.

---

## Work Connection Lifecycle

The work connection flow is the critical path for proxying traffic:

```
User                   frps                          frpc              Local
 |                      |                             |                  |
 |  connect to proxy    |                             |                  |
 |  port (6000)         |                             |                  |
 |--------------------->|                             |                  |
 |                      |  InternalMsg::ProxyUserConn |                  |
 |                      | (to control handler)        |                  |
 |                      |---------------------------->|                  |
 |                      |                             |                  |
 |                      |  ReqWorkConn (if no pooled  |                  |
 |                      |  connection available)      |                  |
 |                      |<----------------------------|                  |
 |                      |                             |                  |
 |                      |              NewWorkConn    |                  |
 |                      |      (dials server, sends   |                  |
 |                      |       run_id for routing)   |                  |
 |                      |<----------------------------|                  |
 |                      |                             |                  |
 |                      |  StartWorkConn              |                  |
 |                      |---------------------------->|                  |
 |                      |                             | connect local    |
 |                      |                             |----------------->|
 |                      |                             |<-----------------|
 |                      |          data bridge        |                  |
 |<==================================================>|                  |
 |                      |                             |                  |
```

The server maintains a per-client work connection pool and a queue of pending
proxy requests:

- **`pool_cap`**: `login.pool_count + 10` (the extra 10 comes from `WORK_POOL_EXTRA`)
- **`work_pool`**: `VecDeque<IoStream>` — idle work connections
- **`pending_requests`**: `VecDeque<PendingRequest>` — user connections waiting for a work conn

When a proxy listener accepts a user:

1. Pop from `work_pool` if non-empty — send `StartWorkConn` + bridge immediately.
2. If `work_pool` is empty, send `ReqWorkConn` to the client and push to
   `pending_requests` (timeout: 10s).

When a new work connection arrives:

1. Pop from `pending_requests` if non-empty — bridge immediately.
2. If no pending requests, push to `work_pool` (if below `pool_cap`).

A pooled connection is therefore assigned immediately, without a `ReqWorkConn`
round trip.

**Bridging** (`control/bridge.rs`, `assign_work_to_proxy`): after sending
`StartWorkConn` with proxy metadata (encryption flag, compression flag), the
server writes any pre-read bytes (from HTTP VHost parsing) and then bridges the
user connection to the work connection using either
`tokio::io::copy_bidirectional_with_sizes` with the 32 KiB `BUFFER_SIZE` (plain,
overridable via `FRP_BRIDGE_BUF_KB`) or `bridge::bridge_encrypted` (AES-128-CFB
+ Snappy, streaming — a single random 16-byte IV followed by continuous
ciphertext, no per-frame length prefix). The client-side plain relay mirrors this
(`relay_plain_fast` with `splice(2)` on Linux, `copy_bidirectional_with_sizes`
elsewhere).

---

## Server Control Plane: The InternalMsg Channel

The server's core is cross-task message passing via `InternalMsg` channels.
State is shared through `AppState`:

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

`ControlTx` contains an `mpsc::UnboundedSender<InternalMsg>` — when a proxy
listener accepts a user connection it sends an `InternalMsg::ProxyUserConn`
through this channel, and the control handler's `select!` loop dispatches it to
the right work connection.

```
                 ┌─────────────────────┐
                 │    AppState          │
                 │  run_id_to_ctl_tx   │
                 │  (run_id -> sender) │
                 └──────┬──────────────┘
                        │ lookup
          ┌─────────────┼─────────────┐
          │             │             │
          ▼             ▼             ▼
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │Control   │  │Control   │  │Work Conn │
   │Handler A │  │Handler B │  │Handler   │
   │          │  │          │  │          │
   │work_pool │  │work_pool │  │          │
   │pending_q │  │pending_q │  │          │
   └──────────┘  └──────────┘  └──────────┘
```

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

### Control handler `select!` loop

The control handler (`frp-server/src/control/mod.rs`, `handle_control()`) is the
most complex part of the server. After login it enters a `tokio::select!` loop:

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

The loop is deliberately **FAIR** — no `biased` keyword: an always-ready internal
queue must not starve control reads (heartbeat pings, Shutdown). Internal
messages represent real user traffic, so they get priority through the queue
discipline itself. Fairness is pinned by a regression test in `control/mod.rs`
that asserts no `biased;` in the loop and a bounded control p99 under internal
pressure.

---

## Authentication

Authentication uses **MD5(token + timestamp)** → hex string, matching Go frp
v0.71.0:

```
privilege_key = hex(MD5(token + timestamp))
```

Go frp switched from HMAC-SHA256 to MD5 in commit `78f9394`. The server computes
the expected key from its own token and the timestamp sent in the Login message,
then compares directly. See `frp-core/src/auth.rs`.

**OIDC** authentication is supported when the `oidc` feature is enabled: the
server verifies JWTs against an OIDC provider and maps subjects to proxy names.

---

## Encryption

### Key derivation

The 16-byte key is derived from the auth token via PBKDF2-SHA1:

```
encryption_key = PBKDF2(token, "frp", iterations=64, key_len=16, hash=SHA1)
```

`derive_key` is called in `Service::new()` with `auth_cfg.token` — the encryption
key derives from the auth token, not from a separate secret. See
`frp-core/src/encryption.rs`.

> **Salt note:** the Go frp golib source says the PBKDF2 salt is `"crypto"`, but
> the pre-built binaries (verified against v0.70.1 and v0.71.0) use `"frp"`. This
> codebase uses `"frp"` for binary compatibility.

### Control connection

AES-128-CFB, with the key derived as above.

### Encrypted bridge (data plane)

When `use_encryption = true` on a proxy, data between frps and frpc is encrypted
with **AES-128-CFB**, with **Snappy** compression applied first:

```
plaintext → Snappy compress → AES-128-CFB encrypt → [16-byte IV][ciphertext stream]
```

The encrypted bridge is a **streaming** CFB channel: the writer sends one random
16-byte IV before the first ciphertext block, then encrypts continuously with
shared cipher state (`CipherWriter`/`CipherReader` in
`frp-core/src/cipher_stream.rs`) — there is no per-frame length prefix, and the
reader consumes the IV on its first read. Implemented in
`frp-core/src/bridge.rs`.

Supported for TCP proxies (both client and server bridge paths), XTCP P2P
channels, and control connections.

### V2 control

AEAD (AES-256-GCM or XChaCha20-Poly1305). Keys are derived via HKDF-SHA256 from
the transcript hash. Implemented in `frp-core/src/crypto.rs`.

### XTCP P2P encryption

Go frp encrypts hole-punched P2P connections with
`PBKDF2-SHA1(SecretKey, salt="frp", iter=64, keylen=16)` → AES-128-CFB. Both
provider and visitor P2P paths use `bridge_encrypted` with `derive_key(&sk)` when
`use_encryption` is true. The `sk` (secret key) is the proxy's `sk` field from
`ProxyConfig`, **not** the auth token; it is stored in `ProxyRuntimeInfo` for
access in the NAT hole punch handler paths. See "XTCP P2P data plane" below.

Probe packets (NatHoleSid) are AES-128-CFB encrypted with the same key; without a
secret key, Rust↔Rust probes fall back to the `"frp"` magic. Both sides derive
the same key from the shared SecretKey, matching Go frp.

---

## Transport Abstraction

`IoStream` (`frp-core/src/transport/`) is a type-erased newtype over a boxed
trait object — the old 11-variant enum is gone:

```rust
pub struct IoStream(Box<dyn Transport>);
```

Each transport implements the `Transport` trait in its own file under
`frp-core/src/transport/`: `tcp.rs` (`TcpStream`), `tls.rs` (`TlsTransport`),
`kcp.rs` (`KcpStream`), `quic.rs` (`QuicStream`), `websocket.rs` (`WsByteStream`,
manual RFC 6455 framing — tungstenite was removed 2026-08-09), `yamux.rs`
(`YamuxStream`), `cipher.rs` (`CipherStream<S>`), `aead.rs` (`AeadStream`),
`ssh_channel.rs` (`SshChannelTransport`), `pre_read.rs` (`PreReadTransport`),
`buffered_read.rs` (`BufferedReadTransport`). `IoStream`'s constructors are named
after the old variants (`IoStream::Tcp(stream)`, `IoStream::Yamux(stream)`, …) so
construction sites read identically; per-transport files each own their `#[cfg]`
gates.

The `Transport` trait bundles `AsyncRead + AsyncWrite + Unpin + Send + 'static`
plus the consuming methods that used to be per-variant matches:

- `into_encrypted(self: Box<Self>)` — default wraps in `CipherStream`; `Aead`
  returns itself.
- `into_split(self: Box<Self>) -> (BoxedReadHalf, BoxedWriteHalf)` — default
  `tokio::io::split`; QUIC uses quinn's native halves. The old static
  `ReadHalf`/`WriteHalf` enums are deleted, and `split_work_conn_halves` is a
  thin wrapper over it.
- `into_tcp` / `try_tcp` / `try_tcp_mut` — downcast to the raw `TcpStream` for
  the Linux `splice(2)` fast path.
- `into_parts` — peels `PreRead` for the TLS/V1 accept paths.
- `is_yamux_wrappable` — false for QUIC only.
- `bridge_split_err` — the `Cipher`/`Aead`-in-bridge guard.

The **WebSocket** adapter wraps WebSocket binary messages into
`AsyncRead`/`AsyncWrite` so the V1 protocol operates over WebSocket without
changes.

### Per-transport notes

- **TCP_NODELAY**: every raw `TcpStream` on the data path (client control/work
  dials via `connect_direct`/`connect_via_proxy`; server control/work/visitor +
  user-proxy + vhost + tcpmux accepts; client local-service dials; SSH gateway;
  plugin forwarders) calls `frp_core::transport::set_nodelay` — matching Go frp's
  `net.TCPConn` default (`NoDelay(true)`). For TLS/mux/WS-wrapped streams it is
  set on the underlying `TcpStream` before wrapping. Errors are logged at debug
  and ignored (a failed socket option must not kill a connection). KCP sets its
  own nodelay; QUIC/UDP are excluded. Wire-invisible.
- **Bridge buffer size**: `frp_core::buffer_pool::BUFFER_SIZE` defaults to
  **32 KiB** (matching Go frp's `io.Copy`; it was 64 KiB — halved for
  per-connection footprint). Override with `FRP_BRIDGE_BUF_KB` (4–1024). The plain
  bridge copies with `copy_bidirectional_with_sizes(a, b, *BUFFER_SIZE,
  *BUFFER_SIZE)`, so `BUFFER_SIZE` applies to the plain path too; the
  encrypted/compressed path uses the `PoolGuard` buffer pool (also
  `BUFFER_SIZE`).

### Transport status

| Transport | Status |
|---|---|
| **TCP** | Fully implemented (control + work connections, TLS, WebSocket upgrade) |
| **WebSocket** | Fully implemented — dial, accept, message dispatch (control + work connections) |
| **KCP** | Fully implemented — dial, accept, TLS, yamux, message dispatch |
| **QUIC** | Fully implemented — dial, accept, message dispatch (requires a TLS cert on the server) |
| **TcpMux** | Full yamux implementation (`frp-core/src/mux.rs`) — server and client mode, keepalive, stream accept/spawn via `server_mux`/`client_mux` |
| **Dashboard** | Status API with axum (`frp-server/src/dashboard.rs`) — version, uptime, client/proxy counts, plus REST v1/v2 |
| **VHost** | HTTP/HTTPS VHost routing (`frp-server/src/vhost.rs`) with Host header parsing, SNI, pre-read byte forwarding, plus h2c |

**KCP architecture**: `KcpSocket` driver (UDP event loop), `KcpSession` per-peer
(in-tree KCP protocol + FEC), `KcpStream` (AsyncRead/AsyncWrite). The KCP state
machine is implemented in-tree (`kcp/protocol.rs`, aligned with kcp-go v5.6.13
wire behavior) — the vendored `kcp` crate and its `[patch.crates-io]` entry are
gone. `conv_index: HashMap<u32, SocketAddr>` provides O(1) write-path lookup.
Write backpressure uses an `Arc<AtomicUsize>` shared between `KcpSocket` and
`KcpStream` (gates `poll_write` at 200 unprocessed messages,
`KCP_WRITE_BACKLOG_THRESHOLD` — a pre-full gate for the 256-cap channel).
Verified: KCP+TLS+tcpMux+CipherStream all working (RTT ~76ms). Integration test
with real UDP sockets: `frp-core/tests/kcp.rs`.

**TcpMux** (`frp-core/src/mux.rs`): server and client mode, keepalive, stream
accept/spawn via `server_mux`/`client_mux`. A double-poll pattern flushes pending
frames to the socket. A zero keepalive interval is normalized to the 30s default
instead of causing an immediate timeout or spin. Dead-conn detection uses
`MAX_IDLE_KEEPALIVE_TICKS = 3` (~90s idle). `open_stream` is wakeup-loss-proof (a
`watch` channel, not `Notify`) and fails fast once the driver has died (`alive`
flag).

---

## Config Normalization

`frp-core/src/config/` (directory: `mod.rs`/`client.rs`/`server.rs`/
`normalize.rs`/`loader.rs`/`strict.rs`) includes a full Go→Rust config
compatibility layer:

- `[common]` sections are flattened to the top level
- `auth_method` / `auth_token` → nested under `[auth]`
- `log_file` / `log_level` → nested under `[log]`
- `web_server_*` → nested under `[web_server]`
- `tcp_mux` → nested under `[transport]`
- Client-side: `protocol` → `transport_protocol`, `serverAddr` → `server_addr`,
  `auth.token` → top-level `token`
- TOML values are converted via `toml_to_json()` to `serde_json::Value`, then
  deserialized into the config structs

The config file format is auto-detected by extension: TOML, YAML, JSON, INI.

---

## XTCP NAT Hole Punching

XTCP enables direct peer-to-peer connections between two frpc clients behind NAT.
The server coordinates the control plane (NAT classification, 5-mode behavior
recommendation, session management) but never relays XTCP data and sends no probe
packets — provider and visitor each do their own STUN.

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

1. **Fresh TCP connection** (accept loop): the visitor sends `NatHoleVisitor` on
   a new TCP connection. The server creates a session and sends
   `NatHoleSidOnWorkConn`; the provider control handler writes
   `StartWorkConn`+`NatHoleSid` on a work conn. The provider does STUN, sends
   `NatHoleClient` on control, the server runs NAT analysis, then sends
   `NatHoleResp` to both sides.
2. **Control connection** (Go frp compat): Go frpc v0.71.0 sends `NatHoleVisitor`
   on its existing control channel. The server creates the session with
   `create_session_with_ctl`, spawns a task waiting for the provider's
   `NatHoleClient` on control, runs NAT analysis, and sends `NatHoleResp` to both
   sides via `InternalMsg::WriteNatHoleSid` / `WriteNatHoleResp` /
   `WriteNatHoleReport`.

**Status:** fully implemented and cross-compat verified (17/17 XTCP pairwise
scenarios against Go frp v0.71.0; daily `xtcp-compat.yml` VPS matrix). e2e test in
`frp-server/tests/xtcp_hole_punch.rs`, loopback MakeHole tests in
`frp-core/tests/xtcp_p2p.rs`.

**End-to-end flow:** Visitor→Server(`NatHoleVisitor`) → Server→Provider
(`NatHoleSidOnWorkConn` → `StartWorkConn`+`NatHoleSid` on work conn) → Provider
does STUN → Provider→Server(`NatHoleClient` on control) → Server NAT analysis
(classify + 5-mode behavior recommend) → Server→Visitor(`NatHoleResp`) +
Server→Provider(`NatHoleResp`, **sender side delayed 1s**) → both sides run
MakeHole UDP probing per `DetectBehavior` → the winner socket carries the
KCP+yamux P2P data plane → bridge to local → Provider→Server(`NatHoleReport`) →
session complete.

**NAT analysis** (`frp-server/src/nathole/analysis.rs`): a 5-mode behavior table
with a score-based `Analyzer`. Each mode tests how the NAT behaves for different
address/port combinations, and the analyzer learns from success feedback —
successful hole punches increase the score for the modes that predicted the
correct behavior.

**STCP fallback**: if the hole punch fails (e.g. both sides behind symmetric NAT),
the visitor falls back to an STCP proxy named by the `fallback_to` config field,
matching Go frp's architecture.

### XTCP P2P data plane

After the hole punch the P2P stream runs on the socket that received the peer's
detect reply (Go `result.lConn` semantics — only that socket has a working NAT
mapping). Two transports are supported, selected by the `protocol` field (the
visitor decides; an empty protocol is normalized to `"quic"` — Go `EmptyOr`
parity):

- **QUIC** (`protocol="quic"`, the default): the punched socket is handed directly
  to quinn (`xtcp_p2p_connect_quic` — no yamux; QUIC multiplexes streams itself),
  self-signed TLS + InsecureSkipVerify, ALPN `frp`. The visitor is the QUIC client
  and the provider the QUIC server. Requires the `quic` feature (default ON). Go
  visitors with `protocol="quic"` interoperate: Go frp v0.71.0 sends the peer
  `"ip:port"` as the QUIC SNI, which upstream rustls 0.23 rejects, so frp-rs
  vendors rustls (0.23.43 at `vendor/rustls`) with a server-side patch treating an
  invalid SNI as "no SNI" (see
  [`vendor/rustls/README-FRP-RS.md`](../vendor/rustls/README-FRP-RS.md) and
  `docs/archive/notes/2026-08-04-xtcp-quic-sni-compat.md`; drop the patch when
  the workspace moves past rustls 0.23).
- **KCP + yamux** (`protocol="kcp"`): the punched UDP socket runs KCP
  (`XtcpP2pStream`) with yamux on top.

**Persistent tunnel session** (`frp-core/src/xtcp_session.rs`, Go
`keepTunnelOpenWorker` parity): one hole-punched QUIC/yamux session per proxy is
reused across user connections instead of re-punching per connection. The visitor
re-signals `startTunnel` on every error path, and the budget clamps to
`min(20s, fallbackTimeoutMs)`.

**Provider/visitor roles**: the provider side (`frp-client/src/service.rs`) reads
`StartWorkConn`+`NatHoleSid` from the work conn, does STUN, sends `NatHoleClient`
on control, reads `NatHoleResp`, then runs `xtcp_p2p_connect_yamux` → bridge to
local. The visitor side (`frp-client/src/visitor.rs`) handles `NatHoleVisitor` →
PreCheck + STUN + full `NatHoleVisitor` → `xtcp_p2p_connect_yamux` → bridge to
user. Hole punching is UDP-based: both sides run Go-style `MakeHole` probing
(`punch_udp_hole_makehole_owned` is the entry point in
`frp-core/src/xtcp_p2p.rs`).

**Module structure** (`frp-server/src/nathole/`):

- `mod.rs` — module root, `NAT_HOLE_TIMEOUT = 10s`
- `controller.rs` — session management, provider registration, `build_nat_hole_response()`
- `classify.rs` — NAT feature classification (EasyNAT vs HardNAT, behavior detection)
- `analysis.rs` — 5-mode behavior table, score-based `Analyzer` with success feedback

---

## Invariants

The rules an agent or contributor must not break (interface contracts, wire
compatibility traps, ordering constraints) are maintained in one place:
[**Gotchas in CLAUDE.md**](../CLAUDE.md#gotchas). They are not duplicated here.
