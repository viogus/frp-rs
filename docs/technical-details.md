# frp-rs Technical Details

> Internal architecture and wire-protocol notes, split out of the README so the
> top-level document stays focused on features, usage, and deployment. See
> [README](../README.md) for the user-facing guide and
> [docs/developing.md](developing.md) for the developer workflow.

## Architecture

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

The project is split into six crates:

| Crate | Purpose |
|-------|---------|
| **frp-core** | Shared library: protocol framing, message types, config parsing, transport abstraction, authentication |
| **frp-server** | Server logic: control connection handler, proxy registry, port allocation, connection bridging |
| **frps** | Server binary with CLI argument parsing and logging setup |
| **frp-client** | Client logic: service lifecycle, control connection, work connection loop, local bridge |
| **frpc** | Client binary with CLI argument parsing and logging setup |
| **frp-vnet** | L3 VPN / TUN device routing, used by the `virtual_net` proxy and visitor plugins |

---

## Protocol

frp-rs implements the **frp V1 wire protocol**, using a simple length-prefixed
JSON framing over TCP.

### V1 Frame Format

```
+---------+------------------+------------------+
| 1 byte  |     8 bytes      |   variable       |
| Type    | Payload Length   | JSON Payload     |
|         | (big-endian i64) |                  |
+---------+------------------+------------------+
```

- **Type byte** identifies the message kind.
- **Length** is a big-endian 64-bit integer, capped at 10 KiB (`V1_MAX_MSG_LENGTH`, matching Go frp). The V2 framing raises the payload cap to 64 KiB.
- **Payload** is UTF-8 JSON serialized via serde_json.

### Message Types

| Type Byte | Message         | Direction      | Purpose |
|-----------|-----------------|----------------|---------|
| 'o'       | Login           | Client to Server | Authenticate and register |
| '1'       | LoginResp       | Server to Client | Login result + run_id |

After login, the server reads the first frame from every new TCP connection to
dispatch it:
- A `Login` frame means a new control connection.
- A `NewWorkConn` frame means a work connection and is routed to the correct
  control handler via `run_id`.

| Type Byte | Message         | Direction      | Purpose |
|-----------|-----------------|----------------|---------|
| 'p'       | NewProxy        | Client to Server | Register a new proxy |
| '2'       | NewProxyResp    | Server to Client | Proxy registration result |
| 'c'       | CloseProxy      | Client to Server | Unregister a proxy |
| 'w'       | NewWorkConn     | Client to Server | Announce a work connection (with run_id for routing) |
| 'r'       | ReqWorkConn     | Server to Client | Request a work connection |
| 's'       | StartWorkConn   | Server to Client | Assign work connection to a specific proxy |
| 'h'       | Ping            | Bidirectional  | Keepalive heartbeat |
| '4'       | Pong            | Bidirectional  | Heartbeat response |
| 'u'       | UDPPacket       | Bidirectional  | Encapsulated UDP data |
| 'v'       | NewVisitorConn  | Client to Server | STCP/XTCP visitor connection |
| '3'       | NewVisitorConnResp | Server to Client | Visitor connection result |
| 'i'       | NatHoleVisitor  | Client to Server | NAT hole punch visitor |
| 'n'       | NatHoleClient   | Client to Server | NAT hole punch client (STUN candidates) |
| 'm'       | NatHoleResp     | Server to Client | NAT hole punch response (peer candidates) |
| '5'       | NatHoleSid      | Server to Client | NAT hole SID assignment |
| '6'       | NatHoleReport   | Client to Server | NAT hole detection report |
| '7'       | CloseProxyResp  | Server to Client | **Rust-only** — proxy close acknowledgment |
| '8'       | Error           | Server to Client | **Rust-only** — protocol error message |

> **Rust-only types ('7', '8'):** These are frp-rs extensions not present in Go frp v0.71.0. Go frp treats unknown message types as errors. Only send on Rust↔Rust connections after capability negotiation. See `frp-core/src/msg.rs` for the payload structs.

### Work Connection Lifecycle

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

The server maintains a per-client work connection pool (`work_pool`) and a queue
of pending proxy requests (`pending_requests`). If a pooled connection is
available when a user connects, it is assigned immediately without sending
`ReqWorkConn`.

### Internal Messaging (Server)

The server uses an `InternalMsg` channel for cross-task communication:

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

- **Proxy listeners** send `InternalMsg::ProxyUserConn` to the control handler
  for the owning client.
- **Work connection handlers** send `InternalMsg::NewWorkConn` to the control
  handler, which either assigns it to a pending request or pools it.
- The `accept` loop reads the first frame from every new connection to dispatch
  it to the correct handler (control vs work).

### Authentication

Authentication uses **MD5(token + timestamp)** → hex string, matching Go frp v0.71.0:

```
privilege_key = hex(MD5(token + timestamp))
```

The server computes the expected key from its token and the timestamp sent in
the Login message, then compares directly.

### Encryption

When `use_encryption = true` on a proxy, data between frps and frpc is encrypted
with **AES-128-CFB**, matching Go frp v0.71.0. The encryption key (16 bytes) is
derived from the auth token via PBKDF2-SHA1:

```
encryption_key = PBKDF2(token, "frp", iterations=64, key_len=16, hash=SHA1)
```

### Compression

When `use_compression = true`, data is compressed with **Snappy** (matching Go frp
v0.71.0) before encryption. Compression is applied first, then encryption:

```
plaintext → Snappy compress → AES-128-CFB encrypt → [16-byte IV][ciphertext stream]
```

The encrypted bridge is a **streaming** CFB channel: the writer sends one random
16-byte IV before the first ciphertext block, then encrypts continuously with
shared cipher state (`CipherWriter`/`CipherReader` in `frp-core/src/cipher_stream.rs`) —
there is no per-frame length prefix. The reader consumes the IV on its first read.

- Supported for TCP proxies (both client and server bridge paths), XTCP P2P channels, and control connections.
- Note: Go frp v0.71.0 golib source says salt `"crypto"` but the pre-built binary uses `"frp"`. This codebase uses `"frp"` for binary compatibility.

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

### Crate Dependency Graph

```
frpc -> frp-client -> frp-core
frps -> frp-server -> frp-core
```

`frp-core` has no internal crate dependencies, making it the shared foundation
that both ends build on.
