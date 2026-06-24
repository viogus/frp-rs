<div align="center">
  <h1>frp-rs</h1>
  <p><em>A fast reverse proxy written in Rust — protocol-compatible with frp.</em></p>
  <p>
    <a href="#overview">Overview</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#getting-started">Getting Started</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#protocol">Protocol</a> •
    <a href="#project-structure">Project Structure</a>
  </p>
</div>

---

## Overview

**frp-rs** is a native Rust implementation of [frp](https://github.com/fatedier/frp),
a reverse proxy that lets you expose services running on a private network to the
public internet. It speaks the same V1 wire protocol as the Go version, making it
suitable as a drop-in replacement for either the client or server side.

### Status

| Feature              | Client | Server |
|----------------------|--------|--------|
| TCP proxy            | ✅     | ✅     |
| UDP proxy            | ✅     | ✅     |
| Token authentication  | ✅     | ✅     |
| Heartbeat (ping/pong)| ✅     | ✅     |
| Auto port allocation | —      | ✅     |
| Encryption (AES-128-CFB) | ✅  | ✅     |
| WebSocket transport  | 🚧     | ✅     |
| TLS transport        | ✅     | ✅     |
| STCP / sk routing    | ✅     | ✅     |
| HTTP VHost routing   | —      | ✅     |
| HTTPS VHost routing  | —      | ✅     |
| TCP health checks    | ✅     | —      |
| QUIC transport       | ❌     | ❌     |
| KCP / SUDP           | ❌     | ❌     |
| Compression (Snappy) | ✅     | ✅     |
| OIDC authentication  | ❌     | ❌     |
| Dashboard (web UI)   | —      | ❌     |
| NAT hole punching (XTCP) | ❌ | ❌     |

---

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

The project is split into five crates:

| Crate | Purpose |
|-------|---------|
| **frp-core** | Shared library: protocol framing, message types, config parsing, transport abstraction, authentication |
| **frp-server** | Server logic: control connection handler, proxy registry, port allocation, connection bridging |
| **frps** | Server binary with CLI argument parsing and logging setup |
| **frp-client** | Client logic: service lifecycle, control connection, work connection loop, local bridge |
| **frpc** | Client binary with CLI argument parsing and logging setup |

---

## Getting Started

### Build

```bash
From the workspace root:

cargo build --release
```

The binaries land at `target/release/frps` and `target/release/frpc`.

### Quick Start

1. Start the server:

   ```bash
   ./target/release/frps -c frps.toml
   ```

   The default `frps.toml` listens on `0.0.0.0:7000` with token auth.

2. Start the client:

   Edit `frpc.toml` to point `server_addr` at your server's IP, then:

   ```bash
   ./target/release/frpc -c frpc.toml
   ```

   The default config proxies local SSH (port 22) to remote port 6000.

3. Connect through the proxy:

   ```bash
   ssh -oPort=6000 user@<server-ip>
   ```

---

## Configuration

### Server (`frps.toml`)

```toml
bind_addr = "0.0.0.0"
bind_port = 7000
websocket_port = 7001

[auth]
method = "token"
token = "my-frp-token"

[log]
level = "info"
file = ""
max_days = 3

[web_server]
addr = ""
port = 0
user = ""
password = ""

[transport]
tcp_mux = true
tcp_mux_keepalive_interval = 30
```

| Field | Default | Description |
|-------|---------|-------------|
| `bind_addr` | `"0.0.0.0"` | Address the server binds to |
| `bind_port` | `7000` | Main control connection port |
| `proxy_bind_addr` | `""` | Separate bind address for proxy ports (empty = same as bind_addr) |
| `vhost_http_port` | `0` | HTTP VHost port (0 = disabled) |
| `vhost_https_port` | `0` | HTTPS VHost port (0 = disabled) |
| `kcp_bind_port` | `0` | KCP port (0 = disabled) |
| `quic_bind_port` | `0` | QUIC port (0 = disabled) |
| `websocket_port` | `0` | WebSocket listener port (0 = disabled) |
| `sub_domain_host` | `""` | Host for sub-domain proxy support |
| `tls_enable` | `false` | Enable TLS on the listener |
| `tls_cert_file` | `""` | Path to TLS certificate |
| `tls_key_file` | `""` | Path to TLS private key |
| `tls_ca_file` | `""` | CA certificate for mutual TLS |
| `auth.method` | `"token"` | Authentication method (token or oidc) |
| `auth.token` | `""` | Shared authentication token |
| `log.level` | `"info"` | Log level: trace, debug, info, warn, error |
| `log.file` | `""` | Log file path (empty = stderr) |
| `log.max_days` | `3` | Max days to retain log files |
| `web_server.port` | `0` | Dashboard port (0 = disabled) |
| `transport.tcp_mux` | `true` | Enable TCP multiplexing |
| `transport.tcp_mux_keepalive_interval` | `30` | Keepalive interval (seconds) for mux |
| `allow_port_start` | `10000` | Start of auto-assigned port range |
| `allow_port_end` | `50000` | End of auto-assigned port range |

### Client (`frpc.toml`)

```toml
server_addr = "127.0.0.1"
server_port = 7000
token = "my-frp-token"
transport_protocol = "tcp"
tcp_mux = true
pool_count = 1
login_fail_exit = false

[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
use_encryption = false
use_compression = false
```

| Field | Default | Description |
|-------|---------|-------------|
| `server_addr` | — | Server address (required) |
| `server_port` | `7000` | Server control port |
| `transport_protocol` | `"tcp"` | Transport: tcp, websocket/ws, wss, quic |
| `token` | `""` | Authentication token (must match server) |
| `user` | `""` | User identity for multi-tenant setups |
| `client_id` | `""` | Unique client identifier (auto-generated if empty) |
| `tls_enable` | `false` | Enable TLS |
| `tls_cert_file` | `""` | Client TLS certificate |
| `tls_key_file` | `""` | Client TLS private key |
| `tls_ca_file` | `""` | CA certificate for server verification |
| `tls_server_name` | `""` | Server name for TLS SNI |
| `log.level` | `"info"` | Log level |
| `login_fail_exit` | `true` | Exit on login failure; false to keep retrying |
| `pool_count` | `0` | Number of pre-established work connections (pooled on the server) |
| `tcp_mux` | `true` | Enable TCP multiplexing |

#### Proxy entries (`[[proxies]]`)

| Field | Default | Description |
|-------|---------|-------------|
| `name` | — | Unique proxy name |
| `type` | — | Proxy type: tcp, udp, http, https, stcp, xtcp |
| `local_ip` | `""` | Local service IP |
| `local_port` | `0` | Local service port |
| `remote_port` | `0` | Remote port to expose (0 = auto-assign) |
| `use_encryption` | `false` | Encrypt proxy traffic |
| `use_compression` | `false` | Compress proxy traffic |
| `sk` | `""` | Secret key (for STCP/XTCP) |
| `custom_domains` | `[]` | Custom domains (for HTTP/HTTPS) |
| `subdomain` | `""` | Sub-domain name |
| `http_user` / `http_password` | `""` | HTTP basic auth for the proxy |
| `host_header_rewrite` | `""` | Rewrite the Host header |
| `group` / `group_key` | `""` | Proxy group for load balancing |
| `health_check_type` | `""` | Health check: tcp or http |
| `health_check_interval_seconds` | `0` | Seconds between health checks (min 10) |
| `health_check_timeout_seconds` | `0` | Health check connect timeout (min 3) |
| `health_check_max_failed` | `0` | Consecutive failures before marking unhealthy (min 1) |
| `bandwidth_limit` | `""` | Bandwidth limit (e.g. "1MB") |
| `bandwidth_limit_mode` | `""` | Bandwidth limit mode (client/server) |
| `multiplexer` | `""` | Multiplexer type for the proxy |
| `metas` | `{}` | Key-value metadata for the proxy |
| `annotations` | `{}` | Key-value annotations for the proxy |
| `headers` | `{}` | Custom HTTP request headers |
| `response_headers` | `{}` | Custom HTTP response headers |
| `route_by_http_user` | `""` | Route by HTTP basic auth user |
| `allow_users` | `[]` | Allowed HTTP basic auth users |
| `http_pwd` | `""` | HTTP basic auth password (alias for http_password) |
| `locations` | `[]` | URL path locations for HTTP routing |

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
- **Length** is a big-endian 64-bit integer, capped at 64 KiB.
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

Authentication uses **MD5(token + timestamp)** → hex string, matching Go frp v0.69.1:

```
privilege_key = hex(MD5(token + timestamp))
```

The server computes the expected key from its token and the timestamp sent in
the Login message, then compares directly.

### Encryption

When `use_encryption = true` on a proxy, data between frps and frpc is encrypted
with **AES-128-CFB**, matching Go frp v0.69.1. The encryption key (16 bytes) is
derived from the auth token via PBKDF2-SHA1:

```
encryption_key = PBKDF2(token, "crypto", iterations=64, key_len=16, hash=SHA1)
```

### Compression

When `use_compression = true`, data is compressed with **Snappy** (matching Go frp
v0.69.1) before encryption. Compression is applied first, then encryption:

```
plaintext → Snappy compress → AES-128-CFB encrypt → [4-byte BE len][encrypted frame]
```

Each encrypted frame contains a random 16-byte IV followed by the CFB-encrypted
(possibly compressed) data:

```
[4-byte BE len][16-byte IV][AES-128-CFB encrypted (Snappy-compressed? plaintext)]
```

- Supported for TCP proxies (both client and server bridge paths).
- UDP proxy encryption not yet implemented.

## Project Structure


```
frp-rs/
  Cargo.toml              Workspace manifest
  frp-core/               Shared library
    Cargo.toml
    src/
      lib.rs              Error types, Result, VERSION
      args.rs             CLI argument parsing (shared by frps + frpc)
      auth.rs             MD5 token authentication
      bridge.rs           Encrypted data bridge (AES-128-CFB framed)
      config.rs           TOML config structs + Go frp compat normalization
      encryption.rs       AES-128-CFB encrypt/decrypt + Snappy compress/decompress
      msg.rs              Wire protocol message structs
      mux.rs              TCP multiplexing (placeholder)
      protocol.rs         V1/V2 frame read/write
      transport.rs        TCP/TLS/WebSocket dial + accept + IoStream abstraction
  frp-server/             Server library
    Cargo.toml
    src/
      lib.rs
      service.rs          AppState, InternalMsg, accept loop with frame dispatch
      control.rs          Per-client control handler, work pool, listener registry
      proxy.rs            ProxyManager, ProxyInfo, port allocation
      vhost.rs            HTTP/HTTPS VHost routing + Host header parsing
      dashboard.rs        Dashboard web UI (stub)
  frps/                   Server binary
    Cargo.toml
    src/main.rs
  frp-client/             Client library
    Cargo.toml
    src/
      lib.rs
      service.rs          Login, proxy registration, message/select loop,
                          work connection spawning, health checks, UDP work conns
      control.rs          ControlConnection, login handshake, hostname resolution
      proxy.rs            NewProxy message builder, local TCP connect, bridge
  frpc/                   Client binary
    Cargo.toml
    src/main.rs
  docker/                 Docker build infrastructure
    Dockerfile             Multi-stage image (downloads release binary)
    Dockerfile.source      Multi-stage image (builds from Rust source)
    build.sh               Release binary download + verification script
    entrypoint.c           Minimal static entrypoint (FRP_MODE, conf path)
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

---

## Docker

Pre-built Docker images are published to GitHub Container Registry on every push to `main`:

```bash
# Server (built from source)
docker pull ghcr.io/viogus/frps-rs:latest

# Client (built from source)
docker pull ghcr.io/viogus/frpc-rs:latest

docker run -d -p 7000:7000 -v $(pwd)/frps.toml:/app/frp.toml ghcr.io/viogus/frps-rs:latest
```

Two Dockerfile variants in `docker/`:
- `Dockerfile` — downloads pre-built release binary
- `Dockerfile.source` — builds from source via multi-stage Rust image (used for CI auto-builds)

---

## Developing

```bash
# Build everything
cargo build

# Run tests
cargo test --workspace

# Lint
cargo clippy

# Start the server locally
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Start the client (in another terminal)
RUST_LOG=debug cargo run --bin frpc -- -c frpc.toml

# Run multiple services from a config directory
cargo run --bin frps -- --config-dir /etc/frp/conf.d

# Build Docker image locally
docker build -f docker/Dockerfile.source --build-arg FRP_COMPONENT=frps -t frps-rs:local .
```

---

## License

MIT. frp-rs is not affiliated with the original Go frp project.
