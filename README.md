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
| Token authentication  | ✅     | ✅     |
| Heartbeat (ping/pong)| ✅     | ✅     |
| Auto port allocation | —      | ✅     |
| WebSocket transport  | 🚧     | 🚧     |
| TLS transport        | 🚧     | 🚧     |
| QUIC transport       | ❌     | ❌     |
| KCP / STCP / SUDP    | ❌     | ❌     |
| HTTP(S) VHost        | ❌     | ❌     |
| OIDC authentication  | ❌     | ❌     |
| Dashboard (web UI)   | —      | ❌     |

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

Authentication uses **HMAC-SHA256** with the shared token:

```
privilege_key = hex(HMAC-SHA256(token, timestamp))
```

The server computes the expected key from its token and the timestamp sent in
the Login message, then compares in constant time.

## Project Structure


```
frp-rs/
  Cargo.toml              Workspace manifest
  frp-core/               Shared library
    Cargo.toml
    src/
      lib.rs              Error types, Result, VERSION
      auth.rs             HMAC-SHA256 token auth
      config.rs           TOML config structs
      msg.rs              Wire protocol message structs
      protocol.rs         V1/V2 frame read/write
      transport.rs        TCP/WebSocket/QUIC dial + accept abstractions
  frp-server/             Server library
    Cargo.toml
    src/
      lib.rs
      service.rs          AppState, InternalMsg, accept loop with frame dispatch
      control.rs          Per-client control handler, work pool, pending queue
      proxy.rs            ProxyManager, ProxyInfo, port allocation
  frps/                   Server binary
    Cargo.toml
    src/main.rs
  frp-client/             Client library
    Cargo.toml
    src/
      lib.rs
      service.rs          Login, proxy registration, message/select loop,
                          work connection spawning
      control.rs          ControlConnection, login handshake, ping
      proxy.rs            NewProxy message builder, local TCP connect, bridge
  frpc/                   Client binary
    Cargo.toml
    src/main.rs
  frps.toml               Example server config
  frpc.toml               Example client config
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

## Developing

```bash
# Build everything
cargo build

# Run tests
cargo test

# Lint
cargo clippy

# Start the server locally
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Start the client (in another terminal)
RUST_LOG=debug cargo run --bin frpc -- -c frpc.toml
```

---

## License

MIT. frp-rs is not affiliated with the original Go frp project.
