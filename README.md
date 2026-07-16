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
| SUDP proxy (shared)  | ✅     | ✅     |
| TCPMux HTTP CONNECT  | ✅     | ✅     |
| HTTP/HTTPS proxy     | ✅     | ✅     |
| STCP / sk routing    | ✅     | ✅     |
| XTCP (NAT hole punch)| ✅     | ✅     |
| Token authentication | ✅     | ✅     |
| OIDC authentication  | ✅     | ✅     |
| Heartbeat (ping/pong)| ✅     | ✅     |
| Auto port allocation | —      | ✅     |
| Encryption (AES-128-CFB) | ✅  | ✅     |
| Compression (Snappy) | ✅     | ✅     |
| Bandwidth limiting   | ✅     | —      |
| TCP multiplexing (yamux) | ✅ | ✅     |
| WebSocket transport  | ✅     | ✅     |
| TLS transport        | ✅     | ✅     |
| QUIC transport       | ✅     | ✅     |
| KCP transport        | ✅     | ✅     |
| V2 wire protocol     | ✅     | ✅     |
| V1 wire protocol     | ✅     | ✅     |
| TCP health checks    | ✅     | —      |
| HTTP VHost routing   | —      | ✅     |
| HTTPS VHost routing  | —      | ✅     |
| Dashboard (web UI)   | —      | ✅     |
| Management REST API  | ✅     | ✅     |
| Prometheus metrics   | —      | ✅     |
| Server config reload | —      | ✅     |
| Config directory mode| ✅     | ✅     |
| Client plugins       | ✅     | —      |
| Visitor (STCP/XTCP)  | ✅     | —      |

Client plugins: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`, `https2http`, `https2https`, `http2http`, `tls2raw`.

### Go frp Compatibility Notes

frp-rs targets protocol compatibility with Go frp v0.70.0. **100% feature parity.**
73/73 cross-compatibility tests pass on every commit (including XTCP 16-test pairwise
matrix on VPS and V2 TCP source-built Go frp).

- **V1 wire protocol**: Fully compatible. All message types, authentication, encryption (AES-128-CFB),
  compression (Snappy) — wire-compatible with Go frp v0.69.1.
- **V2 wire protocol**: Full AEAD encryption + capability negotiation. Requires source-built Go frp
  with V2 patches (pre-built v0.69.1 binary does not include V2).
- **All transports**: TCP, WebSocket, TLS, KCP, QUIC — full interop verified.
- **All 9 client plugins**: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`,
  `https2http`, `https2https`, `http2http`, `tls2raw`.
- **XTCP**: Full cross-compat with Go frp (requires public internet for STUN/NAT probes).
  See [full audit](docs/go-frp-compat-audit.md) for details.

### Why frp-rs?

**Smaller and lighter than Go frp.** Rust compiles to native code with no runtime, no GC, and aggressive size optimizations:

| Metric | Go frp v0.69.1 | frp-rs (full) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|---------------|-----------------|-------------------|
| frps binary | ~14 MB | ~4.8 MB | ~2.7 MB | ~1.6 MB |
| frpc binary | ~12 MB | ~3.7 MB | ~2.3 MB | ~1.7 MB |
| Memory (idle) | ~8-12 MB | ~2-4 MB | ~1.5-3 MB | ~1-2 MB |

**Three build sizes via feature flags.** Trim unused protocols and features to match your deployment:

- **full** (default): All transports (TCP, WS, TLS, KCP, QUIC), SSH gateway, OIDC auth, dashboard, compression, XChaCha20 V2 encryption, HTTP proxy, TCP mux.
- **`tiny`**: Drops QUIC, KCP, WebSocket, SSH, OIDC, dashboard. Keeps TLS, compression, TCP mux. Ideal for edge devices.
- **`micro`**: Core only — no TLS, no compression, no chacha20, no HTTP proxy, no TCP mux. Minimal attack surface and footprint.

```bash
# Tiny build (no heavy protocols)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro build (core only)
cargo build --release -p frps -p frpc --no-default-features --features micro
```

**No GC pauses.** Rust's ownership model eliminates garbage collection — consistent tail latency under load, no stop-the-world spikes.

**Memory safety.** All protocol parsing, FEC encoding, and encryption run in safe Rust. No buffer overflows, no use-after-free, no null pointer derefs at the wire boundary.

**Go frp wire compatible.** Drop `frps` in place of Go frps, `frpc` in place of Go frpc. Same config files, same protocol, same encryption. Zero migration cost.

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

### Binary Variants

Three size tiers (see [Why frp-rs?](#why-frp-rs) for sizes):

```bash
# Full — all features (~4.8 MB frps, ~3.7 MB frpc)
cargo build --release -p frps -p frpc

# Tiny — no QUIC/KCP/WS/SSH/OIDC/dashboard, keeps TLS (~2.7 MB / ~2.3 MB)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro — core only, no TLS/compression/chacha20/http-proxy/tcp-mux (~1.6 MB / ~1.7 MB)
cargo build --release -p frps -p frpc --no-default-features --features micro
```

Individual feature flags (all default ON) let you cherry-pick:

| Feature | Removes |
|---------|---------|
| `quic` | QUIC transport (quinn, ~1 MB) |
| `kcp` | KCP transport |
| `websocket` | WebSocket transport |
| `oidc` | OIDC auth (jsonwebtoken, reqwest) |
| `ssh` | SSH gateway (russh) |
| `dashboard` | Metrics/status API (prometheus, axum) |
| `tls` | TLS encryption (rustls) |
| `compression` | Snappy bridge compression |
| `chacha20` | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | HTTP proxy plugin |
| `tcp-mux` | yamux stream multiplexing (~80 KB) |

`quic` implies `tls`; `oidc` implies `reqwest`; `ssh` implies `rand`.

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
| `tcpmux_httpconnect_port` | `0` | TCPMux HTTP CONNECT port (0 = disabled) |
| `kcp_bind_port` | `0` | KCP port (0 = disabled) |
| `quic_bind_port` | `0` | QUIC port (0 = disabled) |
| `websocket_port` | `0` | WebSocket listener port (0 = disabled) |
| `sub_domain_host` | `""` | Host for sub-domain proxy support |
| `sudp_port` | `0` | Shared port for all SUDP proxies (0 = per-proxy ports) |
| `tls_enable` | `false` | Enable TLS on the listener |
| `tls_only` | `false` | Reject non-TLS connections |
| `tls_cert_file` | `""` | Path to TLS certificate |
| `tls_key_file` | `""` | Path to TLS private key |
| `tls_ca_file` | `""` | CA certificate for mutual TLS |
| `auth.method` | `"token"` | Authentication method (token or oidc) |
| `auth.token` | `""` | Shared authentication token |
| `log.level` | `"info"` | Log level: trace, debug, info, warn, error |
| `log.file` | `""` | Log file path (empty = stderr) |
| `log.max_days` | `3` | Max days to retain log files |
| `web_server.port` | `0` | Dashboard port (0 = disabled) |
| `web_server.user` | `""` | Dashboard Basic Auth username |
| `web_server.password` | `""` | Dashboard Basic Auth password |
| `web_server.enable_prometheus` | `false` | Expose /metrics for Prometheus scraping |
| `web_server.tls_cert_file` | `""` | Dashboard TLS certificate path |
| `web_server.tls_key_file` | `""` | Dashboard TLS private key path |
| `transport.tcp_mux` | `true` | Enable TCP multiplexing |
| `transport.tcp_mux_keepalive_interval` | `30` | Keepalive interval (seconds) for mux |
| `transport.heartbeat_timeout` | `90` | Heartbeat timeout in seconds (server disconnects if no ping) |
| `allow_port_start` | `10000` | Start of auto-assigned port range |
| `allow_port_end` | `50000` | End of auto-assigned port range |
| `udp_packet_size` | `65535` | UDP packet buffer size in bytes |

### Logging

Log level resolves in this order (first match wins):

1. **`RUST_LOG` env var** — overrides everything, accepts full [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax (e.g. `RUST_LOG=frp_server=debug,info`).
2. **`log.level` config** (or `--log-level` CLI flag) — one of `trace, debug, info, warn, error`.
3. Default: `info`.

Per-connection events (`Bridging user conn…`, `bridge completed`) log at **`debug`**, not `info` — a busy proxy would otherwise flood the default output with a line per connection. Enable them with `RUST_LOG=debug` or `log.level = "debug"`.

### Server Reload (SIGUSR1)

Send `SIGUSR1` to the frps process to hot-reload these settings from the config file:
- `auth.token` — updates encryption key and accepts new token for future logins
- `allow_ports` / `allow_port_start` / `allow_port_end` — adjusts port allocation range

Settings that require a restart: `bind_port`, `bind_addr`, TLS settings, OIDC settings.

### Management REST API

Both frps (dashboard) and frpc expose a management API over HTTP with Basic Auth.

**frps endpoints** (on dashboard port):
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Server status (version, uptime, client/proxy counts) |
| GET | `/api/proxies` | List all proxies with traffic stats |
| GET | `/api/proxy/:name` | Proxy detail |
| GET | `/api/proxy/:name/traffic` | Proxy traffic counters |
| GET | `/metrics` | Prometheus text format (if `enable_prometheus = true`) |

**frpc endpoints** (on admin port):
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Proxy status grouped by type |
| GET | `/api/config` | Current config (sensitive values redacted) |
| PUT | `/api/config` | Update config file + trigger reload |
| GET | `/api/reload?strictConfig=true` | Reload proxies from config |
| POST | `/api/stop` | Gracefully stop the client |

### Client (`frpc.toml`)

```toml
server_addr = "127.0.0.1"
server_port = 7000
token = "my-frp-token"
transport_protocol = "tcp"
tcp_mux = true
pool_count = 1
login_fail_exit = false

[web_server]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "admin"

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
| `web_server.addr` | `"127.0.0.1"` | Admin API bind address |
| `web_server.port` | `0` | Admin API port (0 = disabled) |
| `web_server.user` | `""` | Admin API Basic Auth username |
| `web_server.password` | `""` | Admin API Basic Auth password |
| `heartbeat_interval` | `30` | Ping interval in seconds |
| `proxy_url` | `""` | Upstream HTTP/SOCKS5 proxy for control connection |
| `start` | `[]` | Selective proxy start: only start proxies named in this list |
| `includes` | `[]` | Glob patterns for additional config files to merge |
| `metas` | `{}` | Client-level metadata sent in Login message |
| `dial_server_keepalive` | `0` | TCP keepalive interval (seconds) for server connection |
| `connect_server_local_ip` | `""` | Local IP to bind when connecting to server |
| `disable_custom_tls_first_byte` | `false` | Skip Go frp TLS head byte (0x17) |
| `nat_hole_stun_server` | `""` | Custom STUN server for NAT traversal |
| `dns_server` | `""` | Custom DNS server for resolving server address |

#### Latency tuning (`pool_count`)

`pool_count` pre-warms work connections on the server so they are ready
before a user connects. With `pool_count = 0` (the default, matching Go frp),
each new user connection first pays a `ReqWorkConn` → `StartWorkConn` control
round-trip before the first byte can flow. A small positive `pool_count`
absorbs that round-trip up front.

Measured connection-setup latency (64 B probe, 2000 samples, loopback):

| `pool_count` | setup p50 | setup p99 |
|--------------|-----------|-----------|
| `0` (cold)   | 251 µs    | 633 µs    |
| `4` (warm)   | 191 µs    | 372 µs    |

Warming the pool cut setup p50 by ~24% and p99 by ~41% on loopback. The
default stays at `0` for Go frp parity and to avoid holding idle connections;
latency-sensitive deployments should set `pool_count` to a small positive
value.

`TCP_NODELAY` is enabled on every data-path TCP connection automatically
(matching Go frp), so small request/response and interactive traffic is not
delayed by Nagle's algorithm — no configuration needed.

For memory-constrained or high-fan-out servers, the per-connection bridge
buffer defaults to 32 KiB (matching Go frp) and can be tuned via the
`FRP_BRIDGE_BUF_KB` environment variable (range 4–1024).

#### Proxy entries (`[[proxies]]`)

| Field | Default | Description |
|-------|---------|-------------|
| `name` | — | Unique proxy name |
| `type` | — | Proxy type: tcp, udp, http, https, stcp, xtcp, tcpmux |
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
| `proxy_protocol_version` | `""` | HAProxy PROXY protocol: "v1", "v2", or "" (disabled) |
| `health_check_http_headers` | `{}` | Custom HTTP headers for health check requests |
| `response_headers` | `{}` | Custom HTTP response headers injected by the server |
| `enabled` | `true` | Whether the proxy is active (false = skipped at startup) |
| `metas` | `{}` | Key-value metadata sent to server plugins |
| `plugin` | — | Per-proxy client plugin configuration |

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
| 'v'       | NewVisitorConn  | Client to Server | STCP/XTCP visitor connection |
| '3'       | NewVisitorConnResp | Server to Client | Visitor connection result |
| 'i'       | NatHoleVisitor  | Client to Server | NAT hole punch visitor |
| 'n'       | NatHoleClient   | Client to Server | NAT hole punch client (STUN candidates) |
| 'm'       | NatHoleResp     | Server to Client | NAT hole punch response (peer candidates) |
| '5'       | NatHoleSid      | Server to Client | NAT hole SID assignment |
| '6'       | NatHoleReport   | Client to Server | NAT hole detection report |
| '7'       | CloseProxyResp  | Server to Client | **Rust-only** — proxy close acknowledgment |
| '8'       | Error           | Server to Client | **Rust-only** — protocol error message |

> **Rust-only types ('7', '8'):** These are frp-rs extensions not present in Go frp v0.70.0. Go frp treats unknown message types as errors. Only send on Rust↔Rust connections after capability negotiation. See `frp-core/src/msg.rs` for the payload structs.

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
encryption_key = PBKDF2(token, "frp", iterations=64, key_len=16, hash=SHA1)
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

- Supported for TCP proxies (both client and server bridge paths) and control connections.
- Note: Go frp v0.69.1 golib source says salt `"crypto"` but the pre-built binary uses `"frp"`. This codebase uses `"frp"` for binary compatibility.

## Documentation

- **[Configuration Reference](docs/config.md)** — Every config field with types, defaults, and Go frp equivalents
- **[Proxy Type Guide](docs/proxies.md)** — When and how to use each proxy type (TCP, UDP, HTTP, STCP, XTCP, etc.)
- **[Client Plugins](docs/client-plugins.md)** — HTTP proxy, SOCKS5, static file, TLS termination, and more
- **[Deployment Guide](docs/deployment.md)** — Systemd, Docker, TLS, monitoring, performance tuning
- **[Developer Guide](docs/developing.md)** — Architecture deep-dive, debugging, testing, release process

## Project Structure


```
frp-rs/
  Cargo.toml              Workspace manifest
  frp-core/               Shared library
    Cargo.toml
    src/
      lib.rs              Error types, Result, VERSION
      args.rs             CLI argument parsing (shared by frps + frpc)
      admin_auth.rs       HTTP Basic Auth middleware (admin API / dashboard)
      auth.rs             MD5 token authentication + OIDC verification
      bridge.rs           Encrypted data bridge (AES-128-CFB framed)
      cipher_stream.rs    AES-128-CFB streaming encrypt/decrypt
      config.rs           TOML config structs + Go→Rust compat normalization
      encryption.rs       Key derivation (PBKDF2-SHA1) + Snappy compression
      kcp.rs              KCP transport wrapper
      metrics.rs          ProxyMetricsRegistry + ConnGuard (per-proxy counters)
      msg.rs              Wire protocol message structs
      mux.rs              TCP multiplexing (yamux)
      protocol.rs         V1/V2 frame read/write
      quic.rs             QUIC transport wrapper
      transport.rs        TCP/TLS/WebSocket dial + accept + IoStream abstraction
      v1_compat.rs        Go frp v0.69.1 compatibility helpers
  frp-server/             Server library
    Cargo.toml
    src/
      lib.rs
      service.rs          AppState, InternalMsg, accept loop, reload
      control/
        mod.rs            Per-client control handler, work pool, select loop
        bridge.rs         Encrypted/plain bridge (+ proxy auth)
        proxy_ops.rs      NewProxy/CloseProxy handler, listen_and_proxy
      proxy.rs            ProxyManager, ProxyInfo, port allocation
      vhost.rs            HTTP/HTTPS VHost routing + Host header parsing
      tcpmux.rs           TCPMux HTTP CONNECT domain routing
      dashboard.rs        Dashboard web UI + REST API
      dashboard.html      Dashboard HTML template (embedded via include_str!)
      metrics/
        mod.rs            Metrics module root
        prom.rs           Prometheus gauge registry + /metrics rendering
      nathole/            XTCP NAT hole punch coordinator (controller, classify, analysis)
  frps/                   Server binary
    Cargo.toml
    src/main.rs
  frp-client/             Client library
    Cargo.toml
    src/
      lib.rs
      admin.rs            Admin REST API server (status, config, reload, stop)
      service.rs          Login, proxy registration, message/select loop,
                          work connection spawning, health checks, UDP work conns
      control.rs          ControlConnection, login handshake, hostname resolution
      plugin/
        mod.rs            Plugin dispatch
        http.rs           HTTP proxy plugin
        socks5.rs         SOCKS5 proxy plugin
        static_file.rs    Static file serving plugin
      proxy.rs            NewProxy message builder, local TCP connect, bridge
  frpc/                   Client binary
    Cargo.toml
    src/main.rs
  docker/                 Docker build infrastructure
    Dockerfile             Multi-stage image (downloads release binary)
    Dockerfile.source      Multi-stage image (builds from Rust source)
    build.sh               Release binary download + verification script
    entrypoint.c           Minimal static entrypoint (FRP_MODE, conf path)
    README.md              Docker build documentation
  scripts/
    compat-test.sh         Go↔Rust cross-compatibility test suite (39 tests, 5 guarded)
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

One Dockerfile variant in `docker/`:
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
cargo run --bin frps -- -c frps.toml

# Start the client (in another terminal)
cargo run --bin frpc -- -c frpc.toml

# Enable debug logging for development
cargo run --features debug-logs --bin frps -- -c frps.toml
RUST_LOG=debug cargo run --bin frps -- -c frps.toml  # or via env var

# Run multiple services from a config directory
cargo run --bin frps -- --config-dir /etc/frp/conf.d

# Build Docker image locally
docker build -f docker/Dockerfile.source --build-arg FRP_COMPONENT=frps -t frps-rs:local .

# Run Go↔Rust cross-compatibility tests
bash scripts/compat-test.sh            # all tests
bash scripts/compat-test.sh tcp g2r    # specific filter: TCP, Go→Rust direction
```

---

## License

MIT. frp-rs is not affiliated with the original Go frp project.
