<div align="center">
  <h1>frp-rs</h1>
  <p><em>A fast reverse proxy written in Rust — protocol-compatible with frp.</em></p>
  <p>
    <a href="#overview">Overview</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#getting-started">Getting Started</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#protocol">Protocol</a> •
    <a href="#project-structure">Project Structure</a> •
    <a href="#frp-rs-核心优势">核心优势 (中文)</a>
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
| Dynamic auth tokenSource | ✅ | ✅     |
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
| Prometheus metrics   | ✅     | ✅     |
| Server config reload | —      | ✅     |
| Config directory mode| ✅     | ✅     |
| Client plugins       | ✅     | —      |
| Visitor (STCP/XTCP)  | ✅     | —      |
| Store (runtime config) | ✅   | ✅*    |
| VirtualNet (L3 VPN)  | ✅     | ✅     |

Client plugins: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`, `https2http`, `https2https`, `http2http`, `tls2raw`, `virtual_net`.

\* Store semantics differ: the client store (`store.path`) persists runtime proxy/visitor entries for admin API CRUD; the server store (`frps_store.json`) persists dashboard-created proxies.

### Go frp Compatibility Notes

frp-rs targets protocol compatibility with Go frp v0.70.1. The full Go frp
v0.70.1 cross-compatibility suite runs in CI (including the XTCP pairwise
matrix on VPS and V2 over the v0.70.1 pre-built binaries). Coverage is broad
but not literally 100% — see "Known limitations" below.

- **V1 wire protocol**: Fully compatible. All message types, authentication, encryption (AES-128-CFB),
  compression (Snappy) — wire-compatible with Go frp v0.70.1.
- **V2 wire protocol**: Full AEAD encryption + capability negotiation, verified against the
  Go frp v0.70.1 pre-built binary (V2 is included since v0.70.1).
- **All transports**: TCP, WebSocket, TLS, KCP, QUIC — full interop verified.
- **All 10 client plugins**: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`,
  `https2http`, `https2https`, `http2http`, `tls2raw`, `virtual_net`.
- **XTCP**: Cross-compat with Go frp (requires public internet for STUN/NAT probes).
  Both P2P data planes are supported — KCP+yamux (default) and QUIC
  (`protocol="quic"`, `quic` feature is default ON). Go visitors using the
  default `protocol="quic"` interoperate with Rust providers: Go frp v0.70.1
  sends the peer `"ip:port"` as the QUIC TLS SNI, which upstream rustls 0.23
  rejects as an invalid server name — frp-rs vendors rustls with a one-line
  server-side patch treating an invalid SNI as "no SNI" (equivalent to the
  upstream `invalid_sni_policy = IgnoreAll` added in rustls 0.24; see
  [audit note §6](docs/superpowers/notes/2026-08-04-mimalloc-throughput-ab.md);
  full plan + maintenance notes in
  [2026-08-04-xtcp-quic-sni-compat.md](docs/superpowers/notes/2026-08-04-xtcp-quic-sni-compat.md)).
  See [full audit](docs/go-frp-compat-audit.md) for details.

### Known limitations (as of frp-rs 0.7.1)

- **HTTP vhost reverse-proxy semantics**: frps forwards HTTP vhost traffic at
  the byte level (X-Forwarded-For and requestHeaders are injected, Host
  rewriting works). `responseHeaders` (ResponseHeaderInjector), per-request
  `vhost_http_timeout` 504s, and HTTP/2 cleartext (h2c) are implemented: h2c
  clients are decoded with the `h2` crate, forwarded to providers as plain
  HTTP/1.1, and backend HTTP/1.1 responses (including chunked bodies) are
  re-encoded as HTTP/2 — matching Go's `httputil.ReverseProxy` semantics.
- **HTTP plugin `enableHTTP2`**: honored on `https2http` / `https2https` (Go
  parity: defaults to true, advertises ALPN `h2` on the TLS listener; inbound
  h2 requests are decoded with the `h2` crate and forwarded to the backend as
  plain HTTP/1.1 — matching Go's `http.Server` + `httputil.ReverseProxy`
  semantics; `false` restricts the listener to HTTP/1.1). `http2http` /
  `http2https` are plaintext HTTP/1.1 only and have no such field (Go parity).
- **`pprof` endpoints**: `/debug/pprof/*` is a placeholder (no Go-style CPU
  profiles); `/healthz` and pprof are outside auth, matching Go.
- **UDP bandwidth limiting**: Go v0.70.1's UDP forwarder has no limiter, so
  frp-rs intentionally applies none either (parity, not a gap).
- **SSH gateway anonymity**: when no `authorized_keys` file and no server
  token are configured, the SSH tunnel gateway **fails to start** by default
  (fail-closed). Set `ssh_tunnel_gateway.allowNoneAuth = true` to explicitly
  accept anonymous connections (Go parity) on a trusted network; otherwise
  always set a token or `authorized_keys`.

### Why frp-rs?

**Smaller and lighter than Go frp.** Rust compiles to native code with no runtime, no GC, and aggressive size optimizations:

| Metric | Go frp v0.70.1 | frp-rs (default) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | ~14 MB | ~5.1 MB | ~3.0 MB | ~1.8 MB |
| frpc binary | ~12 MB | ~4.3 MB | ~2.6 MB | ~1.9 MB |
| Memory (idle) | ~8-12 MB | ~2-4 MB | ~1.5-3 MB | ~1-2 MB |

**Build sizes via feature flags.** Trim unused protocols and features to match your deployment. `frps`'s `default` feature set already enables every transport and the SSH gateway, so `default` and `full` produce the same binary — the only opt-in feature is `dashboard`:

- **default** (= full minus dashboard): TCP, WS, TLS, KCP, QUIC, OIDC auth, compression, XChaCha20 V2 encryption, HTTP proxy, TCP mux, vnet, and the SSH gateway.
- **full** (`--features "ssh,quic,dashboard"`): default + dashboard/metrics. (`ssh` and `quic` are redundant here — both are already on by default.)
- **`tiny`**: Drops QUIC, KCP, WebSocket, SSH, OIDC, dashboard, and compression. Keeps TLS and TCP mux (frps also keeps the HTTP proxy plugin). Ideal for edge devices.
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

### frp-rs 核心优势

**兼容性。** 完全兼容 Go frp v0.70.1 协议。所有传输层（TCP、WebSocket、TLS、KCP、QUIC）、全部代理类型（TCP/UDP/HTTP/HTTPS/STCP/XTCP/SUDP）、全部 10 种客户端插件（http_proxy、socks5、static_file、unix_domain_socket、http2https、https2http、https2https、http2http、tls2raw、virtual_net）均已通过跨兼容测试。CI 自动运行 68 项常规兼容性测试加 17 项 XTCP 两两矩阵测试（含 QUIC 数据面）。可直接替换 Go frps 或 Go frpc，配置文件、加密方式、认证机制完全一致，零迁移成本。

**体积。** 基于 Rust 原生编译，无运行时、无 GC。默认版本 frps 仅 ~5.1 MB，frpc ~4.3 MB（含 QUIC/KCP/SSH 等全部默认 feature），约为 Go frp 的 1/3。内存占用同样大幅降低：空闲状态下 ~2-4 MB，微核心版本（micro）仅 ~1-2 MB。无 GC 暂停保证负载下尾部延迟稳定。

**功能裁剪。** 四级构建体系，按需组合，适配从云端到嵌入式的全场景（QUIC/SSH 默认启用，dashboard 需显式启用）：

| 版本 | 体积 (frps/frpc) | 保留能力 | 适用场景 |
|------|-----------------|---------|---------|
| **default** | ~5.1MB / ~4.3MB | TCP/WS/TLS/KCP/QUIC、SSH、OIDC、压缩、XChaCha20、HTTP 代理、TCP mux、vnet | 通用部署 |
| **full** | ~5.3MB / ~4.3MB | default + dashboard（`--features "ssh,quic,dashboard"`，ssh/quic 已默认启用） | 全功能部署 |
| **tiny** | ~3.0MB / ~2.6MB | 去掉 QUIC/KCP/WebSocket/SSH/OIDC/dashboard，保留 TLS/TCP mux（frps 另保留 HTTP 代理） | 边缘设备、嵌入式 |
| **micro** | ~1.8MB / ~1.9MB | 仅核心 TCP 代理，无 TLS/压缩/HTTP 代理/TCP mux | 极小镜像、安全敏感 |

每个 feature 均可独立开关（frps 20 个、frpc 18 个编译期 feature flag），精细控制二进制内容。无需修改代码，Cargo feature 即按需裁剪。

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

## Getting Started

### Build

```bash
From the workspace root:

cargo build --release
```

The binaries land at `target/release/frps` and `target/release/frpc`.

### Binary Variants

Four size tiers (see [Why frp-rs?](#why-frp-rs) for sizes). SSH and QUIC are
enabled by default; dashboard is opt-in:

```bash
# Default — core transports + SSH + QUIC, no dashboard (~5.1 MB frps, ~4.3 MB frpc)
cargo build --release -p frps -p frpc

# Full — default + dashboard (~5.3 MB frps, ~4.3 MB frpc)
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"

# Tiny — no QUIC/KCP/WS/SSH/OIDC/dashboard/compression, keeps TLS+TCP mux (frps also HTTP proxy) (~3.0 MB / ~2.6 MB)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro — core only, no TLS/compression/chacha20/http-proxy/tcp-mux (~1.8 MB / ~1.9 MB)
cargo build --release -p frps -p frpc --no-default-features --features micro
```

Individual feature flags let you cherry-pick (dashboard is opt-in; QUIC, SSH
and the rest are default ON):

| Feature | Adds |
|---------|------|
| `ssh` | SSH gateway (russh) |
| `quic` | QUIC transport (quinn, ~1 MB) |
| `dashboard` | Metrics/status API (prometheus, axum) |
| `kcp` | KCP transport (in-tree, kcp-go compatible) |
| `websocket` | WebSocket transport |
| `oidc` | OIDC auth (jsonwebtoken, reqwest) |
| `tls` | TLS encryption (rustls) |
| `compression` | Snappy bridge compression |
| `chacha20` | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | HTTP proxy plugin |
| `tcp-mux` | yamux stream multiplexing (~80 KB) |
| `vnet` | L3 VPN / TUN device routing (frp-vnet) |
| `admin` | Admin REST API on frpc (axum) |
| `mem-profile` | Counting-allocator memory profiling (off in shipped builds) |
| `debug-logs` | Verbose debug logging for development |
| `otel` | OpenTelemetry tracing + OTLP export |

`tiny`/`micro` are binary-level profiles (`frps/Cargo.toml`, `frpc/Cargo.toml`) that select a fixed feature set; they build `frps-tiny`/`frpc-tiny`/`frps-micro`/`frpc-micro` binaries respectively.

`quic` implies `tls`; `oidc` implies `reqwest`; `ssh` implies `rand`.

### Quick Start

1. Start the server:

   ```bash
   ./target/release/frps -c frps.toml
   ```

   The example `frps.toml` binds `0.0.0.0:17000` (control + KCP, TLS enabled, token auth), with HTTP/HTTPS vhosts on 10080/10443 and the dashboard on 7500. Port 7000 appears only in the commented native-format block.

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
| `auth.authenticationTimeout` | `90` | Login timestamp freshness window in seconds (replay protection; `0` = disabled, Go frp default) |
| `ssh_tunnel_gateway.allowNoneAuth` | `false` | Allow the SSH gateway to start with no credentials, accepting every connection (fail-closed by default) |
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
| `transport.heartbeat_timeout` | `-1` | Heartbeat timeout in seconds; `-1` disables it under tcp_mux (Go v0.70.1 default) |
| `allow_port_start` | `1` | Start of auto-assigned port range |
| `allow_port_end` | `65535` | End of auto-assigned port range |
| `udp_packet_size` | `1500` | UDP packet buffer size in bytes |

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

Settings that require a restart: `bind_port`, `bind_addr`, the `tls_enable` switch, and OIDC settings. TLS certificate/key/CA **paths** are hot-reloaded (the TLS acceptor is rebuilt atomically).

### Management REST API

Both frps (dashboard) and frpc expose a management API over HTTP with Basic Auth.

**frps endpoints** (on dashboard port):
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Server status (version, uptime, client/proxy counts) |
| GET | `/api/serverinfo` | Server info (Go frp dashboard parity) |
| GET | `/api/proxies` | List all proxies with traffic stats |
| GET | `/api/proxies/{name}` | Proxy detail (alias: `/api/proxy/{type}/{name}`) |
| GET | `/api/proxy/{type}` | List proxies of one type |
| GET | `/api/proxy/{name}/traffic` | Proxy traffic counters |
| GET | `/api/clients` / `/api/clients/{run_id}` | Connected clients |
| GET | `/metrics` | Prometheus text format (if `enable_prometheus = true`) |

**frpc endpoints** (on admin port):
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Proxy status grouped by type |
| GET | `/api/metrics` | Prometheus text format |
| GET | `/api/config` | Current config (sensitive values redacted) |
| PUT | `/api/config` | Update config file + trigger reload |
| GET/POST | `/api/reload` | Reload proxies from config (strict mode via JSON body `{"strict_config": true}`) |
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
| `transport_protocol` | `"tcp"` | Transport: tcp, kcp, websocket/ws, wss, quic |
| `token` | `""` | Authentication token (must match server) |
| `auth.tokenSource` | — | Dynamic token source: `file://path` or `exec://command` (exec requires `TokenSourceExec` unsafe feature) |
| `user` | `""` | User identity for multi-tenant setups |
| `client_id` | `""` | Unique client identifier (auto-generated if empty) |
| `tls_enable` | `true` | Enable TLS |
| `tls_cert_file` | `""` | Client TLS certificate |
| `tls_key_file` | `""` | Client TLS private key |
| `tls_ca_file` | `""` | CA certificate for server verification |
| `tls_server_name` | `""` | Server name for TLS SNI |
| `log.level` | `"info"` | Log level |
| `login_fail_exit` | `true` | Exit on login failure; false to keep retrying |
| `pool_count` | `1` | Number of pre-established work connections (pooled on the server) |
| `tcp_mux` | `true` | Enable TCP multiplexing |
| `web_server.addr` | `"127.0.0.1"` | Admin API bind address |
| `web_server.port` | `0` | Admin API port (0 = disabled) |
| `web_server.user` | `""` | Admin API Basic Auth username |
| `web_server.password` | `""` | Admin API Basic Auth password |
| `heartbeat_interval` | `-1` | Ping interval in seconds; `-1` disables it under tcp_mux (Go v0.70.1 default) |
| `proxy_url` | `""` | Upstream HTTP/SOCKS5 proxy for control connection |
| `start` | `[]` | Selective proxy start: only start proxies named in this list |
| `includes` | `[]` | Glob patterns for additional config files to merge |
| `store.path` | `""` | JSON file for runtime proxy/visitor store (admin API CRUD); entries overlay config-file entries |
| `virtualNet.address` | `""` | Local TUN IPv4 address for the `virtual_net` proxy/visitor plugins (requires `[feature] VirtualNet = true`) |
| `metas` | `{}` | Client-level metadata sent in Login message |
| `dial_server_keepalive` | `7200` | TCP keepalive interval (seconds) for server connection |
| `connect_server_local_ip` | `""` | Local IP to bind when connecting to server |
| `disable_custom_tls_first_byte` | `true` | Skip Go frp TLS head byte (0x17) |
| `nat_hole_stun_server` | `"stun.easyvoip.com:3478"` | STUN server for NAT traversal |
| `dns_server` | `""` | Custom DNS server for resolving server address |

#### Latency tuning (`pool_count`)

`pool_count` pre-warms work connections on the server so they are ready
before a user connects. With `pool_count = 1` (the default, matching Go frp),
the first user connection pays a `ReqWorkConn` → `StartWorkConn` control
round-trip before the first byte can flow. A larger `pool_count`
absorbs that round-trip up front.

Measured connection-setup latency (64 B probe, 2000 samples, loopback):

| `pool_count` | setup p50 | setup p99 |
|--------------|-----------|-----------|
| `0` (cold)   | 251 µs    | 633 µs    |
| `4` (warm)   | 191 µs    | 372 µs    |

Warming the pool cut setup p50 by ~24% and p99 by ~41% on loopback.
Latency-sensitive deployments can raise `pool_count` further.

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
| `local_ip` | `"127.0.0.1"` | Local service IP |
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
| `health_check_interval_seconds` | `10` | Seconds between health checks (min 10) |
| `health_check_timeout_seconds` | `3` | Health check connect timeout (min 3) |
| `health_check_max_failed` | `1` | Consecutive failures before marking unhealthy (min 1) |
| `bandwidth_limit` | `""` | Bandwidth limit (e.g. "1MB"; only "KB"/"MB" suffixes, 1024-based) |
| `bandwidth_limit_mode` | `"client"` | Bandwidth limit mode (client/server) |
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

> **Rust-only types ('7', '8'):** These are frp-rs extensions not present in Go frp v0.70.1. Go frp treats unknown message types as errors. Only send on Rust↔Rust connections after capability negotiation. See `frp-core/src/msg.rs` for the payload structs.

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

Authentication uses **MD5(token + timestamp)** → hex string, matching Go frp v0.70.1:

```
privilege_key = hex(MD5(token + timestamp))
```

The server computes the expected key from its token and the timestamp sent in
the Login message, then compares directly.

### Encryption

When `use_encryption = true` on a proxy, data between frps and frpc is encrypted
with **AES-128-CFB**, matching Go frp v0.70.1. The encryption key (16 bytes) is
derived from the auth token via PBKDF2-SHA1:

```
encryption_key = PBKDF2(token, "frp", iterations=64, key_len=16, hash=SHA1)
```

### Compression

When `use_compression = true`, data is compressed with **Snappy** (matching Go frp
v0.70.1) before encryption. Compression is applied first, then encryption:

```
plaintext → Snappy compress → AES-128-CFB encrypt → [16-byte IV][ciphertext stream]
```

The encrypted bridge is a **streaming** CFB channel: the writer sends one random
16-byte IV before the first ciphertext block, then encrypts continuously with
shared cipher state (`CipherWriter`/`CipherReader` in `frp-core/src/cipher_stream.rs`) —
there is no per-frame length prefix. The reader consumes the IV on its first read.

- Supported for TCP proxies (both client and server bridge paths), XTCP P2P channels, and control connections.
- Note: Go frp v0.70.1 golib source says salt `"crypto"` but the pre-built binary uses `"frp"`. This codebase uses `"frp"` for binary compatibility.

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
      cli.rs              CLI argument parsing (shared by frps + frpc)
      admin_auth.rs       HTTP Basic Auth middleware (admin API / dashboard)
      auth.rs             MD5 token authentication + OIDC verification
      bridge.rs           Encrypted/compressed data bridge (streaming CFB)
      cipher_stream.rs    AES-128-CFB streaming encrypt/decrypt (CipherReader/CipherWriter)
      config.rs           TOML config structs + Go→Rust compat normalization
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
      quic.rs             QUIC transport wrapper
      transport.rs        TCP/TLS/WebSocket/KCP/QUIC dial + accept + IoStream abstraction
      xtcp_p2p.rs         XTCP MakeHole hole punching (Go frp semantics)
      stun.rs             STUN client for NAT traversal
      proxy_protocol.rs   HAProxy PROXY protocol header builder
      bandwidth.rs        Token-bucket bandwidth limiter
      buffer_pool.rs      Reusable bridge buffers (FRP_BRIDGE_BUF_KB)
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
    compat-test.sh         Go↔Rust cross-compatibility test suite (68 regular + 17 XTCP scenarios)
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

Pre-built Docker images are published to GitHub Container Registry. `:latest`
tracks release tags; pushes to `main` build the `:test` tag (and
`:testtiny`/`:testmicro` for the tiny/micro variants):

```bash
# Server (built from source)
docker pull ghcr.io/viogus/frps-rs:latest

# Client (built from source)
docker pull ghcr.io/viogus/frpc-rs:latest

docker run -d -p 7000:7000 -v $(pwd)/frps.toml:/app/frp.toml ghcr.io/viogus/frps-rs:latest
```

One Dockerfile variant in `docker/`:
- `Dockerfile.source` — builds from source via multi-stage Rust image (used for CI auto-builds); `docker/build.sh` is the alternative download-and-verify path

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
