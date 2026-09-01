<div align="center">
  <h1>frp-rs</h1>
  <p><em>A fast reverse proxy written in Rust — protocol-compatible with frp.</em></p>
  <p>
    <a href="#overview">Overview</a> •
    <a href="#features--usage">Features &amp; Usage</a> •
    <a href="#deployment">Deployment</a> •
    <a href="#technical-differences-vs-go-frp">Technical Differences</a> •
    <a href="#documentation">Documentation</a> •
    <a href="#developing">Developing</a>
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
| Bandwidth limiting   | ✅     | ✅     |
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
| Visitor (STCP/XTCP/SUDP) | ✅     | —      |
| Store (runtime config) | ✅   | ✅*    |
| VirtualNet (L3 VPN)  | ✅     | ✅     |

Client plugins: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`, `https2http`, `https2https`, `http2http`, `tls2raw`, `virtual_net`.

\* Store semantics differ: the client store (`store.path`) persists runtime proxy/visitor entries for admin API CRUD; the server store (`frps_store.json`) persists dashboard-created proxies.

### Go frp Compatibility Notes

frp-rs targets protocol compatibility with Go frp v0.71.0. The full Go frp
v0.71.0 cross-compatibility suite runs in CI (including the XTCP pairwise
matrix on VPS and V2 over the v0.71.0 pre-built binaries). Coverage is broad
but not literally 100% — see "Known limitations" below.

- **V1 wire protocol**: Fully compatible. All message types, authentication, encryption (AES-128-CFB),
  compression (Snappy) — wire-compatible with Go frp v0.71.0.
- **V2 wire protocol**: Full AEAD encryption + capability negotiation, verified against the
  Go frp v0.71.0 pre-built binary (V2 is included since v0.71.0).
- **All transports**: TCP, WebSocket, TLS, KCP, QUIC — full interop verified.
- **All 10 client plugins**: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`,
  `https2http`, `https2https`, `http2http`, `tls2raw`, `virtual_net`.
- **XTCP**: Cross-compat with Go frp (requires public internet for STUN/NAT probes).
  Both P2P data planes are supported — KCP+yamux (default) and QUIC
  (`protocol="quic"`, `quic` feature is default ON). Go visitors using the
  default `protocol="quic"` interoperate with Rust providers: Go frp v0.71.0
  sends the peer `"ip:port"` as the QUIC TLS SNI, which upstream rustls 0.23
  rejects as an invalid server name — frp-rs vendors rustls with a one-line
  server-side patch treating an invalid SNI as "no SNI" (equivalent to the
  upstream `invalid_sni_policy = IgnoreAll` added in rustls 0.24; see
  [audit note §6](docs/superpowers/notes/2026-08-04-mimalloc-throughput-ab.md);
  full plan + maintenance notes in
  [2026-08-04-xtcp-quic-sni-compat.md](docs/superpowers/notes/2026-08-04-xtcp-quic-sni-compat.md)).
  See [full audit](docs/go-frp-compat-audit.md) for details.

### Known limitations (as of frp-rs 0.71.0)

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
- **UDP bandwidth limiting**: frp-rs extension — Go v0.71.0's UDP forwarder
  has no limiter. `bandwidthLimit` / `bandwidthLimitMode` now throttle the
  UDP data plane too, with the same direction semantics as the TCP bridge
  ("server" limits both directions on frps; "client" limits upload on frpc;
  "both" is enforced on the client only — the server does not recognize it,
  same as TCP). Default stays unlimited: a limiter is only active when a
  rate is explicitly configured.
- **SSH gateway anonymity**: when no `authorized_keys` file and no server
  token are configured, the SSH tunnel gateway **fails to start** by default
  (fail-closed). Set `ssh_tunnel_gateway.allowNoneAuth = true` to explicitly
  accept anonymous connections (Go parity) on a trusted network; otherwise
  always set a token or `authorized_keys`.
- **Windows vnet (TUN)**: the `vnet` (L3 VPN) feature runs on Linux and macOS
  only — Windows TUN is a stub (`frp-vnet/src/tun_windows.rs`), every op
  errors out, pending a Wintun (`wintun.dll`) integration. Not a Go-compat
  gap; Go frp's vnet is Linux-focused too.

## Features & Usage

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

### Build

```bash
From the workspace root:

cargo build --release
```

The binaries land at `target/release/frps` and `target/release/frpc`.

### Binary Variants

Four size tiers (see [Technical Differences](#technical-differences-vs-go-frp) for sizes). SSH and QUIC are
enabled by default; dashboard is opt-in:

```bash
# Default — core transports + SSH + QUIC, no dashboard (~5.3 MB frps, ~4.5 MB frpc)
cargo build --release -p frps -p frpc

# Full — default + dashboard (~5.7 MB frps, ~4.5 MB frpc)
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"

# Tiny — no QUIC/KCP/WS/SSH/OIDC/dashboard/compression, keeps TLS+TCP mux (frps also HTTP proxy) (~3.3 MB / ~3.2 MB)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro — core only, no TLS/compression/chacha20/http-proxy/tcp-mux (~2.3 MB / ~2.2 MB)
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
| `oidc` | OIDC auth (jsonwebtoken, hyper/hyper-rustls via `http-client`) |
| `tls` | TLS encryption (rustls) |
| `compression` | Snappy bridge compression |
| `chacha20` | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | HTTP proxy plugin |
| `tcp-mux` | yamux stream multiplexing (~80 KB) |
| `vnet` | L3 VPN / TUN device routing (frp-vnet) |
| `admin` | Admin REST API on frpc (axum) — **opt-in** (was default; build `--features admin`) |
| `mem-profile` | Counting-allocator memory profiling (off in shipped builds) |
| `debug-logs` | Verbose debug logging for development |
| `otel` | OpenTelemetry tracing + OTLP export |

`tiny`/`micro` are binary-level profiles (`frps/Cargo.toml`, `frpc/Cargo.toml`) that select a fixed feature set; they build `frps-tiny`/`frpc-tiny`/`frps-micro`/`frpc-micro` binaries respectively.

`quic` implies `tls`; `oidc` implies `http-client` (hyper); `ssh` implies `rand`.

### Configuration

#### Server (frps.toml)

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
| `auth.oidc.issuer` | `""` | OIDC issuer URL (server side: discovery + JWKS for token verification) |
| `auth.oidc.audience` | `""` | OIDC `aud` claim required on tokens (empty = audience check skipped) |
| `ssh_tunnel_gateway.allowNoneAuth` | `false` | Allow the SSH gateway to start with no credentials, accepting every connection (fail-closed by default) |
| `log.level` | `"info"` | Log level: trace, debug, info, warn, error |
| `log.file` | `""` | Log file path (empty = stderr) |
| `log.max_days` | `3` | Max days to retain log files (mtime-based cleanup at startup + daily; `<= 0` disables) |
| `log.format` | `"text"` | Log format: `text` or `json` (CLI `--log-format` overrides) |
| `web_server.port` | `0` | Dashboard port (0 = disabled) |
| `web_server.user` | `""` | Dashboard Basic Auth username |
| `web_server.password` | `""` | Dashboard Basic Auth password |
| `web_server.enable_prometheus` | `false` | Expose /metrics for Prometheus scraping |
| `web_server.tls_cert_file` | `""` | Dashboard TLS certificate path |
| `web_server.tls_key_file` | `""` | Dashboard TLS private key path |
| `web_server.assets_dir` | `""` | Custom dashboard `index.html` directory (read once at startup; empty = built-in page) |
| `transport.tcp_mux` | `true` | Enable TCP multiplexing |
| `transport.tcp_mux_keepalive_interval` | `30` | Keepalive interval (seconds) for mux |
| `transport.heartbeat_timeout` | `-1` | Heartbeat timeout in seconds; `-1` disables it under tcp_mux (Go v0.71.0 default) |
| `allow_port_start` | `1` | Start of auto-assigned port range |
| `allow_port_end` | `65535` | End of auto-assigned port range |
| `udp_packet_size` | `1500` | UDP packet buffer size in bytes |

#### Client (frpc.toml)

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
| `log.format` | `"text"` | Log format: `text` or `json` (CLI `--log-format` overrides) |
| `login_fail_exit` | `true` | Exit on login failure; false to keep retrying |
| `pool_count` | `1` | Number of pre-established work connections (pooled on the server) |
| `tcp_mux` | `true` | Enable TCP multiplexing |
| `web_server.addr` | `"127.0.0.1"` | Admin API bind address |
| `web_server.port` | `0` | Admin API port (0 = disabled) |
| `web_server.user` | `""` | Admin API Basic Auth username |
| `web_server.password` | `""` | Admin API Basic Auth password |
| `heartbeat_interval` | `-1` | Ping interval in seconds; `-1` disables it under tcp_mux (Go v0.71.0 default) |
| `proxy_url` | `""` | Upstream HTTP/SOCKS5 proxy for control connection |
| `auth.oidc.proxyURL` | `""` | OIDC token/discovery HTTP proxy (HTTP CONNECT or SOCKS5; Go frp `proxyURL` compat) |
| `start` | `[]` | Selective proxy start: only start proxies named in this list |
| `includes` | `[]` | Glob patterns for additional config files to merge |
| `store.path` | `""` | JSON file for runtime proxy/visitor store (admin API CRUD); entries overlay config-file entries |
| `virtualNet.address` | `""` | Local TUN IPv4 address for the `virtual_net` proxy/visitor plugins (requires `[feature] VirtualNet = true`) |
| `metas` | `{}` | Client-level metadata sent in Login message |
| `dial_server_keepalive` | `300` | TCP keepalive idle time (seconds) for server connection; `0` disables. A short probe interval + 3 retries are also set so dead peers are reclaimed quickly (see `docs/config.md`). |
| `connect_server_local_ip` | `""` | Local IP to bind when connecting to server |
| `disable_custom_tls_first_byte` | `true` | Skip Go frp TLS head byte (0x17) |
| `nat_hole_stun_server` | `"stun.easyvoip.com:3478"` | STUN server for NAT traversal |
| `dns_server` | `""` | Custom DNS server for resolving server address |

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

#### Logging

Log level resolves in this order (first match wins):

1. **`RUST_LOG` env var** — overrides everything, accepts full [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax (e.g. `RUST_LOG=frp_server=debug,info`).
2. **`log.level` config** (or `--log-level` CLI flag) — one of `trace, debug, info, warn, error`.
3. Default: `info`.

Per-connection events (`Bridging user conn…`, `bridge completed`) log at **`debug`**, not `info` — a busy proxy would otherwise flood the default output with a line per connection. Enable them with `RUST_LOG=debug` or `log.level = "debug"`.

#### Management REST API

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
| GET | `/api/v2/config` | Sanitized server config (auth/dashboard secrets omitted) |
| PUT | `/api/v2/proxy/{name}/update` | Hot-update a live proxy's `bandwidthLimit` / `bandwidthLimitMode` (provider-dependent fields → 400) |
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

---

## Deployment

### Deployment Guide

The full deployment reference lives in [docs/deployment.md](docs/deployment.md) —
systemd units, Docker, TLS, monitoring, and performance tuning. Key operational
sections below are kept inline for quick reference.

### Docker

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

### Server Reload (SIGUSR1)

Send `SIGUSR1` to the frps process to hot-reload these settings from the config file:
- `auth.token` — updates encryption key and accepts new token for future logins
- `allow_ports` / `allow_port_start` / `allow_port_end` — adjusts port allocation range

Settings that require a restart: `bind_port`, `bind_addr`, the `tls_enable` switch, and OIDC settings. TLS certificate/key/CA **paths** are hot-reloaded (the TLS acceptor is rebuilt atomically).

### Latency tuning (`pool_count`)

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

---

## Technical Differences vs Go frp

### Why frp-rs?

**Smaller and lighter than Go frp.** Rust compiles to native code with no runtime, no GC, and aggressive size optimizations:

| Metric | Go frp v0.71.0 | frp-rs (default) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | ~14 MB | ~5.3 MB | ~3.3 MB | ~2.3 MB |
| frpc binary | ~12 MB | ~4.5 MB | ~3.2 MB | ~2.2 MB |
| Memory (idle) | ~8-12 MB | ~2-4 MB | ~1.5-3 MB | ~1-2 MB |

> Binary sizes measured 2026-08-08 (macOS arm64) with the **declared release profile** (`fat-LTO`, `opt-level=z`, `strip = true`, `panic=abort`). Local/CI dev builds override LTO/opt (`lto=false opt-level=2` for build speed) and come out ~70% larger (measured 2026-08-09: 9.1MB vs 5.3MB) — they do not reflect release artifacts.

**Build sizes via feature flags.** Trim unused protocols and features to match your deployment. `frps`'s `default` feature set already enables every transport and the SSH gateway (the Cargo `full` feature is identical to `default`); opt-in features are `dashboard`, `vnet`, `mimalloc`, `otel`, and the dev-only profiling flags:

- **default** (= Cargo `full`, no dashboard): TCP, WS, TLS, KCP, QUIC, OIDC auth, compression, XChaCha20 V2 encryption, HTTP proxy, TCP mux, and the SSH gateway.
- **dashboard build** (`--features "ssh,quic,dashboard"`): default + dashboard/metrics. (`ssh` and `quic` are redundant here — both are already on by default.)
- **vnet** (`--features vnet`): adds L3 VPN / TUN device routing (frp-vnet; opt-in, not in default binaries).
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

**协议兼容。** 完全兼容 Go frp v0.71.0 协议。所有传输层（TCP、WebSocket、TLS、KCP、QUIC）、全部代理类型（TCP/UDP/HTTP/HTTPS/STCP/XTCP/SUDP）、全部 10 种客户端插件（http_proxy、socks5、static_file、unix_domain_socket、http2https、https2http、https2https、http2http、tls2raw、virtual_net）均已通过跨兼容测试。CI 自动运行 86 项常规兼容性测试加 17 项 XTCP 两两矩阵测试（含 QUIC 数据面）。可直接替换 Go frps 或 Go frpc，配置文件、加密方式、认证机制完全一致，零迁移成本。

**体积与内存。** 基于 Rust 原生编译，无运行时、无 GC。默认版本 frps 仅 ~5.3 MB，frpc ~4.5 MB（含 QUIC/KCP/SSH 等全部默认 feature，声明 release profile 实测），约为 Go frp 的 1/3，且仍在持续收缩（`strip=true` + fat-LTO + `opt-level=z`）。内存占用同样大幅降低：空闲状态下 ~2-4 MB，微核心版本（micro）仅 ~1-2 MB。无 GC 暂停保证负载下尾部延迟稳定。

**性能工程（多轮审计实证）。** 热路径经过三轮独立审计与交叉验证，数据面干净利落：

- **零拷贝中继**：Linux 上 TCP 桥接使用 `splice(2)` 零拷贝；跨平台回退 `copy_bidirectional_with_sizes` 32 KiB 缓冲
- **热路径零分配**：无锁缓冲池（RAII `PoolGuard` 复用）、CFB 批量 u128 XOR 加密、压缩缓冲复用——每迭代零堆分配
- **无锁并发**：控制通道由单 writer 任务汇聚（bounded mpsc，慢对端不阻塞任何生产者）、代理注册表用 DashMap 无锁读、accept 限速器为 AtomicU64 令牌桶——全部锁竞争已消除
- **优雅关闭**：SIGINT/SIGTERM 均触发连接排空（graceful drain），活跃连接有界等待后干净退出，不丢数据
- **连接防御**：VHost/TCPMux 等所有 accept 路径均有并发上限 + 速率限制，死连接由 TCP keepalive 及时回收

**安全。** 网络数据解析全部边界检查后才索引（协议层无 panic 向量）；热路径零 `unwrap`/`expect`；所有 `unsafe` 块均带 `// SAFETY:` 注释且可逐一审计；多轮安全审计零 P0/P1 残留。

**功能裁剪。** 四级构建体系，按需组合，适配从云端到嵌入式的全场景（QUIC/SSH 默认启用，dashboard 需显式启用）：

| 版本 | 体积 (frps/frpc) | 保留能力 | 适用场景 |
|------|-----------------|---------|---------|
| **default** | ~5.3MB / ~4.5MB | TCP/WS/TLS/KCP/QUIC、SSH、OIDC、压缩、XChaCha20、HTTP 代理、TCP mux | 通用部署 |
| **full** | ~5.7MB / ~4.5MB | default + dashboard（`--features dashboard`；ssh/quic 等其余能力已在 default 内）；L3 VPN / TUN 路由可再叠加 `--features vnet` | 全功能部署 |
| **tiny** | ~3.3MB / ~3.2MB | 去掉 QUIC/KCP/WebSocket/SSH/OIDC/dashboard，保留 TLS/TCP mux（frps 另保留 HTTP 代理；frpc 的 h2 支持也独立为 `http2http` feature） | 边缘设备、嵌入式 |
| **micro** | ~2.3MB / ~2.2MB | 仅核心 TCP 代理，无 TLS/压缩/HTTP 代理/TCP mux | 极小镜像、安全敏感 |

每个 feature 均可独立开关（frps 21 个、frpc 20 个编译期 feature flag），精细控制二进制内容。无需修改代码，Cargo feature 即按需裁剪。

#### Feature 归属一览

**frps（21 个）** — `default` 已启用：`websocket` `kcp` `quic` `oidc` `tls` `http-proxy` `compression` `chacha20` `tcp-mux` `ssh`；opt-in：`dashboard`（指标/状态 API）、`vnet`（L3 VPN / TUN 路由）、`mimalloc`（全局分配器）、`otel`（遥测）；dev-only（不进入 shipped 构建）：`debug-logs` `mem-profile` `profiling`；组合别名：`default` `full`（= frp-server 默认）、`tiny`（tls+http-proxy+tcp-mux）、`micro`（仅 TCP 核心）。

**frpc（20 个）** — `default` 已启用：`tls` `kcp` `quic` `websocket` `oidc` `compression` `chacha20` `tcp-mux` `http2http`；opt-in：`vnet`、`admin`（frpc 管理 API）、`mimalloc`、`otel`；dev-only：`debug-logs` `mem-profile` `profiling`；组合别名：`default` `full`（= frp-client 默认）、`tiny`（tls+tcp-mux）、`micro`。

**隐含关系**：
- 底层 crate 通过二进制的 feature 转发裁剪：frp-core 默认虽含 `vnet`/`stun`，但 frps/frpc 以 `default-features = false` 引用，因此**默认二进制不含 vnet**（opt-in）
- `http2http`（frpc/frp-client）独立控制 h2 插件，**隐含 `tls`**，tiny 构建不含
- 共享内部 feature：`http-client`（被 `oidc`/`http-proxy` 依赖）、`admin-auth`（被 `dashboard`/`admin` 依赖）
- dev-only 三个 feature 在全部 shipped 构建（full/tiny/micro）中关闭，生产二进制字节一致

---

## Documentation

- **[Configuration Reference](docs/config.md)** — Every config field with types, defaults, and Go frp equivalents
- **[Proxy Type Guide](docs/proxies.md)** — When and how to use each proxy type (TCP, UDP, HTTP, STCP, XTCP, etc.)
- **[Client Plugins](docs/client-plugins.md)** — HTTP proxy, SOCKS5, static file, TLS termination, and more
- **[Deployment Guide](docs/deployment.md)** — Systemd, Docker, TLS, monitoring, performance tuning
- **[Developer Guide](docs/developing.md)** — Architecture deep-dive, debugging, testing, release process

- **[Technical Details](docs/technical-details.md)** — Architecture, wire protocol (V1/V2 framing, message types, lifecycle, auth, encryption, compression), and project structure
- **[Go frp Compatibility Audit](docs/go-frp-compat-audit.md)** — Full cross-compat analysis against Go frp v0.71.0

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
