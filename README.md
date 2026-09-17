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
  [audit note §6](docs/archive/notes/2026-08-04-mimalloc-throughput-ab.md);
  full plan + maintenance notes in
  [2026-08-04-xtcp-quic-sni-compat.md](docs/archive/notes/2026-08-04-xtcp-quic-sni-compat.md)).
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

Four size tiers (sizes are in the
[generated table above](#technical-differences-vs-go-frp) — they are not repeated
here, because two copies drift and the wrong one always looks authoritative).
SSH and QUIC are enabled by default; dashboard is opt-in:

```bash
# Default — core transports + SSH + QUIC, no dashboard
cargo build --release -p frps -p frpc

# Full — default + dashboard
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"

# Tiny — no QUIC/KCP/WS/SSH/OIDC/dashboard/compression, keeps TLS+TCP mux (frps also HTTP proxy)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro — core only, no TLS/compression/chacha20/http-proxy/tcp-mux
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
tcp_mux_keepalive_timeout = 0
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
| `transport.tcp_mux_keepalive_timeout` | `0` | Dead-session reaper silence bound (seconds): `0` = auto, `>0` = explicit (floored 30s), `<0` = disable |
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
| `tcp_mux_keepalive_timeout` | `0` | Dead-session reaper silence bound (seconds): `0` = auto, `>0` = explicit (floored 30s), `<0` = disable |
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

Ordered by what actually decides a migration, not by what is easiest to measure.

#### 1. Adopt it one side at a time — and roll back the same way

The two implementations are wire-compatible **in both directions**: an frp-rs
`frpc` talks to a Go `frps`, and an frp-rs `frps` serves Go `frpc` clients. Same
config files, same encryption, same authentication. So this is not a migration —
you replace **one** binary, leave the other side exactly as it is, and roll back by
putting the old file back.

That is not a promise, it is a CI gate: `scripts/compat-test.sh` runs **86
scenarios plus a 17-case XTCP pairwise matrix against the real Go frp release**, in
both directions and including V2, on every push; `scripts/protocol-matrix.sh`
asserts that all 11 transport rows actually move bytes. No other frp
reimplementation offers a rollback-safe swap with evidence behind it.

#### 2. It runs where a 17 MB binary does not fit

<!-- Generated by `bash scripts/compare-go-frp.sh --build --memory` — regenerate
     rather than editing these numbers by hand. The previous hand-written version
     compared macOS Go binaries against Linux frp-rs sizes, so none of it was
     reproducible. -->

| Metric | Go frp v0.71.0 | frp-rs (default) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | 17.7 MB | **5.1 MB** | 3.2 MB | 1.9 MB |
| frpc binary | 14.2 MB | **4.1 MB** | 2.8 MB | 2.1 MB |
| Memory (idle, frps) | 26.3 MB | **9.9 MB** | — | — |
| Memory (idle, frpc) | 17.1 MB | **9.2 MB** | — | — |

That is **3.5× smaller and 2.7× lighter** than Go frp at the default tier, and up to
**9× smaller** at `micro`.

> Measured on **macOS arm64**, both implementations at **v0.71.0**, with the declared
> release profile (`fat-LTO`, `opt-level=z`, `codegen-units=1`, `strip = "symbols"`,
> `panic=abort`). Generated by [`scripts/compare-go-frp.sh`](scripts/compare-go-frp.sh),
> which downloads the official Go release for *this* platform and version and
> **aborts if either does not match** — a cross-platform or cross-version comparison
> is not a measurement. Absolute figures are platform-dependent: re-run the script
> on your target platform instead of trusting these. CI builds override LTO/opt
> (`lto=false opt-level=2`) for speed and are larger, so CI artifacts do not reflect
> a release.

The small tiers are a **new deployment**, not a replacement: 1.9 MB of frps and
2.1 MB of frpc fit on OpenWrt routers, IoT devices, and size-capped container
images where a 17 MB Go binary is not an option at all. Idle RSS for those tiers is
not measured yet — see [`TODO.md`](TODO.md).

#### 3. Memory, and the absence of a GC

Idle RSS is **9.9 MB vs 26.3 MB** for frps and **9.2 MB vs 17.1 MB** for frpc. More
importantly, Rust has no garbage collector: the heap cannot grow to roughly 2× live
the way Go's can, and there is no stop-the-world component in the tail.

**This is the claim that most needs more evidence.** Every committed baseline
measures frp-rs against itself; there is no long-uptime head-to-head yet. The
harness now takes `FRPS_BIN`/`FRPC_BIN`, so that measurement is one environment
variable away — it is an open item in [`TODO.md`](TODO.md), and until it is done,
treat "stable RSS over weeks" as a hypothesis rather than a result.

#### 4. Operational knobs Go frp does not have

- **UDP bandwidth limiting.** Go frp v0.71.0's UDP forwarder has **no limiter at
  all**; frp-rs applies the same `bandwidthLimit` semantics it uses for TCP.
- **SSH gateway per-IP login throttling** plus `ssh_session_idle_timeout`. Go's
  gateway has only `authorized_keys` public-key auth — no password path and no
  throttle.
- **`frpc verify --strict-config`** — reject unknown config keys rather than
  silently ignoring them.

#### 5. The verification posture (the part procurement cares about)

Every deliberate divergence from Go frp is recorded with the Go source `file:line`
that justifies it, in [`docs/go-frp-compat-audit.md`](docs/go-frp-compat-audit.md)
and the [development log](docs/history/development-log.md), and the compatibility
suite runs against the real Go binary on every push. If you have to justify a
dependency, "here is exactly where and why we differ, and how it is tested" is
worth more than a feature table.

#### What frp-rs is not

Saying this plainly is part of the pitch:

- **Go frp wins on ecosystem, documentation, community and cross-compilation.**
  Rust cross-compilation is genuinely painful — this repo ships a `zigbuild`
  container for it. If you want the well-trodden path, use Go frp.
- **A single maintainer.** No second person currently reviews a protocol change.
- **No third-party security audit.** The audits under `docs/` are self-run.
- **`rustls`, `yamux` and `russh` are vendored**, so `cargo update` does not bring
  their security releases; that check is manual and lives in the
  [pre-release checklist](docs/developing.md#pre-release-checklist).
- **`panic = "abort"`** means a panic takes down that frps process and every proxy
  on it. This was measured and chosen deliberately (unwinding costs frpc +17% in
  size), but it is a real trade-off against per-connection fault isolation.
- **"Memory safety" is not a difference from Go** — Go is memory-safe too. The
  Rust-specific claims are *no GC*, *no runtime*, and *compile-time data-race
  freedom*. An earlier version of this section listed memory safety as if it were a
  differentiator.

#### Which tier to pick

`frps`'s `default` feature set already enables every transport and the SSH gateway
(the Cargo `full` feature is identical to `default`); opt-in features are
`dashboard`, `vnet`, `mimalloc`, `otel`, and the dev-only profiling flags:

- **default** (= Cargo `full`, no dashboard): TCP, WS, TLS, KCP, QUIC, OIDC auth,
  compression, XChaCha20 V2 encryption, HTTP proxy, TCP mux, and the SSH gateway.
- **dashboard build** (`--features "ssh,quic,dashboard"`): default + dashboard/metrics.
  (`ssh` and `quic` are redundant here — both are already on by default.)
- **vnet** (`--features vnet`): adds L3 VPN / TUN device routing (frp-vnet; opt-in,
  not in default binaries).
- **`tiny`**: drops QUIC, KCP, WebSocket, SSH, OIDC, dashboard and compression.
  Keeps TLS and TCP mux (frps also keeps the HTTP proxy plugin). Ideal for edge devices.
- **`micro`**: core only — no TLS, no compression, no chacha20, no HTTP proxy, no
  TCP mux. Minimal attack surface and footprint.

```bash
# Tiny build (no heavy protocols)
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro build (core only)
cargo build --release -p frps -p frpc --no-default-features --features micro
```

### frp-rs 核心优势

与上一节同结构、同事实，按"真正决定迁移的因素"排序。

#### 1. 可以只换一侧，也可以原样换回来

两个实现在**双向**上 wire 兼容：frp-rs 的 `frpc` 能连 Go 的 `frps`，frp-rs 的 `frps` 也能服务 Go 的 `frpc`。配置文件、加密方式、认证机制一致。所以这不是"迁移"——只替换**一个**二进制，另一侧完全不动，回滚就是把旧文件放回去。

这不是承诺而是 CI 门禁：`scripts/compat-test.sh` 每次 push 都对**真实 Go frp 发行版**跑 86 项常规场景 + 17 项 XTCP 两两矩阵（双向，含 V2）；`scripts/protocol-matrix.sh` 断言 11 条传输链路确实有数据流动。

#### 2. 它能跑在 17 MB 二进制放不下的地方

数字见上表——由 `scripts/compare-go-frp.sh` 生成，同平台同版本，平台或版本不符即**拒绝比较**。默认档位比 Go frp **小 3.5 倍、轻 2.7 倍**，`micro` 档位最小可达 **9 倍**。

`tiny`/`micro` 是**新增场景**而非替代：1.9 MB 的 frps 与 2.1 MB 的 frpc 可以放进 OpenWrt 路由、IoT 设备、以及有镜像体积上限的容器——那些地方原本根本不会跑 frp。

#### 3. 内存，以及"没有 GC"这件事

空闲 RSS：frps **9.9 MB vs 26.3 MB**，frpc **9.2 MB vs 17.1 MB**。更重要的是 Rust 没有垃圾回收器：堆不会像 Go 那样涨到约 2× live，尾部延迟里也没有 stop-the-world 分量。

**这一条最需要更多证据。** 现有基线全是 frp-rs 对自己的测量，尚无长时对拍。基线脚本现已支持 `FRPS_BIN`/`FRPC_BIN`，那个测量只差一条环境变量——它是 [`TODO.md`](TODO.md) 里的未决项。在完成之前，"连续数周 RSS 稳定"应视为假设而非结论。

#### 4. Go frp 没有的运维旋钮

- **UDP 带宽限制。** Go frp v0.71.0 的 UDP forwarder **完全没有 limiter**；frp-rs 对 UDP 应用与 TCP 相同的 `bandwidthLimit` 语义。
- **SSH 网关按 IP 的登录节流**，以及 `ssh_session_idle_timeout`。Go 的网关只有 `authorized_keys` 公钥认证——没有密码路径，也没有节流。
- **`frpc verify --strict-config`**：未知配置键直接报错，而不是静默忽略。

#### 5. 可核查性（采购环节真正在意的部分）

每一处与 Go frp 的**有意分歧**都记录了对应的 Go 源码 `file:line` 依据（见 [`docs/go-frp-compat-audit.md`](docs/go-frp-compat-audit.md) 与[开发日志](docs/history/development-log.md)），兼容性套件每次 push 都对真实 Go 二进制运行。为依赖做论证时，"差异在哪、为什么、怎么测的"比功能对照表有用得多。

#### frp-rs 不是什么

把这一节讲清楚也是卖点的一部分：

- **生态、文档、社区、交叉编译：Go frp 全胜。** Rust 交叉编译确实痛苦——本仓库为此提供了 `zigbuild` 容器。想走最好走的路，就用 Go frp。
- **只有一位维护者。** 目前没有第二个人 review 协议改动。
- **没有第三方安全审计。** `docs/` 下的审计均为自审。
- **`rustls`、`yamux`、`russh` 是 vendored**，`cargo update` 不会带来它们的安全更新；该检查是人工的，列在[发布前检查清单](docs/developing.md#pre-release-checklist)。
- **`panic = "abort"`**：一次 panic 会带走该 frps 进程及其上所有代理。这是测量后有意选择的（unwind 会让 frpc 体积 +17%），但确实是对"按连接隔离故障"的取舍。
- **"内存安全"不是与 Go 的差异**——Go 同样内存安全。Rust 独有的论据是**无 GC**、**无运行时**、**编译期数据竞争自由**。本节早期版本把内存安全列为差异化卖点，那是不成立的。

#### 档位选择

各档位的能力取舍（体积数字见上表）：

- **default**（= Cargo `full`，不含 dashboard）：TCP/WS/TLS/KCP/QUIC、OIDC、压缩、XChaCha20 V2、HTTP 代理、TCP mux、SSH 网关。
- **dashboard**（`--features dashboard`）：default + 指标/状态 API。
- **vnet**（`--features vnet`）：增加 L3 VPN / TUN 路由（opt-in，默认二进制不含）。
- **`tiny`**：去掉 QUIC/KCP/WebSocket/SSH/OIDC/dashboard/压缩，保留 TLS 与 TCP mux（frps 另保留 HTTP 代理）。适合边缘设备。
- **`micro`**：仅核心 TCP 代理。最小攻击面与体积。

#### Feature 归属一览

**frps（21 个）** — `default` 已启用：`websocket` `kcp` `quic` `oidc` `tls` `http-proxy` `compression` `chacha20` `tcp-mux` `ssh`；opt-in：`dashboard`（指标/状态 API）、`vnet`（L3 VPN / TUN 路由）、`mimalloc`（全局分配器）、`otel`（遥测）；dev-only（不进入 shipped 构建）：`debug-logs` `mem-profile` `profiling`；组合别名：`default` `full`（= frp-server 默认）、`tiny`（tls+http-proxy+tcp-mux）、`micro`（仅 TCP 核心）。

**frpc（20 个）** — `default` 已启用：`tls` `kcp` `quic` `websocket` `oidc` `compression` `chacha20` `tcp-mux` `http2http`；opt-in：`vnet`、`admin`（frpc 管理 API）、`mimalloc`、`otel`；dev-only：`debug-logs` `mem-profile` `profiling`；组合别名：`default` `full`（= frp-client 默认）、`tiny`（tls+tcp-mux）、`micro`。

**隐含关系**：
- 底层 crate 通过二进制的 feature 转发裁剪：frp-core 默认虽含 `vnet`/`stun`，但 frps/frpc 以 `default-features = false` 引用，因此**默认二进制不含 vnet**（opt-in）
- `http2http`（frpc/frp-client）独立控制 h2 插件，**隐含 `tls`**，tiny 构建不含
- 共享内部 feature：`http-client`（被 `oidc`/`http-proxy` 依赖）、`admin-auth`（被 `dashboard`/`admin` 依赖）
- dev-only 三个 feature 在全部 shipped 构建（full/tiny/micro）中关闭，生产二进制字节一致

---

## Vendored crates

Three crates are patched via `[patch.crates-io]` in the workspace `Cargo.toml`.
Each exists for a concrete, documented reason and **each has an exit condition** —
a vendored crypto/TLS tree is a maintenance liability, not a resting state.

| Crate | Version | Why it is vendored | Exit condition |
|---|---|---|---|
| [`rustls`](vendor/rustls/README-FRP-RS.md) | 0.23.43 | Go frp XTCP QUIC visitors send the peer `"ip:port"` as the TLS SNI; rustls 0.23 rejects it as invalid. Patch treats invalid SNI as *no SNI* (server-side only). | **Delete when the workspace moves to rustls ≥ 0.24** — `invalid_sni_policy = IgnoreAll` is native there. Until then, track 0.23.x `RUSTSEC` advisories manually on every release. |
| [`yamux`](vendor/yamux/README-FRP-RS.md) | 0.14.0 | 5 patches: per-stream RST at the inbound stream cap (instead of a session-killing GoAway, matching Go frp's fork), a read-side lost-wakeup deadlock fix, a per-stream receive-window cap, window-growth RTT seeding, and a send-side body-buffer pool. | Upstream each patch, or re-apply on every yamux bump (each patch section lists its own upgrade note). The deadlock fix is the one to upstream first. |
| [`russh`](vendor/russh/README-FRP-RS.md) | 0.62.7 | 2 patches dropping the `ssh-key` `encryption` + `ppk` and `pkcs8` `encryption` chains, which the SSH gateway never uses (`load_secret_key(path, None)` only). Removes 7 pre-release packages and ~48.5 KiB from frps. | Drop when upstream makes those `ssh-key` features optional. |

> The rustls patch is the security-sensitive one, and **`cargo update` will not
> pick up upstream security releases for any of these three** — `[patch.crates-io]`
> pins them. The manual advisory check is a step in the
> [pre-release checklist](docs/developing.md#pre-release-checklist), not something
> a tool will remind you about.

---

## Documentation

Full index — architecture, developer guide, compatibility audit, history and
archive: **[docs/README.md](docs/README.md)**.

**Reference — using frp-rs**

- **[Configuration Reference](docs/config.md)** — every config field with types, defaults, and Go frp equivalents
- **[Proxy Type Guide](docs/proxies.md)** — when and how to use each proxy type (TCP, UDP, HTTP, STCP, XTCP, …)
- **[Client Plugins](docs/client-plugins.md)** — HTTP proxy, SOCKS5, static file, TLS termination, `virtual_net`, …
- **[Deployment Guide](docs/deployment.md)** — systemd, Docker, TLS, monitoring, performance tuning

**Contributing** — start with [CLAUDE.md](CLAUDE.md) (rules, invariants, dependency
policy) and [docs/architecture.md](docs/architecture.md) (how it works).
Release history: [CHANGELOG.md](CHANGELOG.md).

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
