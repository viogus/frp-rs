# Go frp v0.71.0 → frp-rs Compatibility Audit

> Source-level comparison. Updated 2026-07-14; compat re-verified against Go
> frp v0.71.0 2026-08-30/31 (round-18 gates: 86/86 compat, protocol-matrix
> 11/11).

## Summary

frp-rs targets Go frp v0.71.0 wire compatibility. Core tunneling (TCP/UDP/HTTP/STCP/XTCP/SUDP/TCPMux), authentication, encryption, compression, all 5 transports, all 10 client plugins, config coverage, SSH tunnel gateway, V2 AEAD protocol, and XTCP Go↔Rust cross-compat all match Go frp behavior.

**86 non-XTCP compatibility tests and the 17-test XTCP pairwise matrix run against Go frp v0.71.0 (V2 included).**

---

## Proxy Types

| Type | Status | Notes |
|------|--------|-------|
| TCP | ✅ Compat | PROXY protocol v1/v2, group load balancing |
| UDP | ✅ Compat | Configurable `udp_packet_size` |
| HTTP | ✅ Compat | `response_headers` injection, `route_by_http_user`, `health_check_http_headers` |
| HTTPS | ✅ Compat | SNI-only routing; also supports TLS termination mode |
| STCP | ✅ Compat | Real visitor plugin, `bind_port=-1` no-bind mode, visitor auth via MD5(sk+timestamp) |
| XTCP | ✅ Compat | UDP MakeHole hole punching (KCP-over-UDP or QUIC P2P data plane — no TCP simultaneous open; that pre-v0.7.0 mechanism is incompatible), `keepTunnelOpen`/`maxRetriesAnHour`/`minRetryInterval` retry, `fallbackTimeoutMs` (clamped to 20s), `disableAssistedAddrs` |
| SUDP | ✅ Compat | frp-rs uses explicit `sudp_port` config; Go frp auto-manages via VisitorManager |
| TCPMux | ✅ Compat | Auth: frp-rs uses `Proxy-Authorization` header; Go frp uses HTTP Basic Auth |

---

## Transport Compatibility

| Transport | Dial | Accept | Wire Compat | Notes |
|-----------|------|--------|-------------|-------|
| TCP | ✅ | ✅ | ✅ | Full interop verified by compat tests |
| WebSocket | ✅ | ✅ | ✅ | Both client and server use Raw mode WsByteStream — treats all WS data frames as opaque bytes, tolerating Go frp TEXT frames with non-UTF-8 payload. Client masks outgoing frames per RFC 6455 §5.3. |
| KCP | ✅ | ✅ | ✅ Full interop | Window 1024, MTU 1350. Go↔Rust KCP passes both directions, including KCP+TLS and KCP+tcpMux — Go frp v0.71.0 applies TLS and yamux over its KCP session layer exactly like TCP (frps `server/service.go` HandleListener runs CheckAndEnableTLSServerConn + fmux.Server over kcpListener; frpc `client/connector.go` realConnect applies TLS hooks with WithProtocol("kcp") and Open wraps in fmux.Client). Rust side uses the in-tree KCP implementation (kcp-go v5.6.13 aligned). |
| QUIC | ✅ | ✅ | ✅ Full interop | ALPN `"frp"`. Multi-stream QuicConnection wrapper accepts Go frp quic-go additional streams. Full Go↔Rust cross-compat verified. |
| TLS | ✅ | ✅ | ✅ | `disableCustomTLSFirstByte` controls 0x17 prefix. Full interop with Go frp TLS. |

**Bottom line**: TCP, WebSocket, TLS, KCP, and QUIC are fully cross-compatible with Go frp — including the KCP+TLS and KCP+tcpMux combinations (Go frp applies TLS/yamux over its KCP transport just as over TCP).

---

## Protocol

| Feature | Go frp | frp-rs |
|---------|--------|--------|
| V1 wire protocol | ✅ Full | ✅ Full (all message types) |
| V2 wire protocol | ✅ Full (ClientHello/ServerHello, AEAD, capability negotiation) | ✅ Full (AEAD encryption, capability negotiation, crypto handshake) |
| V2 PROXY protocol binary header | ✅ | ✅ |
| Extra message types | — | `CloseProxyResp` ('7'), `Error` ('8') — frp-rs extensions |

---

## Authentication

| Feature | Go frp | frp-rs |
|---------|--------|--------|
| Token auth (MD5) | ✅ | ✅ |
| OIDC auth | ✅ | ✅ |
| OIDC proxy URL | ✅ | ✅ |
| Dynamic token sourcing (file://, exec://) | ✅ | ✅ |
| OIDC custom TLS (TrustedCaFile, etc.) | ✅ | ✅ |
| OIDC non-caching token source fallback | ✅ | ✅ |
| additionalAuthScopes config | ✅ | ✅ (full implementation) |
| Auth fail delay (brute-force protection) | ✅ (200ms) | ✅ |

---

## Dashboard / Management API

| Endpoint/Feature | Go frp | frp-rs |
|-----------------|--------|--------|
| `/healthz` | ✅ | ✅ |
| `/metrics` | ✅ | ✅ (Prometheus text format) |
| `/api/status` | ✅ | ✅ (version, uptime, client/proxy counts) |
| `/api/proxies` | ✅ | ✅ |
| `/api/proxy/:name` | ✅ | ✅ |
| `/api/proxy/:name/traffic` | ✅ | ✅ |
| `/api/clients` | ✅ | ✅ |
| Dashboard TLS | ✅ | ✅ |
| Static web UI | ✅ | ✅ (inline HTML dashboard) |
| Pprof endpoint | ✅ | ⚠️ placeholder routes (`/debug/pprof/*` return a notice; no Go-style profiles) |

---

## Client Plugins

| Plugin | Status |
|--------|--------|
| `http_proxy` | ✅ |
| `socks5` | ✅ |
| `static_file` | ✅ |
| `unix_domain_socket` | ✅ |
| `http2https` | ✅ |
| `https2http` | ✅ |
| `https2https` | ✅ |
| `http2http` | ✅ |
| `tls2raw` | ✅ |
| `virtual_net` | ✅ Proxy work-conn plugin + visitor tunnel packet path |

**10 of 10 client plugin types implemented. The Go frp v0.71.0 `virtual_net`
proxy plugin hands work connections to the vnet controller (TUN ingress plus
source-IP return routing), and the `virtual_net` visitor plugin delivers
inbound `VnetPacket`s into its no-bind STCP/XTCP tunnel while forwarding
tunnel return traffic to the local TUN. vnet routing is dual-stack
(IPv4/IPv6), proxy/visitor transport encryption and compression are applied to
tunnel bytes, and frps broadcasts vnet route advertisements/removals to peers
with disconnect cleanup.**

---

## Config Coverage

| Area | Go frp fields | frp-rs fields |
|------|---------------|---------------|
| Server config | ~55 | ~50 |
| Client config | ~45 | ~43 |
| Proxy config | ~30+ | ~30+ |
| Visitor config | ~20 | ~18 |

All key config fields implemented: `proxy_protocol_version` (v1/v2), `response_headers`, `health_check_http_headers`, `metas`/`metadatas`, `additional_auth_scopes`, `fallback_timeout_ms`, `oidc_proxy_url`, `disable_custom_tls_first_byte`, `bind_port` (including -1), `disable_assisted_addrs`, `udp_packet_size`, `feature_gates`, `dial_server_keepalive`, `connect_server_local_ip`, `transport.proxy_url`, `nat_hole_stun_server`, `start`, `includes`/`include`, `enabled`, `keep_tunnel_open`/`max_retries_an_hour`/`min_retry_interval`, `heartbeat_interval`/`heartbeat_timeout`.

---

## Resolved (2026-06-28)

1. **V2 AEAD encryption + capability negotiation** — ✅ Full implementation: Login plaintext, AEAD after LoginResp, crypto negotiation in handshake. V2 compat tests run against the Go frp v0.71.0 pre-built binary (V2 is included since v0.70.1).

2. **XTCP Go frp cross-compat** — ✅ Full implementation: server coordinates NAT analysis with address exchange. Compat tests guarded behind `RUN_XTCP=1` (requires public internet for STUN/NAT probes).

3. **QUIC Go↔Rust cross-compat** — ✅ Multi-stream QuicConnection wrapper accepts Go frp quic-go additional streams. Full cross-compat verified. Enabled by default since 0.3.1 (root cause was stale debug build, release build works).

## Out of Scope

- **Pprof profiling endpoint** — out of scope (Go-specific; Rust equivalent is tokio-console)
- **gRPC management API** — Go frp v0.71.0 has no gRPC; REST API covers all management

### Recently Fixed (2026-06-27)

- ✅ Client reconnect: two-phase fast backoff (escalating phase, 20s cap) — matches Go frp v0.71.0's `fastBackoffImpl`
- ✅ Group load balancing: true round-robin with per-group atomic counter
- ✅ Admin `/api/status`: reports actual `plugin`, `remote_addr`, `err`; status reflects registration state
- ✅ Config reload: detects changed proxies via config_snapshot hash, supports CloseProxy+NewProxy cycle for add/remove/modify without restart
- ✅ Go↔Rust XTCP: server-side routing fixed (handle_client() for NatHoleResp wire path); frp-rs visitors default the P2P protocol to **QUIC** (Go parity — empty protocol normalized to `"quic"` via Go `EmptyOr`), `protocol="kcp"` selects the KCP+yamux data plane
- ✅ KCP parameters: window 128→1024, MTU 1400→1350 (matches Go frp)
- ✅ QUIC: verified both sides use one bidirectional stream per logical channel
- ✅ Client `/api/metrics`: Prometheus-format metrics endpoint (traffic_in/out, connection_counts, current_conns) — matches server `/metrics`
- ✅ KCP cross-compat: Rust↔Rust KCP + Go↔Rust KCP (plain, TLS, tcpMux) all pass in both directions — in-tree Rust KCP is aligned with Go kcp-go session layer (kcp-go v5.6.13), verified against Go frp v0.71.0
- ✅ QUIC cross-compat: Rust↔Rust QUIC transport test added (r2r); Go↔Rust guarded — stream model mismatch (Go quic-go multi-stream-per-connection vs Rust one-stream-per-connection)
- ✅ Multi-port STUN, IPv6 parsing, session limit, stable key generation
- ✅ Rust→Go HTTPS compat test: fixed TLS termination architecture (Go frps vhostHTTPSPort forwards raw TLS; local echo server upgraded to HTTPS with proper SSL error resilience)
- ✅ Go→Rust SOCKS5 compat test: symmetric coverage with existing r2g test
- ✅ WebSocket + encryption compat tests: g2r + r2g both pass. Client-side Raw mode WsByteStream (manual WS upgrade + RFC 6455 masking, in-tree framing — tungstenite removed 2026-08-09) tolerates Go frps TEXT frames with encrypted binary payload.

---

## frp-rs Advantages

| Feature | Notes |
|---------|-------|
| `--config-dir` mode | Recursive config directory scanning; Go frp only has `includes` in client config |
| `includes` with glob | Glob-based config file inclusion with deep TOML merge (both server and client) |
| Unified metrics | Single `ProxyMetricsRegistry` for dashboard + Prometheus; Go frp has dual system |
| Streaming Snappy decompressor | Handles partial TCP chunks; Go frp uses simple reader |
| Config normalization | camelCase aliases, `[common]` section flattening for Go-format TOML compatibility |
| Management REST API | PUT /api/config, /api/reload, /api/stop on client; richer than Go frp's client admin |
| `enabled` per-proxy toggle | Disable individual proxies without removing config |
| Selective `start` | Start only named proxies for testing/staging |
| PROXY protocol v1+v2 | Both text and binary HAProxy PROXY protocol support |
| SSH tunnel gateway | ✅ SSH proxy-registration commands; `ssh -R` reverse forwarding (tcpip-forward/forwarded-tcpip) since 0.7.1 parity pass |
| Rust type safety | Memory safety, no data races, compile-time guarantees |

---

## Go frp Compatibility Notes

frp-rs targets protocol compatibility with Go frp v0.71.0. The full Go frp
v0.71.0 cross-compatibility suite runs in CI (including the XTCP pairwise
matrix on VPS and V2 over the v0.71.0 pre-built binaries). Coverage is broad
but not literally 100% — see [Known Limitations](#known-limitations) below.

The per-surface parity details are in the tables above: V1/V2 wire protocol
under [Protocol](#protocol), transports under
[Transport Compatibility](#transport-compatibility), and the ten client
plugins under [Client Plugins](#client-plugins). The remaining Go-compat
specifics that are not already tabulated:

- **XTCP**: Cross-compat with Go frp (requires public internet for STUN/NAT
  probes). Both P2P data planes are supported — KCP+yamux and QUIC
  (`protocol="quic"`, the default; an empty `protocol` normalizes to `"quic"`,
  and the `quic` feature is default ON). Go visitors using the default
  `protocol="quic"` interoperate with Rust providers: Go frp v0.71.0 sends the
  peer `"ip:port"` as the QUIC TLS SNI, which upstream rustls 0.23 rejects as
  an invalid server name — frp-rs vendors rustls with a one-line server-side
  patch treating an invalid SNI as "no SNI" (equivalent to the upstream
  `invalid_sni_policy = IgnoreAll` added in rustls 0.24; see
  [audit note §6](archive/notes/2026-08-04-mimalloc-throughput-ab.md); full
  plan + maintenance notes in
  [2026-08-04-xtcp-quic-sni-compat.md](archive/notes/2026-08-04-xtcp-quic-sni-compat.md)).

---

## Known Limitations

Current limitations as of frp-rs 0.71.0:

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
