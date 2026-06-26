# Go frp v0.69.1 → frp-rs Compatibility Audit

> Source-level comparison. Generated 2026-06-27.

## Summary

frp-rs implements ~70% of Go frp v0.69.1's feature surface. Core tunneling (TCP/UDP/HTTP/STCP/XTCP/SUDP/TCPMux) works. Gaps are mostly in operational tooling, plugins, and advanced config.

---

## Proxy Types

| Type | Status | Notes |
|------|--------|-------|
| TCP | ✅ Compat | Group load balancing differs slightly |
| UDP | ✅ Compat | V1 only; Go frp supports mixed V1/V2 UDP bridge |
| HTTP | ✅ Compat | `response_headers` + `route_by_http_user` stored but not applied |
| HTTPS | ✅ Compat | SNI-only routing (32029bb); also supports TLS termination mode |
| STCP | ✅ Compat | Visitor auth via MD5(sk+timestamp) matches |
| XTCP | ✅ Compat | TCP simultaneous open works. Missing KCP/QUIC P2P data transport (Go frp supports both). |
| SUDP | ✅ Compat | frp-rs uses explicit `sudp_port` config; Go frp auto-manages via VisitorManager |
| TCPMux | ✅ Compat | Auth: frp-rs uses `Proxy-Authorization` header; Go frp uses HTTP Basic Auth |

---

## Transport Compatibility

| Transport | Dial | Accept | Wire Compat | Notes |
|-----------|------|--------|-------------|-------|
| TCP | ✅ | ✅ | ✅ | |
| WebSocket | ✅ | ✅ | ⚠️ | Go frp sends TEXT frames; frp-rs server handles this via Raw mode. Client sends BINARY frames. |
| KCP | ✅ | ✅ | ❓ | Different parameters (window: 128 vs 1024, MTU: 1400 vs 1350, nodelay disabled vs enabled). May not interoperate. |
| QUIC | ✅ | ✅ | ⚠️ | ALPN fixed to `"frp"` (f91ddd1). Go frp opens multiple streams per QUIC conn; frp-rs opens 1. |
| TLS | ✅ | ✅ | ⚠️ | Go frp v0.69.1 defaults `DisableCustomTLSFirstByte=true` (no 0x17 prefix); frp-rs always sends 0x17. |

**Bottom line**: TCP + WebSocket are the only transports confirmed interoperable. KCP needs parameter tuning. QUIC needs ALPN fix + architectural change.

---

## Protocol

| Feature | Go frp | frp-rs |
|---------|--------|--------|
| V1 wire protocol | ✅ Full | ✅ Full (all 18 message types) |
| V2 wire protocol | ✅ Full (ClientHello/ServerHello, AEAD, capability negotiation) | ❌ Stubs only (magic detection, type constants) |
| V2 AEAD (AES-256-GCM) | ✅ | ❌ |
| V2 AEAD (XChaCha20-Poly1305) | ✅ | ❌ |
| Extra message types | — | `CloseProxyResp` ('7'), `Error` ('8') — frp-rs extensions |

---

## Authentication

| Feature | Go frp | frp-rs |
|---------|--------|--------|
| Token auth (MD5) | ✅ | ✅ |
| OIDC auth | ✅ | ✅ |
| Dynamic token sourcing (file://, exec://) | ✅ | ❌ |
| OIDC custom TLS (TrustedCaFile, etc.) | ✅ | ❌ |
| OIDC non-caching token source fallback | ✅ | ❌ |
| additionalAuthScopes config | ✅ | Partial (inferred from field presence) |
| Auth fail delay (brute-force protection) | ✅ (200ms) | ✅ |

---

## Dashboard / Management API

| Endpoint/Feature | Go frp | frp-rs |
|-----------------|--------|--------|
| `/healthz` | ✅ | ✅ |
| `/metrics` | ✅ | ✅ |
| `/api/serverinfo` | ✅ (15+ fields) | `/api/status` (5 fields) |
| `/api/proxy/{type}` | ✅ | ❌ |
| `/api/proxy/{type}/{name}` | ✅ | ❌ |
| `/api/clients` | ✅ | ✅ |
| `/api/clients/{key}` | ✅ | ✅ |
| Static web UI (`/static/`) | ✅ | ❌ (inline HTML only) |
| Dashboard TLS | ✅ (`dashboard_tls_cert_file`) | ✅ |
| Pprof endpoint | ✅ | ❌ |

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
| `virtual_net` | ❌ |

**9 of 10 implemented.**

---

## Config Coverage

| Area | Go frp fields | frp-rs fields |
|------|---------------|---------------|
| Server config | ~55 | ~20 |
| Client config | ~45 | ~18 |
| Proxy config | ~30+ | ~25 |
| Visitor config | ~20 | ~11 |

Key missing server fields: `vhost_http_timeout`, `tcp_mux_passthrough`, `custom_404_page`, `ssh_tunnel_gateway`, `detailed_errors_to_client`, `max_ports_per_client`, `user_conn_timeout`, `udp_packet_size`, `nat_hole_analysis_data_reserve_hours`, `http_plugins`.

Key missing client fields: `nat_hole_stun_server`, `start` (filter), `metadatas`, `include_config_files`, `store_config`, `feature_gates`, `virtual_net`, `transport.tls.*`, `transport.heartbeat_*`.

---

## Missing Features (Complete List)

1. **Server HTTP plugins** (`httpPlugins`) — lifecycle hooks for Login/NewProxy/CloseProxy/Ping/NewWorkConn/NewUserConn
2. **Client proxy/visitor hot reload** — Go frpc has `ReloadFromFile()`; frp-rs client reload only handles admin API reload (no proxy reconciliation)
3. **SSH Tunnel Gateway** — Go frp can act as SSH bastion
4. **V2 wire protocol** — AEAD encryption, capability negotiation
5. **virtual_net client plugin**
6. **XTCP advanced config** (Protocol, KeepTunnelOpen, MaxRetriesAnHour, MinRetryInterval, FallbackTimeoutMs, NatTraversal)
7. **Dynamic token sourcing** (file://, exec://)
8. **OIDC custom TLS** (TrustedCaFile, etc.)
9. **OIDC non-caching token source fallback**
10. **Dashboard /api/proxy/{type} and /api/proxy/{type}/{name} endpoints**
11. **Static web UI** (`/static/`) — currently only inline HTML
12. **Pprof profiling endpoint**
13. **Custom 404 page**
14. **Proxy protocol version** (v1/v2 per-proxy)

---

## frp-rs Advantages

| Feature | Notes |
|---------|-------|
| `--config-dir` mode | Recursive config directory scanning; Go frp only has `includes` in client config |
| Unified metrics | Single `ProxyMetricsRegistry` for dashboard + Prometheus; Go frp has dual system |
| Streaming Snappy decompressor | Handles partial TCP chunks; Go frp uses simple reader |
| Config normalization | camelCase aliases, `[common]` section flattening for Go-format TOML compatibility |
| Management REST API | PUT /api/config, /api/reload, /api/stop on client; richer than Go frp's client admin |
