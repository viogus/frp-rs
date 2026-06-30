# TODO — frp-rs Feature Backlog

> Auto-generated from codebase scan (frp-rs vs Go frp v0.69.1). 2026-06-30.
> **Milestone**: [v0.69.1 — Go frp parity + innovation](https://github.com/viogus/frp-rs/milestone/1)
> **Issues**: [#43–#67](https://github.com/viogus/frp-rs/issues?q=milestone%3A%22v0.69.1+%E2%80%94+Go+frp+parity+%2B+innovation%22)

---

## 1. 功能补全 (Go frp Parity)

### 1.1 V2 protocol full transport wiring
**Priority**: High | **Effort**: High | **Status**: Partial

V2 handshake + framing code exists (`frp-core/src/protocol.rs:358-442`, `v2_handshake.rs`). Currently only wired for V2+yamux. Missing:
- V2 over bare TCP (no mux)
- V2 over QUIC — TODO at `frp-client/src/control.rs:147`
- V2 over KCP
- V2 over WebSocket

Files: `frp-core/src/protocol.rs`, `frp-client/src/control.rs`, `frp-client/src/service.rs`, `frp-server/src/service.rs`

### 1.2 Server plugin hooks: Ping / NewWorkConn / NewUserConn
**Priority**: Medium | **Effort**: Medium | **Status**: Gap

frp-rs server plugin manager (`frp-server/src/plugin/http.rs`) only fires 3 lifecycle hooks: `login`, `new_proxy`, `close_proxy`. Go frp fires 6: adds `Ping`, `NewWorkConn`, `NewUserConn`.

Call sites to add:
- Ping hook: heartbeat handler in control loop
- NewWorkConn hook: work connection accept path
- NewUserConn hook: visitor connection accept path

### 1.3 Virtual Net (L3 VPN with TUN device)
**Priority**: High | **Effort**: High | **Status**: Stub

`virtual_net: String` field exists in `ProxyConfig` (`frp-core/src/config.rs:761`) but zero TUN device implementation. Go frp has full `pkg/vnet/` (~3000 lines): TUN device creation, IP routing, IPv4/IPv6, client/server routers.

Needs: TUN device creation (cross-platform), IP packet routing through frp tunnels, config wiring.

### 1.4 Work connection warm-start pool
**Priority**: Medium | **Effort**: Low | **Status**: Partial

`pool_count` parsed from `Login` (`frp-server/src/control/mod.rs:234`) sets pool capacity. Pool fills passively — connections only created on demand. Go frp pre-allocates `PoolCount` connections at startup.

Fix: spawn `pool_count` work connections eagerly in `handle_control()` setup.

### 1.5 Config store file persistence
**Priority**: Medium | **Effort**: Medium | **Status**: Gap

Dashboard has `/api/store/proxies` CRUD endpoints but proxy changes made via API are lost on restart. Go frp has atomic file-backed store (`pkg/config/source/store.go`).

Needs: JSON file persistence, atomic writes, load on startup.

---

## 2. 协议 / 传输增强

### 2.1 V2 + QUIC interop
**Priority**: Medium | **Effort**: Medium | **Status**: TODO

Single TODO at `frp-client/src/control.rs:147`: "V2 handshake over QUIC when V2+QUIC interop needed." V2 handshake + QUIC transport are both implemented independently — need to compose them.

### 2.2 V2 without yamux (bare TCP)
**Priority**: Medium | **Effort**: Medium | **Status**: Gap

V2 framing (`read_v2_frame` / `write_v2_frame`) works on any `AsyncRead`/`AsyncWrite` but dispatch paths in `service.rs` only route V2 through yamux streams. Need bare-TCP V2 accept + dial paths.

### 2.3 `CloseProxyResp` + `Error` V2 type IDs
**Priority**: Low | **Effort**: Low | **Status**: Gap

`CloseProxyResp` and `Error` message types return `v2_type_id() == 0` (V1-only). Tests at `protocol.rs:633-634` explicitly skip them in V2 roundtrip. Need to assign V2 type IDs and add V2 serialization.

---

## 3. 可观测性 (Observability)

### 3.1 OpenTelemetry tracing
**Priority**: High | **Effort**: Medium | **Status**: None

Zero `tracing::span` usage. Zero `#[instrument]` macros. All 300+ `tracing::info!/warn!/debug!` calls are flat log lines with interpolated strings.

Plan:
1. Add `tracing-opentelemetry` + `opentelemetry-otlp` deps (feature-gated: `otel`)
2. Add `#[instrument]` to key functions: control loop, bridge, NAT hole punch, proxy registration
3. Add OTLP exporter config (endpoint, sample rate)
4. Convert `info!("foo {bar}")` → `info!(bar=%bar, "foo")` for structured queryability

### 3.2 `/healthz` real health checks
**Priority**: Medium | **Effort**: Low | **Status**: Trivial

`frp-server/src/dashboard.rs:293`: `handle_healthz()` returns `"ok"` unconditionally. Needs:
- Liveness: always ok (process alive = ok)
- Readiness: check internal channels alive, proxy manager responsive

### 3.3 `/metrics` endpoint authentication
**Priority**: Low | **Effort**: Low | **Status**: Gap

Server `/metrics` endpoint has no auth. Go frp gates behind `EnablePrometheus` config toggle. Add optional Basic auth or `EnablePrometheus` gate.

---

## 4. 创新功能 (Beyond Go frp)

### 4.1 gRPC management API
**Priority**: Medium | **Effort**: High | **Status**: None

Design: `tonic` + `.proto` definitions for `AdminService`:
- `ListProxies`, `CreateProxy`, `DeleteProxy`, `UpdateProxy`
- `GetStats` (streaming traffic stats)
- `ReloadConfig`
- `ListClients`, `GetClient`

Side-by-side with existing REST API. Feature-gated (`grpc`). Go frp has no gRPC — first-party advantage.

### 4.2 WASM/WASI plugin system
**Priority**: Medium | **Effort**: High | **Status**: None

Current plugins: external HTTP services (server) or compile-time Rust modules (client). WASM = sandboxed, hot-loadable, language-agnostic.

Plugin interface: `on_login`, `on_new_proxy`, `on_close_proxy`, `on_traffic`, `on_new_work_conn`, `on_new_user_conn`. Use `wasmtime` (pure Rust, no C deps).

### 4.3 Plugin hot-reload on client
**Priority**: Low | **Effort**: Medium | **Status**: Gap

`frp-client/src/reload.rs` warns: "plugin restart requires full frpc restart". Need to kill old plugin process, start new one with updated config, drain + migrate connections.

### 4.4 Admin WebSocket event stream
**Priority**: Low | **Effort**: Medium | **Status**: None

Push proxy state changes, connection events, traffic stats to dashboard in real-time via WebSocket. Eliminates polling `/api/status`.

### 4.5 Traffic mirroring
**Priority**: Low | **Effort**: Medium | **Status**: None

Mirror traffic from one proxy to another for testing/staging. Config: `mirror_to = "staging-proxy"`.

---

## 5. 性能 / 体积优化

### 5.1 Buffer pooling (replace `vec![0u8; 65536]`)
**Priority**: High | **Effort**: Medium | **Status**: None

8 allocation sites in `frp-core/src/bridge.rs` use `vec![0u8; 65536]` per-direction per-connection. Replace with `bytes::BytesMut` + pool. Saves ~128KB alloc per bridged connection pair.

Sites: `bridge.rs:73,108,193,226,308,336,446,470`

### 5.2 axum out of frp-core TLS feature
**Priority**: High | **Effort**: Medium | **Status**: Gap

`frp-core/Cargo.toml` `tls` feature pulls `axum` (for `TlsListener`). This means `axum` (~500KB+ HTTP framework) is compiled into frpc even though frpc never serves HTTP. Move axum dependency to `frp-server` only.

### 5.3 `webpki-roots` → `rustls-platform-verifier`
**Priority**: Medium | **Effort**: Low | **Status**: Gap

`webpki-roots` bundles ~300KB of CA certificates. `rustls-platform-verifier` uses native OS trust store (macOS Security.framework, Windows Schannel, Linux openssl dir). Saves ~300KB binary size. Also benefits mobile targets.

### 5.4 `snap` → `lz4_flex` evaluation
**Priority**: Low | **Effort**: Low | **Status**: Evaluation

`snap` is pure Rust Snappy (~30KB). `lz4_flex` is faster (SIMD), smaller, same API surface. Benchmark compression ratio + speed on frp traffic patterns before switching.

### 5.5 Connection pool pre-connect
**Priority**: Medium | **Effort**: Low | **Status**: Partial

See 1.4. Same item — warm-start pool connections at proxy registration time.

### 5.6 Zero-copy encrypted bridge path
**Priority**: Medium | **Effort**: High | **Status**: None

Encrypted bridge path: buf → decrypt → buf → write. Could use `Bytes` to share buffers between decrypt output and write, avoiding one copy. Plain path already uses `copy_bidirectional` (kernel zero-copy).

### 5.7 `quinn` → lightweight QUIC (long-term)
**Priority**: Low | **Effort**: High | **Status**: None

`quinn` pulls `rustls`, `webpki-roots`, `quinn-proto`, `quinn-udp`. ~800KB+. Long-term: thin wrapper over `quinn-proto` only, reuse existing TLS config.

---

## 6. 工程改进

### 6.1 Fuzz testing for protocol parsing
**Priority**: Medium | **Effort**: Medium | **Status**: None

`protocol.rs` V1/V2 frame parsing handles untrusted network input. `cargo-fuzz` + `arbitrary` for all 20 message types, frame header parsing, V2 handshake.

### 6.2 Property-based tests for config normalization
**Priority**: Medium | **Effort**: Medium | **Status**: None

`frp-core/src/config.rs` TOML→JSON normalization is ~200 lines of field mapping. Proptest round-trip: `normalize(Go_TOML) → Rust_TOML → normalize → same Rust_TOML`.

### 6.3 Benchmark suite expansion
**Priority**: Low | **Effort**: Medium | **Status**: Partial

Existing: `benches/crypto_bridge.rs`. Add: protocol serialize/deserialize, bridge throughput (plain + encrypted + compressed), connection accept latency, proxy registration throughput.

### 6.4 TLS certificate hot-reload
**Priority**: Low | **Effort**: Low | **Status**: Gap

Server TLS certs expire. Currently requires restart. Watch cert file, reload `rustls::ServerConfig` on change.

### 6.5 Graceful connection drain on shutdown
**Priority**: Medium | **Effort**: Medium | **Status**: None

Server stop should drain active connections with timeout, not abort them. `tokio::signal` + connection counter + drain timeout.

### 6.6 Admin API TLS support
**Priority**: Low | **Effort**: Low | **Status**: Gap

Dashboard/admin API serves plain HTTP only. Go frp `WebServer` config has TLS fields. Add TLS support to admin/API server.

---

## Quick Wins (low effort, high impact)

| # | Item | Effort |
|---|------|--------|
| 3.2 | Real `/healthz` with readiness check | 1h |
| 1.4 | Work connection warm-start pool | 2h |
| 3.3 | `/metrics` auth gate | 1h |
| 6.4 | TLS cert hot-reload | 2h |
| 5.3 | `webpki-roots` → platform verifier | 2h |

## Next Milestone Targets

| # | Item | Effort |
|---|------|--------|
| 3.1 | OpenTelemetry tracing | 1d |
| 5.1 | Buffer pooling | 1d |
| 5.2 | axum out of frp-core | 0.5d |
| 1.2 | Plugin hooks (Ping/NewWorkConn/NewUserConn) | 0.5d |
| 1.5 | Config store file persistence | 1d |

## Major Features

| # | Item | Effort |
|---|------|--------|
| 1.1 | V2 protocol full transport wiring | 3d |
| 4.1 | gRPC management API | 3d |
| 4.2 | WASM plugin system | 5d |
| 1.3 | Virtual Net (L3 VPN) | 5d |
