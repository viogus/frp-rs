# Changelog

All notable changes to frp-rs.

## Unreleased

- **XTCP MakeHole executed on the provider side + Go v0.70.1 punch semantics**:
  the provider previously called `xtcp_p2p_connect_yamux` with
  `candidates=&[]`, `behavior=None`, and the peer addresses stuffed into
  `assisted`, so the simplified punch always failed with "no candidate
  addresses" and XTCP provider-side hole punching never actually ran. Both
  provider paths (`handle_nat_hole_resp` and the legacy `handle_nat_hole_client`)
  now pass `candidates`/`assisted`/`detect_behavior` per Go semantics.
  `punch_udp_hole_makehole_owned` in `frp-core/src/xtcp_p2p.rs` was aligned with Go
  `pkg/nathole/nathole.go` MakeHole: the winning socket (the one the peer's
  detect reply arrived on) is now returned and used for the KCP data plane
  (`result.lConn` semantics); probe TTL is set for the detect phase and
  restored afterwards (`ttl<=0` leaves it untouched); `send_random_ports`
  probes that many distinct random ports in [1024, 65535] concurrently (15 ms
  apart, Go `sendSidMessageToRandomPorts`) instead of a clamped 8-port window;
  `candidate_ports` range scanning now sleeps 2 ms per port (Go
  `sendSidMessageToRangePorts`); and NatHoleSid `nonce` is a random 0-19 '0'
  string like Go (`strings.Repeat("0", rand.IntN(20))`).

- **Rust frps XTCP coordination fix**: `detect_behavior` (role/ttl/send_delay/
  read_timeout chosen by the 5-mode analyzer) was computed but dropped when
  NatHoleResp was forwarded through `InternalMsg::WriteNatHoleResp`, so Go
  peers received a zero-valued DetectBehavior with an empty Role and their
  MakeHole could not tell sender from receiver — every rust-frps XTCP scenario
  with a Go peer failed. The internal message now carries `detect_behavior`
  and all construction sites fill it. Verified: XTCP pairwise compat went
  from 4/16 (main) / 10/16 (MakeHole work) to **16/16**, and the full
  68-scenario suite is green.

- **V2 post-handshake Login read timeout**: after a V2 ClientHello handshake,
  the read of the next frame (the Login message) is now bounded by the same
  10s `V2_HANDSHAKE_TIMEOUT` as the handshake itself, closing a gap where a
  peer that completed ClientHello but never sent Login could pin a server
  task / file descriptor forever. All server-side V2 accept paths (TCP,
  TCP+yamux, TLS, WebSocket, KCP, KCP+yamux, QUIC) now align with Go frp
  v0.70.1's single `connReadTimeout = 10s` deadline covering magic read +
  ClientHello/ServerHello exchange + first message.

- **Connection read timeout parity**: the new-connection read timeout now
  matches Go frp's compile-time `connReadTimeout = 10s` constant
  (`server/service.go`, not configurable). Removed the inner 5s timeout in
  `detect_and_strip_magic` so the caller's 10s wrapper governs; raised the V2
  handshake read timeout from 5s to 10s; aligned the TLS SNI peek and the
  TLS-encrypted WebSocket first-byte peek to 10s. Corrected the
  `detect_and_strip_magic` doc comment that wrongly claimed Go frp exposes
  `connReadTimeout` as configurable `ServerConfig.Transport.connReadTimeout`.

## v0.7.1 — Go frp v0.70.1 Source-Level Compatibility Audit

Full-source audit of Go frp v0.70.1 (fatedier/frp) against frp-rs. 106 findings
from 6 parallel subagent audits, 60+ fixes across 37 files. Every fix references
the exact Go frp source location that mandates the behavior.

### Post-Release Review Fixes (2026-08-01)

Second parallel audit pass focused on the staged 0.7.1 review-fix wave:

- **yamux liveness**: dead-peer retention is bounded by transport I/O while
  healthy idle sessions stay open; zero keepalive intervals are normalized.
- **Work-conn admission**: removed the client-side 64-inflight/128-queue cap
  that diverged from Go frp and could tear down the control session; each
  `ReqWorkConn` is spawned directly, matching Go v0.70.1.
- **Heartbeat defaults**: application heartbeats are disabled under `tcp_mux`
  by default (Go parity) while explicit values are preserved; `dialServerTimeout`
  zero means default, and explicit server heartbeat timeouts are kept.
- **QUIC**: zero option values normalize to Go defaults; pre-auth timeout/error
  paths close the connection; first-frame deadline starts after stream accept;
  preauth stream admission is bounded after acceptance.
- **OIDC**: authorization keeps the claimed `login.user` (Go parity); subject
  generation-scoped cleanup prevents supersession clobbering.
- **STCP/XTCP visitors**: legacy visitors without `run_id` and fresh-TCP NAT
  visitors use Go owner/allow-list admission instead of failing closed.
- **SSH gateway**: raw exec commands are no longer logged; reverse forwarding
  (`-R`) is disabled until a safe listener implementation lands.
- **mTLS**: `trustedCaFile` always requires and verifies client certificates;
  partial cert/key configs fail startup.
- **Log sanitization**: client/server control logs no longer emit full JSON
  payloads, STCP secrets, or V1 payload text.
- **Config**: Go `[transport.tls]`, server `[transport] tcpMux`, and related
  camelCase keys are normalized; WebSocket raw frames allow V2 payloads.
- **Client plugins**: Go-style flat plugin configs (`plugin = "unix_domain_socket"`
  with `plugin_local_addr`, `plugin_http_user`, etc.) are normalized to the
  nested plugin shape, fixing Docker socket and other Go frp plugin configs.
- **Config aliases**: proxy `localIP` / `localPort` camelCase fields are now
  parsed, matching Go frp configs that previously left `local_port` at 0 and
  made frpc dial `127.0.0.1:0`.
- **Config audit**: additional Go camelCase mappings added for `webServer`,
  `httpPlugins`, `featureGates`, `allowPorts` arrays, `customDomains`,
  proxy/visitor `metadatas`, `subDomainHost`, `tcpmuxPassthrough`,
  `detailedErrorsToClient`, `enablePrometheus`, `poolCount`,
  `additionalScopes`, OIDC `skipExpiryCheck`/`skipIssuerCheck`, visitor
  `[transport]`/`[natTraversal]`, plugin `unixPath`/`crtPath`/`keyPath`, and
  legacy flat `plugin_*` fields.
- **Config audit phase 2**: parse `healthCheck.httpHeaders` Go arrays,
  `webServer.assetsDir`/`pprofEnable`/`webServer.tls`, `log.disablePrintColor`,
  `httpPlugins.tlsVerify`, plugin `requestHeaders`/`enableHTTP2`, visitor
  `enabled`, and proxy `natTraversal`.
- **Store**: implement Go frp `[store] path` file-backed proxy/visitor store
  with admin API CRUD at `/api/store/proxies` and `/api/store/visitors`, plus
  config+store merging and `start` allowlist filtering.
- **Auth tokenSource**: implement Go frp `auth.tokenSource` file/exec dynamic
  token sources for client Login/Ping/NewWorkConn and server validation.
- **VirtualNet**: add `[virtualNet] address`, `virtual_net` proxy plugin, and
  `virtual_net` visitor plugin with route advertisement and bidirectional
  packet delivery. vnet routing is dual-stack (IPv4/IPv6), tunnel bytes honor
  `use_encryption`/`use_compression`, reload re-creates plugin TUNs, visitor
  return traffic is targeted to the owning TUN subnet instead of broadcast,
  and frps broadcasts vnet route advertisements/removals to peers with
  disconnect cleanup.
- **PR review fixes**: `start` allowlist now also filters visitors; vnet OS
  routes injected from peer advertisements are removed on route removal and
  disconnect; vnet tunnels use Go-compatible `[u32 LE length][packet]`
  framing even without compression; `auth.tokenSource` exec commands have a
  10s timeout and kill on expiry; server vnet route removal is guarded by the
  advertising run_id; store files persist with `0600` and validate entries on
  load; `/api/store/*` is documented as a frp-rs-native contract.
- **Concurrency**: per-run_id lifecycle mutexes are reclaimed; ClientRegistry
  lock order is canonical; post-login AEAD failure cleanup is generation-safe.
- **KCP**: login throttling uses the real peer address instead of a shared key.

### Config (19 fixes)

- **QUICOptions**: add `QuicOptions` struct with `keepalive_period` (10s), `max_idle_timeout` (30s), `max_incoming_streams` (100000). Added as `quic_options` field to `ServerTransportConfig` and `ClientConfig` (serde alias "quic").
- **TCPKeepAlive**: add `tcp_keepalive` (default 7200) to `ServerTransportConfig` with alias `tcpKeepAlive`.
- **DialServerTimeout**: add `dial_server_timeout` (default 10) to `ClientConfig` with alias `dialServerTimeout`. Now properly threaded through `ControlConnection` and `WorkConnConfig` to `DialOptions`.
- **WebServer.Addr override**: when `web_server.port > 0 && addr.is_empty()`, set addr to `"0.0.0.0"` in `ServerConfig::complete()`.
- **XTCP visitor protocol**: add `protocol` field (default "quic") to `VisitorConfig` with alias "protocol".
- **pool_count serde default**: changed from `0` to `1` via `default_pool_count()` function.
- **health_check_url default**: changed from `"/"` to `""` (empty string, matching Go frp).
- **tcp_mux (server)**: changed from `bool` to `Option<bool>` to distinguish "not set" from explicit `false`.
- **flatten_to_table overwrite semantics**: change `or_insert` to `insert` so legacy flat fields overwrite v1 nested fields (Go compat).
- **Serde aliases**: add `alias = "clientID"`, `alias = "tlsServerName"`, `alias = "tlsServerName"` on server transport, `alias = "keepalivePeriod"` on `QuicOptions`.
- **allow_port_start default 0→1**: port 0 caused OS-assigned port mismatch (server advertised port 0 but listener was on kernel-chosen port).
- **allow_port_end default 50000→65535**: full port range allowed by default, matching Go frp empty AllowPorts.
- **disable_custom_tls_first_byte serde default**: changed from `#[serde(default)]` (false) to `#[serde(default = "default_true")]` — config-file and programmatic users now get the same default (true).
- **udp_packet_size serde alias**: add `alias = "udpPacketSize"` on `udp_packet_size` field for Go frp config compat.
- **login_fail_exit serde alias**: add `alias = "loginFailExit"` on `login_fail_exit` field for Go frp config compat.
- **dns_server serde alias**: add `alias = "dnsServer"` on `dns_server` field for Go frp config compat.
- **Health check path → url mapping**: `normalize_proxies()` maps `health_check.path` to `health_check_url` (Go frp v0.70.1 aliases `path` as `url` in health check config).
- **Bandwidth_limit GB hint**: validation error message now mentions GB suffix alongside KB/MB (was missing).

### Messages (1 fix)

- **NatHoleReport.success**: changed from `Option<bool>` to `bool` (Go frp v0.70.1 always sends the field).

### Client (13 fixes)

- **V2 handshake pipelining**: split `v2_handshake_client` into `send_hello` / `recv_hello` so Login is sent between ClientHello and ServerHello, matching Go frp's `control_session.go:140-203`.
- **Health check monotonic counter**: `failures` is now a monotonic u64 that never resets on success (matching Go frp behavior). Counter inspected at `/healthz?probe=health`.
- **Health check 500ms startup delay**: first health check delayed by 500ms (matching Go frp).
- **Ping auth always set**: removed `scope_requires_auth` gate so Ping always carries auth credentials.
- **GracefulClose ordering**: signal visitors → drop yamux → wait (three-step sequence matching Go frp's `closeSession()`).
- **Visitor graceful shutdown**: `Arc<AtomicBool>` shutdown signal instead of `handle.abort()` — visitors exit cleanly.
- **STUN default**: changed from empty to `stun.easyvoip.com:3478`.
- **Unique transaction_id per request**: `uuid::Uuid::new_v4()` per message instead of static constant.
- **UDP bind before NatHoleSid**: fix race where NatHoleSid was sent before the UDP socket bind completed (Go frp binds first, then sends).
- **client_spec in Login**: `ClientSpec { client_type: "frpc", always_auth_pass: None }` sent in every Login message (Go frp compat).
- **NewVisitorConn proxy_name**: follows Go frp v0.70.1 `BuildTargetServerProxyName` — prefixes with `server_user` if non-empty, else with client `user` if non-empty, else bare `server_name`. Previously only supported `server_user` prefix.
- **NewVisitorConn run_id**: passes client `run_id` in NewVisitorConn message for server-side session tracking (Go frp compat).
- **UDP work conn keepalive**: sends `Ping` every 30s on UDP work connections to prevent server idle timeout from closing the connection (Go frp `udpWorkConnKeepalive`).

### Server (9 fixes)

- **VHost multi-proxy per domain**: changed from `HashMap<String, VhostRoute>` to `HashMap<String, Vec<VhostRoute>>` with longest location prefix match — multiple proxies can serve the same domain at different locations, matching Go frp's `routerByHTTPUser`.
- **Separate TCP/UDP port managers**: `used_udp_ports` tracking separate from `used_ports`. UDP/SuDP proxies allocate from UDP pool, TCP proxies from TCP pool with OS-level bind probe.
- **Pool pre-filling at startup**: work connection pool is pre-filled during control handler initialization, with replacement after use (matching Go frp).
- **StartWorkConn addr metadata**: always sends `src_addr` and `dst_addr` (removed `proxy_protocol_version` guard).
- **Dashboard API endpoints**: added `/api/traffic/{name}`, `/api/proxy/{type}`, `/api/proxy/{type}/{name}` with type validation and 404 for unknown types.
- **Dashboard healthz**: returns empty body for Go compat (was "ok"); `/healthz?probe=readiness` returns "ok".
- **TCP keepalive**: applied via `socket2` in server accept loop on every raw `TcpStream`.
- **TLS force handling**: proper detection and handling of `tls_only` mode on the server side.
- **NewWorkConn auth simplification**: removed Go frp compat workaround that skipped auth when `privilege_key` was present but timestamp missing — Go frp v0.70.1 always sends timestamp on NewWorkConn messages.

### XTCP / NAT Hole Punch (13 fixes)

- **Mode 3 PortsRangeNumber**: changed from `sender(0,0,0,0,0)` to `sender(0,0,10,0,0)` (was 0, Go frp uses 10).
- **Score bias**: non-fallback entries now score 0 instead of 1 (matching Go frp — entries only selected after `report_success` boosts them).
- **lastUpdateTime unconditional**: moved before the analysis loop — analyst update time always recorded.
- **IPv6 support**: removed `!ip.contains(':')` filter from `parse_ips()` — IPv6 addresses now parsed correctly.
- **Visitor read_timeout_ms**: extracted from `NatHoleResp.detect_behavior` instead of hardcoded value.
- **Configurable p2p_protocol**: visitor uses `p2p_protocol` from config instead of hardcoded "kcp".
- **Analysis key MD5 format**: `gen_analysis_key()` rewritten to produce MD5 hex string matching Go frp format.
- **NatHoleReport success tracking**: `send_nat_hole_report()` takes `success: bool` parameter, forwarded through the analysis pipeline.
- **5-mode behavior table**: full implementation matching Go frp's NAT classification state machine.
- **STUN OTHER-ADDRESS parsing**: 0x802c attribute for dual-server NAT probing.
- **Classify NAT feature**: `parse_ips` handles all address formats from Go frp's STUN library.
- **Controller session management**: session creation with timeout, provider registration, bidirectional NatHoleResp delivery.
- **Analysis scoring**: incremental `report_success` boosts, proper fallback mode initialization with score=1.

### Transports (8 fixes)

- **DialOptions default**: `disable_custom_tls_first_byte` changed from `false` to `true` in `DialOptions::default()`.
- **Server TCP keepalive**: `set_keepalive()` public function via `socket2` for outbound connections.
- **IoStream::Tls peer_addr**: TLS variant now carries `SocketAddr` for peer address tracking.
- **TLS force**: server handles `tls_only` mode correctly on the accept path.
- **Tiny/micro build fix**: removed `#[cfg(feature = "websocket")]` gate from `use std::time::Duration` (was breaking `set_keepalive`).
- **QUIC ECN doc note**: documented gap — Go frp sets `QUIC_GO_DISABLE_ECN=true`, quinn doesn't expose ECN control.
- **WebSocket comments**: clarify frame boundary handling and dispatch order.
- **KCP ACKNoDelay comment**: verify Rust kcp crate default (batched ACKs) matches Go frp's `SetACKNoDelay(false)`.

### Upgrade Notes: v0.7.0 → v0.7.1

This release aligns config defaults with Go frp v0.70.1. Existing configs that
relied on previous defaults may need updating.

#### Client defaults changed

- **`tls_enable`**: changed from `false` to `true`. If your frps does not
  have TLS configured, set `tls_enable = false` explicitly in frpc.toml.
- **`disable_custom_tls_first_byte`**: changed from `false` to `true`.
  Go frp v0.70.1 no longer sends the FRPTLSHeadByte before TLS handshake.
  If connecting to older frps (< v0.70.1), set this to `false`.
- **`tcp_mux`**: changed from feature-gated (`--features tcp-mux`) to
  always-on (`true`). If you do not want yamux multiplexing, set
  `tcp_mux = false` explicitly. When `tcp_mux` is enabled, heartbeats
  are disabled automatically (yamux provides keepalive).
- **`nat_hole_stun_server`**: changed from empty (`""`) to
  `"stun.easyvoip.com:3478"`. If you need a different STUN server,
  set it explicitly.
- **`tcp_mux_keepalive_interval`**: new field, defaults to `30`
  (seconds). Controls yamux keepalive ping interval.
- **`heartbeat_timeout`**: new field, defaults to `90` (seconds).
  Set to `-1` when `tcp_mux = true` (yamux provides keepalive).

#### Server defaults changed

- **`max_ports_per_client`**: changed from `50` to `0` (unlimited).
  To restore the old limit, set `max_ports_per_client = 50`.
- **`auth.authentication_timeout`**: changed from `15` to `0`.
- **`graceful_timeout`**: changed from `15` to `0`.
- **`web_server.addr`**: changed from `""` (bind all interfaces) to
  `"127.0.0.1"` (localhost only). This is a security hardening change.
  If the dashboard/admin API must be reachable from remote hosts, set
  `web_server.addr = "0.0.0.0"`.

#### Proxy defaults changed

- **`local_ip`**: changed from `""` (empty) to `"127.0.0.1"`.
  If your local service binds a different address, set `local_ip`
  explicitly.
- **`bandwidth_limit_mode`**: changed from `""` (both directions) to
  `"client"` (upload only). If you explicitly set `bandwidth_limit` and
  want to throttle both upload and download, set
  `bandwidth_limit_mode = ""`.

#### Bandwidth limit parsing tightened

The `bandwidth_limit` field now requires a "KB", "MB", or "GB" suffix
(case-insensitive). Bare numbers (e.g., `"500"`) and single-letter
suffixes (e.g., `"500K"`) are rejected. Use the full suffix: `"500KB"`,
`"10MB"`, `"1GB"`. Empty `bandwidth_limit` means "no limit" (matching
Go frp behavior).

#### Port range defaults expanded

`allow_port_start` changed from 10000 to 1, `allow_port_end` from 50000 to 65535.
All ports are now allowed by default (matching Go frp empty AllowPorts).

### Binary Size Optimization

Three-phase binary size reduction: frps -36% (8.18→5.20 MB), frpc -13% (6.24→5.42 MB)
in the default build. Full-feature build (`--features "ssh,quic,dashboard"`) unchanged.

#### Feature Flags: QUIC/Dashboard Opt-In, SSH Default

- **SSH** (russh + rand010, ~407 KB) → enabled by default.
- **QUIC** (quinn, ~280 KB) → opt-in. Enable with `--features quic`.
- **Dashboard** (prometheus + axum, ~181 KB) → opt-in. Enable with `--features dashboard`.
- QUIC/dashboard removed from default features; SSH remains default. Transitive dependencies for QUIC/dashboard eliminated wholesale.
- Feature forwarding added in frps/frpc Cargo.toml for all optional features.
- `toml_edit` already removed in favor of `toml` 0.8.

#### Code-Level Optimizations

- **Type erasure for authenticate**: Changed from generic to `Box<dyn AsyncReadWriteUnpin>` with `#[inline(never)]`. Eliminates dual monomorphization. Saved ~37 KB.
- **Box large async futures**: Added `spawn_boxed()` helper using unsizing coercion to erase concrete future types. Boxed dispatch match block in main accept handler. Saved ~36 KB.
- **Dispatch split**: Non-async match functions returning `Pin<Box<dyn Future + Send>>` replace N-variant async state machines. `dispatch_frp_message` reduced from 43 KB to 206 bytes.
- **Validation extraction**: `validate_new_proxy()` pure function removes 5 `.await` points from `handle_new_proxy`.
- **anyhow backtrace disabled**: Changed to `default-features = false, features = ["std"]`. Added minimal panic hooks.
- **Nightly infrastructure**: Added `nightly = []` feature placeholder.

#### Binary Sizes

| Build | frps | frpc |
|-------|------|------|
| Default | ~5.6 MB | ~5.4 MB |
| Full (`--features "ssh,quic,dashboard"`) | ~7.8 MB | ~6.0 MB |
| Tiny (`--no-default-features --features tiny`) | ~4.4 MB | ~3.8 MB |
| Micro (`--no-default-features --features micro`) | ~2.6 MB | ~2.7 MB |

#### Upgrade Notes

- **QUIC and dashboard are now opt-in.** If you use QUIC transport or the
  dashboard/metrics API, add `--features "quic,dashboard"` to your build.
  SSH is enabled by default.
- **Config files unchanged.** All config parsing and defaults are identical.
- **No wire protocol changes.** Compatible with Go frp v0.70.1.

## v0.7.0 (2026-07-21)

### Go frp dev HEAD Full Audit (d486018)

Full-source audit of Go frp dev branch against frp-rs, fixing 18 findings (7 CRITICAL, 11 MEDIUM).

**Server control plane (3 critical):**
- Two-phase login: Admit → Handoff Wait → Activate/LoginResp matching Go frp dev's ControlManager lifecycle
- ClientRegistry with `control_id`-aware `register_with_control_id()` and `mark_offline_by_run_id_and_control_id()` — prevents stale handler mutations
- Generation-aware control replacement: per-runID handoff barrier ensures old handler is fully shut down before new one activates

**XTCP/NAT hole punch (3 critical):**
- PublicNetwork detection: pass assisted_addrs as local_ips to classify_nat_feature (was always false with empty slice)
- STUN OTHER-ADDRESS (0x802c) attribute parsing for dual-server NAT probing matching Go discovery.go
- Visitor assisted_addrs: build local-IP-based addresses (ListLocalIPsForNatHole) instead of sending STUN mapped addresses

**Auth/Config (1 critical, 4 medium):**
- Token auth: no timestamp freshness check by default (matching Go's MD5-only VerifyLogin)
- heartbeat_interval = -1 when tcp_mux enabled (yamux provides keepalive)
- nat_hole_stun_server defaults to "stun.easyvoip.com:3478"
- tcp_mux unconditionally defaults to true (not feature-gated)
- proxy_bind_addr inherits from bind_addr when empty

**Client (2 medium):**
- Heartbeat timeout detection: track last_pong, trigger reconnect on timeout
- Proxy phase state machine foundation: New → WaitStart → StartErr → Running → CheckFailed → Closed enum with phase field (currently transitions New/Running/StartErr; WaitStart/CheckFailed/Closed reserved for future retry worker)

**Server misc (5 medium):**
- TCP group shared listener per group with round-robin dispatch
- HTTP group health-check-aware backend selection (skip unhealthy, 30s recovery)
- Bandwidth limit mode: server-side limiters only for `mode == "server"` (matching Go)
- AlwaysAuthPass for internal SSH gateway connections
- ServerAdditionalAuthScopes defaults to empty (Go compat)

**Docs:**
- Clarify KCP XOR encryption is not needed for Go compat (Go passes nil blockCrypt)
- Clarify group health checks are not a Go compat gap (Go only accepts "", "tcp", "http")

### Security

- Constant-time comparison for HTTP Basic Auth and proxy credentials
- Auth hardening: `check_startup()` rejects empty tokens at startup, dynamic token resolution with zeroize on Drop
- Login throttle: split check/record to close race window, memory leak cleanup, throttle check before authentication
- Connection limits: `max_connections` in ServerConfig (was hardcoded 10000), per-IP rate limiting
- OIDC: fix subject leak in error paths, validate proxy name/length
- SSH: host key permissions set to 0600
- Dashboard: bind to localhost when no admin credentials configured
- Remove `unsafe` from ResponseHeaderInjector (safe slice manipulation)
- Fix async mutex held across await in NAT hole handler and session read lock
- Client: fix TOCTOU race in static file serving, secure admin API endpoints, hash secret key in config snapshot
- Client: redact secret key in STCP visitor auth debug log
- Client: split HTTP buffer on header terminator to prevent request smuggling
- Client: handle IPv6 bracket notation in host:port parsing
- Cipher: fix partial-write re-encrypt bug — buffer encrypted output on subsequent writes
- Server: RwLock poison recovery via `RwLockExt` trait (26 sites) — single panicked task no longer cascades
- Deps: drop unmaintained `rustls-pemfile` (RUSTSEC-2025-0134), migrate cert/key parsing to `rustls::pki_types::pem::PemObject`
- Deps: remove `hex` crate — replaced with inline `hex_encode` in frp-core (saves ~30-50KB)
- Box 5 largest `FrpMessage` variants (NewProxy, Login, NatHoleResp, StartWorkConn, NatHoleClient) to reduce stack size
- V1 payload buffer pooling: reuse `BufferPool` for V1 message deserialization
- Snappy decompression bomb guard: 128KB per-chunk output limit
- Dashboard: security response headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy)
- Accept-loop timer cleanup: expire stale `pending_udp` entries (10s timeout)
- Accept-loop: replace fragile `front()+pop_front().unwrap()` patterns with `while let Some(...)` in pool
- Accept-loop: add graceful shutdown via CancellationToken to VHost, TCPMux, SSH listeners
- Accept-loop: replace 26 `Mutex::lock().unwrap()` with poison recovery `unwrap_or_else(|e| e.into_inner())`
- OIDC: JWT algorithm allowlist (RS256/384/512, ES256/384, PS256/384/512, HS256/384/512)
- OIDC: add `oidc_skip_nbf` flag to skip `nbf` validation
- HTTP: sanitize CR/LF from `host_header_rewrite` and `response_headers` to prevent header injection
- Dashboard: `DELETE /api/proxy/{name}` sends `CloseProxy` to client for proper cleanup
- Remove dead code: KCP peer_addr, splice zero-copy (165 lines)
- Known config keys: add `max_connections`, `graceful_shutdown_timeout` to type checker
- Remove unused deps: `bytes`, `libc` (dead direct dependencies)
- Security: constant-time comparison for admin auth (`constant_time_eq_str`)
- Login replay protection: timestamp freshness validation + (run_id, timestamp) duplicate detection with UUID fallback
- Login throttle: count ALL attempts atomically in single operation (fix TOCTOU-prone two-phase check)
- HTTP proxy CONNECT: per-line read limit (16KB), total header limit (64KB) to prevent request smuggling
- Doc: document `simple_glob` single-`*` limitation, sequential proxy registration, test coverage gaps
- Config defaults aligned with Go frp v0.70.0: `pool_count` (0→1), `dial_server_keepalive` (0→7200), `fallback_timeout_ms` (5000→1000), `min_retry_interval` (30→90), visitor `bind_addr` (0.0.0.0→127.0.0.1), `detailed_errors_to_client` (false→true), `nat_hole_analysis_data_reserve_hours` (1→168)
- Config defaults aligned with Go frp dev (fe79598): `tls_enable` (false→true), `disable_custom_tls_first_byte` (false→true), `local_ip` (""→"127.0.0.1"), `bandwidth_limit_mode` (""→"client"), health check defaults (timeout=3, max_failed=1, interval=10)
- ⚠️ **Migration:** `tls_enable` now defaults to `true` (matches Go frp dev). Existing non-TLS deployments must explicitly set `tls_enable = false` in their config, or connections will fail with TLS negotiation errors.
- Token auth: remove timestamp freshness check (Go only checks hash equality), `authentication_timeout` 15→300 (OIDC only)
- XTCP: wire `disable_assisted_addrs` — visitor sends STUN addresses as assisted_addrs for NAT classification
- HTTP: wire `route_by_http_user` — flows through ProxyInfo→VhostRoute→serve_vhost_request, matching Go behavior
- Server: wire `bandwidth_limit` in bridge + dashboard_v2; wire `response_headers` via ResponseHeaderInjector for HTTP/HTTPS
- DNS resolved IP now used for KCP/QUIC dials
- XTCP PreCheck: two-phase `NatHoleVisitor` validates before STUN
- `bandwidth_limit_mode`: empty/unspecified applies both directions (client+server gates)
- `frpc --log-file`: add CLI flag with CLI-overrides-config pattern
- KCP XOR: documented as unimplemented (KcpConfig lacks crypt field in Go frp)
- Group health checks: documented compat gap (TODO)

### Added

- Virtual Net L3 VPN: new `type = "vnet"` proxy with TUN device routing
- New `frp-vnet` crate: cross-platform TUN (Linux/macOS), CIDR routing table, VnetController
- Server-side vnet route management with subnet conflict detection
- Client-side VnetController: TUN↔work_conn bidirectional packet loop
- OS route injection for peer subnet reachability (Linux, macOS)
- Feature-gated behind `vnet` flag (full=on, tiny/micro=off)
- KCP: removed vendored `rust_tokio_kcp` (~5900 lines), replaced with 1502-line direct tokio-KCP module (`frp-core/src/kcp/`)

### Performance

- Replace `Box<dyn>` with `ReadHalf`/`WriteHalf` enums in `into_split()` — zero heap allocs per split, static dispatch (#161)
- Remove `.into_boxed()` in client control writer hot path — zero alloc in send path
- ReqWorkConn pre-warming for both V1 and V2+AEAD paths (reduces proxy connection latency)
- Pool replenishment for XTCP work connections (Go frp v0.70 compat — prevents pool exhaustion under XTCP load)
- `used_timestamps`: BTreeMap `split_off` O(log n) cleanup (was O(n) retain scan)
- ProxyManager: return `Arc<ProxyInfo>` to avoid expensive clones in hot path

### Fixed

- KCP FEC: wire format now matches Go kcp-go (6-byte header + inter-packet FEC encoding)
- KCP: proper poll_flush via force_flush in driver loop, fix busy-spin on idle connections
- KCP: Go↔Rust cross-compat FEC defaults + session routing
- WebSocket: fix pipelined-data framing (partial frame boundary handling)
- Cipher: buffer encrypted output on subsequent partial writes (re-encrypt on split writes)
- STCP: apply encryption to pure-relay visitor path, use configured encryption in fallback relay
- Client: cancel old visitor tasks on reconnect (no more orphaned tasks), exponential backoff
- Client: restore health check cancellation (no more leaked health check tasks)
- Accept empty token at login for backward compatibility (startup check still guards)
- Bridge diagnostic logs downgraded from ERROR to debug/trace/warn
- Clippy: fix warnings for Rust 1.96.0 (manual_inspect, io_other_error, manual_div_ceil, vec_init_then_push, collapsible_if)
- VNet: fix missing IntoRawFd import, remove stale `#[cfg(vnet)]` gates from NewProxy
- Server `udp_packet_size`: default 1500 (erroneously matched Go's `d.DefaultUDPPacketSize` not `DefaultUDPPacketSize`) restored to 65535
- Remove unused `collapsible_match` allow attributes (#163)
- Remove dead code, replace `into_boxed()` with `From` impl
- Support pre-built frps/frpc in integration tests (honor `FRPS_BIN`/`FRPC_BIN` env vars)
- XTCP P2P: KCP conv=1 for Go kcp-go cross-language compat (root cause of 8/16 failing XTCP compat; now 16/16 PASS)
- XTCP P2P: yamux background driver — poll_read after poll_flush no longer drops accepted streams
- XTCP P2P: Go-compatible KCP config (nodelay, window 128→256, MTU 1350→1400, FEC defaults)
- XTCP P2P: Go↔Rust hole-punch deadlock and yamux 30s timeout fix
- XTCP P2P: remove STUN address dedup (Go frp sends raw STUN results without dedup)
- XTCP P2P: MD5 hash for KCP conv derivation (was DefaultHasher; matches Go kcp-go)
- XTCP P2P: pre_check before sign_key dispatch order (matches Go frp handler.go)
- Micro/tiny: add `default_kcp_config` to no-kcp fallback module (fix build for frp-client NAT hole handlers)
- Supersession safety: old handler cleanup captures proxy names before removing from registry
- KCP/QUIC accept errors: continue with backoff instead of breaking accept loop
- Listener bind: report success/failure via oneshot channels (no more silent failures)
- OTel layer ordering: bare Registry before EnvFilter (fix log level propagation)
- UDP reader/writer: check `session_alive` to prevent indefinite hangs after session close
- Shared logging: extract to `frp-core::logging` (~300 lines deduplicated across frps/frpc)
- VhostManager: single RwLock consolidation (eliminates TOCTOU between table operations)
- `IoStream::into_split()`: return `Result` instead of panicking on unsupported stream type
- Test: replace 300ms sleep with /healthz polling in `FrpsHandle::start` (faster, more reliable)
- Wire compat: `NatHoleSid` — add `transaction_id`, `response`, `nonce` fields matching Go frp v0.70.0 (Go uses these for MakeHole UDP detection)
- Wire compat: `NatHoleReport` — add `success: Option<bool>` field matching Go `msg.NatHoleReport`
- Go compat: pre-check remove extra `mapped_addrs.is_none()` condition (Go frp only checks `PreCheck` boolean)
- Go compat: Fresh-TCP pre_check validate `allow_users` before returning OK
- Go frp dev compat: V2 max frame payload 64 KiB (was 1 MiB), reject non-zero V2 frame flags
- Go frp dev compat: `read_timeout_ms` JSON key → `read_timeout` (matches Go `NatHoleDetectBehavior`)
- Go frp dev compat: client two-phase fast-backoff reconnect (200ms phase 1, 1s×2ⁿ phase 2)
- Go frp dev compat: 60s sliding window for fast-retry counter (matches `FastBackoffManager.FastRetryWindow`)
- Go frp dev compat: 1s sender delay before NatHoleResp when role is "sender"
- Go frp dev compat: VHost wildcard domain routing (progressive `*` label widening)
- Go frp dev compat: SNI HTTPS routing via `lookup_wildcard` (was exact match)
- Go frp dev compat: gate analyzer `report_success` on `NatHoleReport.success == Some(true)`
- Compat tests: `wait_for_port_safe` falls back to `nc -z` when `lsof` is unavailable
- Compat tests: Rust frpc non-TLS configs explicitly set `tls_enable = false`
- Go compat: `handle_report` only report success to analyzer when `success != Some(false)`
- Go compat: NatHoleReport forwarding pass through `success` field
- XTCP: replace `try_into().unwrap()` with `.map_err()` on untrusted UDP frames (no panics on malformed packets)
- XTCP: log all `send_to` failures instead of silently dropping UDP send errors
- Buffer pool: recover poisoned mutex instead of panicking
- Feature stubs: return defaults instead of panicking when features disabled
- Cleanup: remove `#[allow(unused_mut)]` in v2_handshake and dashboard_v2

### Compat Tests

- Phase 2: 5 transport combo tests enabled (STCP+enc, QUIC+enc, WSS+mux)
- KCP Go↔Rust cross-compat: all transport combos verified (plain/yamux/TLS/TLS+yamux)
- WSS Go↔Rust cross-compat: uncommented g2r WSS tests
- SSH Go frps gateway test: re-enabled
- Fix flaky `go-to-rust-tcp-tls-encrypt`: retry on empty reply in send_and_expect
- Add 100ms delay to echo server before close (reduces timing races)
- Default test suite: 40 passing + 2 guarded (XTCP 16-test matrix, V2 protocol)
- Integration tests: add auth tokens to all server tests
- HTTP compat: 3 new Go→Rust tests (basic auth, host_header_rewrite, subdomain) — 60/60 total
- Reload: new integration test (reload_integration.rs) — SIGUSR1 client-side config reload e2e

## [0.3.2] - 2026-06-30

### Added
- File-backed persistence for proxy config store (#46) — dashboard CRUD survives restarts via atomic JSON file (`frps_store.json`)
- Dashboard TLS CLI flags and config normalization (#61) — `--dashboard-tls-cert-file`, `--dashboard-tls-key-file` wired to WebServerConfig
- Property-based tests for config TOML→JSON normalization (#56) — proptest idempotency, flat↔nested equivalence, camelCase→snake_case
- Fuzz/property-based tests for V1/V2 protocol frame parsing (#55) — all 256 type bytes, arbitrary payloads, truncated frames
- Benchmark suite (#60) — expanded from 6 to 10 groups: V2 protocol roundtrip (20 types × 5 benches), bridge plain/encrypted/compressed (1K–1MB), bandwidth limiter accuracy, NAT hole-punch classify+analysis
- CI: benchmark compile check — `cargo bench --workspace --no-run` in CI to catch bench rot

### Changed
- frp-server: criterion dev-dep + `[[bench]]` harness for nathole benchmarks
- frp-core: `deserialize_v1` made public for bench access

## [0.3.1] - 2026-06-28

### Added
- V2 compat test auto-build: `build_go_frp_v2()` clones Go frp v0.69.1 + `go build` when Go compiler available, caches to `/tmp/frp-source-build/`
- CI: `setup-go@v5` + cache `/tmp/frp-source-build/` for V2 test source builds
- XTCP e2e test: full NatHole message routing test (visitor↔provider via server relay)

### Fixed
- g2r V2 test: removed duplicate `transport.tls.enable=false` causing Go frpc TOML parse error
- r2g V2 test: added missing Rust frpc launch (test wrote config but never started frpc)
- g2r_quic test: enabled by default (was guarded behind `RUN_QUIC_G2R=1`); root cause was stale debug build, release build works
- XTCP message routing: server now matches Go frp v0.69.1 architecture exactly:
  - Provider notification via `NatHoleSid` on **work connection** (prefixed with `StartWorkConn` for routing)
  - `NatHoleClient` direction reversed: **provider→server** (not server→provider)
  - Address crossover corrected: visitor gets provider's STUN addresses, provider gets visitor's
  - PreCheck: stateless validation returns `NatHoleResp(OK)` without session creation
  - Server NEVER does STUN — pure relay (Go frp compat)
- STUN discovery: use `tokio::net::lookup_host` for DNS resolution of STUN server hostnames
- `pending_nat_hole_sids` queue: added 10s timeout eviction (matches other pending queues)
- xtcp_hole_punch test: fixed `NewWorkConn` Default compile error

### Changed
- XTCP tests guarded behind `RUN_XTCP=1` (requires public internet for actual QUIC/UDP hole punching)
- V2 tests: enabled locally (auto-detect Go), skipped in CI by default due to known V2 frame parsing bug (`V2 frame payload too large: 34408960`). Set `GO_FRP_V2=1` to enable in CI
- Compat test suite: 40 default tests pass, 2 guarded (was 39 default, 5 guarded)
- `InternalMsg::NatHoleClient` deprecated — Go frp compat uses `NatHoleSidOnWorkConn` on work connections

## [0.3.0] - 2026-06-28

### Added
- V2 AEAD encryption + capability negotiation (Login plaintext, AEAD after LoginResp, crypto negotiation in handshake)
- XTCP Go↔Rust cross-compat (NAT hole punch coordination with STUN discovery)
- QUIC Go↔Rust cross-compat (multi-stream QuicConnection wrapper for quic-go interop)
- XTCP compat tests (g2r_xtcp, r2g_xtcp) — guarded behind `RUN_XTCP=1` (requires public internet)
- V2 compat tests (g2r_v2_tcp, r2g_v2_tcp) — guarded behind `GO_FRP_V2=1` (requires source-built Go frp)

### Fixed
- Compat test retry logic: `send_and_expect` and `send_and_expect_udp` now use short per-attempt timeout (min 3s) with proper retry loop, instead of consuming the full deadline on a single attempt
- Compat test timing races: added startup delays for UDP (1s), tcpmux (2s), XTCP (2s), QUIC (2s) tests to allow work connection assignment and routing propagation
- QUIC g2r test guarded behind `RUN_QUIC_G2R=1` (Go frpc v0.69.1 pre-built binary QUIC work-connection limitation)
- g2r_udp, g2r_tcpmux tests now stable (39/39 default tests pass)

### Changed
- 100% feature parity with Go frp v0.69.1 (was ~98-99%)
- Compat test suite: 39 default tests + 5 guarded (was 31 tests)
- Updated README, audit doc, and CLAUDE.md to reflect parity status

## [0.2.1] - 2026-06-27

### Added
- SSH Tunnel Gateway (full ssh -R support, auto-gen Ed25519 keys)
- Reconnect backoff: min(24s×n, 720s) × jitter[0.8, 1.2] — matches Go frp v0.69.1
- Group load balancing: true round-robin with per-group atomic counter
- Admin `/api/status`: reports actual plugin, remote_addr, err; reflects registration state
- Config reload: CloseProxy+NewProxy cycle handles add/remove/modify (config_snapshot hash diff)
- KCP parameters: window 1024, MTU 1350 — matches Go frp
- XTCP NAT hole punch: full controller + analysis engine + STUN discovery
- QUIC Go↔Rust cross-compat: multi-stream QuicConnection wrapper
- Client `/api/metrics`: Prometheus-format endpoint
- Dynamic token sourcing (file://, exec://)
- OIDC custom TLS (TrustedCaFile, insecure_skip_verify)
- OIDC non-caching token source fallback (60s refresh buffer)

### Changed
- ~98-99% feature parity with Go frp v0.69.1 (was ~90%)
- Compat test suite: 31 tests (was 18)

### SSH Added to Default Features

SSH gateway (russh + rand010) added to default features. Default frps now
includes SSH support (~4.1 MB). Tiny and micro profiles unchanged.
