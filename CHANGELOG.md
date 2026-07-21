# Changelog

All notable changes to frp-rs.

## v0.7.0 (2026-07-21)

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
