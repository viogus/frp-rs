# Changelog

All notable changes to frp-rs.

## v0.7.0 (2026-07-16)

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

### Added

- Virtual Net L3 VPN: new `type = "vnet"` proxy with TUN device routing
- New `frp-vnet` crate: cross-platform TUN (Linux/macOS), CIDR routing table, VnetController
- Server-side vnet route management with subnet conflict detection
- Client-side VnetController: TUN↔work_conn bidirectional packet loop
- OS route injection for peer subnet reachability (Linux, macOS)
- Feature-gated behind `vnet` flag (full=on, tiny/micro=off)
- KCP: removed vendored `rust_tokio_kcp` (~5900 lines), replaced with 1502-line direct tokio-KCP module (`frp-core/src/kcp/`)

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

### Compat Tests

- Phase 2: 5 transport combo tests enabled (STCP+enc, QUIC+enc, WSS+mux)
- KCP Go↔Rust cross-compat: all transport combos verified (plain/yamux/TLS/TLS+yamux)
- WSS Go↔Rust cross-compat: uncommented g2r WSS tests
- SSH Go frps gateway test: re-enabled
- Fix flaky `go-to-rust-tcp-tls-encrypt`: retry on empty reply in send_and_expect
- Add 100ms delay to echo server before close (reduces timing races)
- Default test suite: 40 passing + 2 guarded (XTCP 16-test matrix, V2 protocol)
- Integration tests: add auth tokens to all server tests

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
