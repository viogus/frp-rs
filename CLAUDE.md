# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build / Test / Lint

```bash
cargo build                  # Build all crates
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
cargo run --bin frps -- -c frps.toml
cargo run --bin frpc -- -c frpc.toml
RUST_LOG=debug cargo run --bin frps -- -c frps.toml  # Enable debug logging
```

### Integration Tests Without Building

Integration tests (`frp-server/tests/`) need an `frps` binary. Without `cargo build`, use a pre-built release:

```bash
bash scripts/download-frp-rs.sh         # Download latest release to workspace root
cargo test --workspace --all-features    # Tests find ../frps and ../frpc
```

Or set `FRPS_BIN`/`FRPC_BIN` env vars to point at any pre-built binary:

```bash
FRPS_BIN=/path/to/frps FRPC_BIN=/path/to/frpc cargo test --workspace --all-features
```

### Binary Variants

Four size tiers via feature flags. QUIC and SSH are default; dashboard is opt-in:

```bash
# Default (SSH + QUIC included; no dashboard; keeps TLS, KCP, WS, compression)
cargo build --release -p frps -p frpc
# → frps (~5.3MB), frpc (~4.5MB)
#   (measured 2026-08-08 with the DECLARED release profile: fat-LTO,
#   opt-level=z, strip=symbols, panic=abort — see [profile.release] in
#   Cargo.toml. There is no local `.cargo/config.toml` override anymore
#   (removed 2026-08-09); local `cargo build --release` uses the declared
#   profile. CI workflows still write `lto=false opt-level=2` on runners
#   for build speed, so CI artifact sizes do not reflect release.)

# Full (all features; dashboard is the main opt-in on top of default)
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"
# → frps (~5.7MB), frpc (~4.5MB)

# Tiny (no QUIC/KCP/WS/SSH/OIDC/dashboard/compression; keeps TLS)
cargo build --release -p frps -p frpc --no-default-features --features tiny
# → frps-tiny (~3.3MB), frpc-tiny (~3.2MB)

# Micro (core only: no TLS, compression, chacha20, HTTP proxy, tcp-mux)
cargo build --release -p frps -p frpc --no-default-features --features micro
# → frps-micro (~2.3MB), frpc-micro (~2.2MB)
```

Feature flags across crates:
| Feature | Crate | Removes |
|---------|-------|---------|
| `quic` | frp-core | QUIC transport (quinn) — **default ON** (was opt-in) |
| `kcp` | frp-core | KCP transport (in-tree, kcp-go v5.6.13 aligned) |
| `websocket` | frp-core/server | WebSocket transport (manual RFC 6455 framing, no tungstenite since 2026-08-09) |
| `oidc` | frp-core | OIDC auth (jsonwebtoken, hyper) |
| `ssh` | frp-server | SSH gateway (russh, rand 0.10) |
| `dashboard` | frp-server | Metrics/status API (prometheus, axum) |
| `tls` | frp-core/server/client | TLS encryption (rustls, webpki-roots) |
| `compression` | frp-core | Snappy bridge compression (snap) |
| `chacha20` | frp-core | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | frp-server | HTTP proxy plugin (hyper/http-client) |
| `tcp-mux` | frp-core/server/client | yamux stream multiplexing (~80KB) |
| `vnet` | frp-core/server/client | L3 VPN / TUN device routing |
| `admin` | frp-client | frpc admin API (axum) |
| `admin-auth` | frp-core | shared admin auth helpers (token/basic) |
| `mimalloc` | frps/frpc | mimalloc global allocator (exclusive with mem-profile) — measured no ≥5% throughput gain in the 2026-08 A/B (see `docs/superpowers/notes/2026-08-04-mimalloc-throughput-ab.md`), keep opt-in |
| `mem-profile` | frp-core/server/client | CountingAlloc global allocator + MEMPROFILE emitter (dev only) |
| `profiling` | frp-core | profiling feature gate (dev only) |
| `otel` | frp-core/server/client | OpenTelemetry tracing + OTLP export (~+2-3MB) — frp-server exposes no `otel` feature; frps/frpc forward frp-core's |
| `debug-logs` | frp-core | debug/trace logging (dev only) |

Default features: frps = websocket, kcp, quic, oidc, tls, http-proxy, compression, chacha20, tcp-mux, ssh; frpc = websocket, kcp, quic, oidc, tls, admin, compression, chacha20, tcp-mux. `quic` implies `tls`. `oidc` implies `http-client` (hyper). `ssh` implies `rand`. Note: `frp-core`'s own default includes `vnet`/`stun`/`tcp-mux`, but frps/frpc default binaries do **not** include `vnet` (opt-in) — only the `stun` (NAT hole punch) and `tcp-mux` parts that they forward.

**Opt-in (NOT default):** `dashboard`, `mimalloc`, `otel`, `debug-logs`, `profiling`, `mem-profile`, `vnet` (frps/frpc — L3 VPN/TUN routing, drops frp-vnet from default binaries); `http-proxy` is a server-side opt-in (the client http_proxy plugin compiles unconditionally). `mem-profile` installs a `CountingAlloc` global allocator + a 1 Hz `MEMPROFILE` stderr emitter and is mutually exclusive with `mimalloc` (the `#[global_allocator]` guards are cfg-exclusive — with both enabled neither allocator is installed and the emitter does not run). Off in every shipped build (full/tiny/micro) → production binaries are byte-identical. Enable only for the memory baseline: `cargo build -p frps -p frpc --features mem-profile`. std `GlobalAlloc` + `AtomicUsize`, no new dep.

- No `cargo check` variation needed for day-to-day work — `cargo build` covers the full workspace; ci.yml additionally gates the size tiers with `cargo check --no-default-features --features tiny|micro`.
- Unit tests live inline (`#[cfg(test)] mod tests`); integration tests live in per-crate `tests/` dirs (`frp-server/tests/`, `frp-client/tests/`, `frp-core/tests/`).

## Versioning (mandatory)

**frp-rs 自身版本号严格对齐 Go frp 的发布号** —— frp-rs 的版本号 = 当前兼容目标 Go frp 的版本号（当前 `0.71.0`），不搞独立版本演进。Go frp 发布新版本号时，frp-rs 同步 bump 到相同号。以下位置必须保持一致：

- 各 crate `Cargo.toml` 的 `version`（`frp-core` / `frp-server` / `frp-client` / `frps` / `frpc`）
- `frp-core/src/lib.rs` 的 `VERSION` 常量
- `scripts/download-frp-rs.sh` 的默认版本
- README 中标注的版本号

例外：`frp-vnet` 保持独立版本 `0.1.0`，不受对齐规则影响。

## Development Workflow (mandatory)

Every feature, fix, and test change follows three rules:

1. **Worktree** — create a git worktree (`EnterWorktree`) before any file modification. Never edit directly on the main branch.
2. **Subagents** — dispatch work to subagents (`Agent` or `Workflow` tool). One subagent per logical task, review between tasks.
3. **Compat tests** — after any protocol, transport, encryption, or proxy change, run the cross-compatibility test suite:
   ```bash
   bash scripts/compat-test.sh --verbose
   ```
   CI gate: `.github/workflows/compat.yml` must stay green. Download Go frp first if needed:
   ```bash
   bash scripts/download-go-frp.sh
   ```

## Current Health (2026-08-30)

| Metric | Value |
|--------|-------|
| `cargo clippy` (default) | zero warnings |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | zero warnings |
| `cargo fmt --all -- --check` | zero diffs |
| `cargo test --workspace --all-features` | 1507 passed, 0 failed (full suite incl. dashboard — requires an all-features frps binary, see Testing & Tooling) |
| `cargo build --release` | passes, zero warnings on all 4 profiles (frps ~5.3MB/frpc ~4.5MB default; ~5.7/4.5 full; frps-tiny ~3.3MB/frpc-tiny ~3.2MB; frps-micro ~2.3MB/frpc-micro ~2.2MB — measured 2026-08-08 with the DECLARED release profile (fat-LTO + opt-level=z + strip=symbols + panic=abort); CI dev builds override LTO/opt (`lto=false opt-level=2`, written by ci.yml on runners) for build speed and come out ~70% larger (measured 2026-08-09: 9.1MB vs 5.3MB), so CI artifact sizes do not reflect release; local builds use the declared profile; hyper-based HTTP client + otel/prometheus default-features pruning) |
| `compat-test.sh` (Go frp v0.71.0) | 86 passed, 0 failed (run_test + XTCP pairwise; re-verified locally vs Go 0.71.0 on 2026-08-30) |
| `unsafe` blocks | 17 in frp-core, ~38 in frp-vnet (all with `// SAFETY:` comment) |
| `#[instrument]` spans removed | bridge hot path (conditional logging instead) |
| `hex` crate | removed — inline `hex_encode` in frp-core |
| `data-encoding` crate | removed — inline `frp_core::base64` (encode/decode, standard alphabet) + existing `hex_encode` for the one HEXLOWER log site |
| `let _ =` error discards | all commented (`vhost.rs`, `tcpmux.rs`) |
| `exec://` token source | always blocked by `UnsafeFeatures::default()` |
| Security audit | `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071` + `cargo deny check` before release |
| Go frp parity (2026-08-02) | 20-task pass merged (PR #221): OIDC/QUIC/KCP+TLS/WS/UDP/PROXY/plugin/client-management parity, `{single=N}` allowPorts + 24h reservations, HTTPS vhost SNI passthrough, fail-closed HTTP server plugins, **SSH gateway `ssh -R`** (tcpip-forward/forwarded-tcpip), dashboard offline clients/root auth/store 0600, XTCP **MakeHole** state machine, IPv6 vnet routing |
| Go frp v0.71.0 parity (2026-08-16) | PR #246: UDP packet binary codec (`binary-v1`, V2 frame type 19), version alignment 0.71.0, V2 extension types renumbered 21/22, negative pool_count rejected at login, case-insensitive customDomains check |
| Post-0.71.0 hardening (2026-08-17..22) | PRs #254-#263: vendor yamux 0.14 + stream cap 1024, zero-copy snappy hot paths, 3 LOW data-path fixes, WS-over-TLS stall recovery, ci fmt/clippy/audit fixes, 15-item review (wedge/cipher/splice/metrics/dedup), cargo update, single-writev V2 frames + zero-alloc binary UDP encode |
| Post-0.71.0 hardening (2026-08-24) | PR #267: 3 HIGH leak fixes (server bridge cancel via per-control CancellationToken, KCP dial-driver self-exit via alive_streams counter, client work-conn abort + bounded join), XTCP/STCP bridge cancellation on teardown + proxy deletion (visitor `bridge_until_cancelled` helper; provider per-proxy `p2p_bridge_tokens` cancelled by CloseProxy/HealthEvent::Close/reload), case-insensitive vhost/tcpmux/SNI routing (Go parity), frpc SIGINT/SIGTERM incl. config-dir mode, single-copy KCP send segmentation (drops the `split_off` tail-chain, every byte copied exactly once) |
| Pre-release hardening (2026-08-25) | PR #268 (second full review, 4 finders + 4 adversarial verifiers, 0 refuted): tcpmux Go parity — subdomain expansion via `sub_domain_host` (Go accept/reject semantics), leading-label wildcard customDomains + bare `*` catch-all, wildcard tcpmux lookup (≥3-label guard), trailing-dot trim (lookup-side only, Go `CanonicalHost` parity); OIDC login throttle on all failure paths + JWKS forced-refresh 60s cooldown; replay table `ReplayTable` (incremental total, leading-key prune O(expired), cap evicts oldest key — no per-login O(100k) scan); per-timestamp cap evicts oldest run_id; `POST_HANDSHAKE_READ_TIMEOUT` 30s on 16 accept-path sites (10s accept_deadline regressed OIDC login — Go frpc fetches JWT via proxyURL post-handshake pre-Login); client P2P punch dead-proxy guard (proxy_info_map/CheckFailed) + control-writer JoinHandle abort at teardown; `panic="abort"` kept — unwind measured +17.1% frpc / +14.0% frps (1.15/1.26MB) vs per-connection fault isolation; new compat scenarios `test_g2r_tcpmux_subdomain`/`test_g2r_tcpmux_wildcard` |
| Pre-release hardening round 3 (2026-08-25) | PR #268 commit `d2c1580` (third full review, 14 findings: 1 MEDIUM + 13 LOW, all fixed): **CONNECT routes on request-line authority first** (Go net/http `req.Host = req.URL.Host`, Host header ignored per RFC 7230 §5.3 — round-2 header-first reading corrected); KCP-path direct `read_msg_v1` (4 sites) now bounded by `POST_HANDSHAKE_READ_TIMEOUT` (timeout arm does NOT return — would kill the KCP accept loop; io drops at block end); per-stream V2 magic in `handle_v2_connection` bounded (was unbounded); CloseProxy marks phase `Closed` so a late server nathole session can't punch a deleted proxy; ReplayTable duplicate-check before cap eviction; tcpmux wildcard lookup fast-exits when no `*.` route registered; login replay rejection outside the lock; HTTP/HTTPS vhost rejects subdomain without `sub_domain_host` (Go parity); vhost bracketed-IPv6 trailing-dot trim; subdomain validation relaxed to Go rules (only `.`/`*` rejected); customDomains structure validation removed (Go does none; empty/control-char rejection kept); slowloris ponging variant proves the 30s deadline (not yamux driver dead-time) releases the handler |
| Pre-release hardening round 4 (2026-08-25) | PR #268 commit `51f82a1` (fourth full review, 4 finders + adversarial verify → 1 BLOCKER + 2 MEDIUM + 15 LOW, all fixed): **slowloris ponging test was RED — round-3 claim wrong** (yamux-rs 0.14 ping tag = **2** not 4 — `tag as u8` discriminant Data=0/WindowUpdate=1/Ping=2/GoAway=3, verified in crates.io source; non-Data frames are header-only 12 bytes — the length field is ping id / credit, not a body; pong echoes the id in the length field); **V2_HANDSHAKE_TIMEOUT 10s→30s** (10s was defeating the 30s `POST_HANDSHAKE_READ_TIMEOUT` on every V2 accept path — v2_login_timeout tests re-windowed 15s→35s / 8s→20s); **Go CanonicalHost hasPort-gate parity** in tcpmux+vhost (`canonicalize_host` → Option: SplitHostPort only when colons==1 or bracketed+`"]:`, port must be numeric, portless values kept as-is incl. bracketed `[::1]` which stays unroutable — Go discards the split error → `host=""` unroutable, NOT a 400); `extract_route_host` requires a 3-part request line (missing version or `HTTP/`-prefixed target → 400), case-sensitive `CONNECT` gate, lowercase method → Host-header fallback (Go httpconnect parity); tcpmux `register()` drops orphaned routes on subdomain-shrink reload (wildcard_count stays symmetric — new unit test); ReplayTable duplicate-at-cap test (replay at global cap evicts nothing); login replay rejection now consumes the per-IP throttle slot; CloseProxy skips `New`/`WaitStart` phase (reload re-registration race); stale comments fixed (login.rs ×3, proxy_ops.rs ×2, state.rs) + dispatch.rs stale "10s" log; **vendor/yamux orphan removed** (commit 457647e deliberately reverted to crates.io yamux 0.14 — the vendored batched path measured 114 vs 150.1 MB/s, a net loss; the 1024 stream cap lives in `mux.rs`, not the vendor copy) |
| Pre-release hardening round 5 (2026-08-25) | PR #268 commit `3cead64` (fifth full review, 4 finders + adversarial verify → 4 MEDIUM + 5 LOW comments, all fixed): **tcpmux `register()` no-partial-state** — orphan-route cleanup moved AFTER the conflict check, so a rejected re-registration leaves the old routes intact (rollback is a no-op for tcpmux); **Go `validOptionalPort` parity** — CONNECT request-line port must be all-digits or empty (`:abc` → 400, empty port legal) while Host headers stay lenient (`canonicalize_host` strict/lenient split; vhost inline copy likewise); **Go `parseRequestLine` parity** — `splitn(3, ' ')` + version token must be `HTTP/1.x` (tab-separated request line → malformed 400); **KCP V2 accept paths** (8 sites incl. TLS/TLS+yamux combos) use the `v2_handshake_and_read` helper bounded by post_deadline — the per-read 30s no longer stacks ×3 (~90s) on conn_semaphore; **QUIC V2/V1 first frame** bounded by `post_deadline = max(10s magic deadline, now + 30s)` — the 10s `QUIC_FIRST_FRAME_TIMEOUT` covered magic detection only and could cut a slow pre-Login OIDC JWT fetch via proxyURL (doc: v2_handshake.rs TCP/WS/KCP → TCP/WS/KCP/QUIC); comment-only fixes (login.rs replay-throttle ×2, state.rs ReplayTable cap eviction, proxy_ops.rs wildcard validation, dispatch.rs 30s deadline) |
| Pre-release hardening round 6 (2026-08-26) | PR #268 commit `080ff35` (sixth full review, 4 finders + adversarial verify → 16 confirmed findings, all fixed; 1 refuted, 1 documented deliberate): **pre-auth throttle gate** — login.rs rejects already-throttled IPs before auth work; **health config snapshot** — reload.rs config_snapshot gains health_check_* fields (reload keeps health configs); **Go request-line parity** — version token exactly 8-char `HTTP/X.Y` (ParseHTTPVersion), absolute-form request-target routes on authority, location match strips query, bracket-`]`-then-colon port validation; **empty domains → zero registrations** (Go: `locations=[""]` but buildDomains appends nothing → register loop never runs); tcpmux `route_by_http_user` double-key lookup + duplicate-Host 400 (RFC 7230 §5.4); vhost location sort + HTTP/1.0 400/505 gates; ReplayTable future-timestamp tail prune; XTCP probe reads (peek/header/payload) bounded by probe timeout — consumed bytes wrap into BufferedRead, STCP bridge proceeds; `v2_handshake_and_read` cfg gate `any(websocket,kcp,quic)`; KCP dial-driver exit checks channel close before zero count; visitor retry-sleep cancelled on shutdown; 4 missing `return`s on `cfg(not(tls))` Err paths + import cfg cleanups (ws-only build warnings) |
| Pre-release hardening round 7 (2026-08-26) | PR #269 (seventh full review, 6 finders + adversarial verify → 6 MEDIUM + 7 LOW, all fixed; 1 MEDIUM + 1 LOW found in post-fix diff review, both fixed): **KCP chunk pool** (`CHUNK_POOL_CAP=8`, `Kcp::send(AsRef<[u8]>)`) — the per-32KiB bridge-write alloc+copy is gone; **udp_binary owned decode** (`copy_within`+`truncate`+`mem::take`, reader refills from the buffer pool) — per-packet double copy gone; **stale-control reaper full sweep** — `unregister_control` + `remove_if_control_id` (atomic generation-guarded removal, closes a get-then-remove TOCTOU vs re-login that could destroy a superseding control's fresh registration) + OIDC subject cleanup for swept run_ids; **supersession Shutdown bounded 2s send** (draining-but-busy old control now superseded; wedged one costs ≤2s, no parked tasks); **ssh_gateway control-exit teardown** (CancellationToken + biased select; terminate_ssh_session on control exit); **mux MAX_PENDING_OPEN_REQUESTS=64 + driver drain cap; pending_udp/pending_nat_hole_sids cap 256 oldest-evict; heartbeat clamp 3600s (overflow-proof); TLS connector-key cache carries (mtime,size) stamps** — in-place cert rotation (certbot) re-detected on the next dial; snappy CRC32C verified on decompress (Go does verify — both chunk arms); frpc CloseProxy drops PluginHandle + vnet TUN; `log_way` accept-and-ignore in strict config (Go parity); msg `skip_serializing_if` on `NatHoleReport.success`/`NatHoleVisitor.pre_check` (Go omitempty parity) + `UdpAddr.zone` always emitted; frpc `verify --strict-config`; control select loop `checked_add`→`pending()` degrade; skip-verify rate-limited WARN (300s) |
| Pre-release hardening round 8 (2026-08-28) | PR #273 (eighth full review, rebased onto #272): **h2c slowloris BLOCKER** — `serve_h2c_request` handshake + first accept share one absolute `vhost_http_timeout` deadline (later accepts deliberately undeadlined for idle keep-alive; preface-then-silence no longer parks task + fd + conn_semaphore permit) + `max_header_list_size(4096)` (h2 default 16 MiB × 100 streams = ~1.6 GiB per-connection ceiling); **ini lone-quote panic** — `infer_ini_value` `s[1..s.len()-1]` became `s[1..0]` for a value that is exactly `"`/`'` (abort under `panic=abort`, reachable at startup + reload) — `len >= 2` guard, Go ini.v1 keeps lone quote literal; **login-backoff shutdown race** — initial-login backoff now `select!`s `stop_rx` (bare sleep held cap-1 stop_tx) + cancels detached health/admin tasks; 16 tests landed (h2c preface-timeout red-pre-fix, backoff.rs 0→5, bridge plain/encrypted half-close EOF, unknown-field tolerance ×19 V1 structs, ini/JSON config ×5, duplicate run_id supersession); protocol-matrix 11/11 |
| Test-gap filling round 9 (2026-08-28) | PR #273 (ninth full review: 63 findings, verdict 🟡 — production code healthy, test completeness below standard; every gap filled directly, 6 parallel builders): **114 tests added** (1253 → 1367, 0 failed; fmt/clippy `-D warnings` clean); yamux work-conn validation chain e2e (wrong run_id / bad privilege_key / Login frame → stream dropped, valid NewWorkConn pooled — regression-tests the round-8 auth-bypass fix); login replay × throttle interaction (5 replay rejections consume the per-IP throttle slots; 6th attempt pre-auth-throttled even with fresh ts — surfaced that `test_auth_cfg()` keeps `authentication_timeout=0`, Go-parity replay-OFF); client heartbeat watchdog post-registration + server heartbeat timeout; pool replenishment (ReqWorkConn on miss + dead-pooled-conn re-enqueue); relay integrity (half-close EOF, plain + encrypted); h2c preface-timeout determinism (h2 0.4 `end_stream` pinned on the wire via explicit empty DATA frame + server body drain — respond-drop/conn-drop RST race root-caused and eliminated); vhost subdomain expansion routes; mux 1024-stream cap (cap-hit note: crates.io yamux 0.14 `TooManyStreams` closes the ENTIRE mux session — all streams; Go's fork survives, frp-rs recovers via control reconnect — parity note, not fixed); login_fail_exit both arms; ini/JSON config edges; unknown-field tolerance ×19; **3 production changes**: negative poolCount → config error (fail-fast divergence — Go has no client-side check; Go's server rejects at login control.go:438, already mirrored in frp-rs login.rs; frpc now refuses at load instead of dialing first), client heartbeat clamp 3600s (mirrors server clamp; documented divergence — Go accepts any value), `healthy_resets_error_count` pure fn (no behavior change, unit-testable); test-side parity discovery: Go frps sends one ReqWorkConn pre-warm immediately after LoginResp (`capped_pool_count` floors at 1) — tests drain it before asserting post-rejection silence |
| Round-10 deep review (2026-08-28) | PR #273 commit `ea08ece` (tenth full review, 5 finders + adversarial verify, 2 HIGH + 8 MEDIUM + 6 LOW all fixed, 3 finder claims refuted): **yamux-stream control reads bounded by `CTL_READ_TIMEOUT` 30s** (post-auth half-frame trickle pinned task + fd + semaphore permit + run_id registration — Go bounds via heartbeatWorker `ctl.Close()`); **vnet route advertise membership guard** (advertiser must hold a vnet proxy in the target virtual_net) + **64-route per-client cap** (new keys refused at cap, owned-key updates allowed); **XTCP raw-KCP HWM deadlock** (no tcp-mux builds: silent peer = write half parked forever; now notify OR 10ms timer wake + forced `drive_kcp` drain); vhost dead code removed (`location_routes`/`by_proxy_locations`/`lookup_by_path`, -159 lines — Go locations are domain-scoped only); h2c chunk streaming 64KiB slices (vhost + client plugin — attacker-declared chunk no longer allocs `read_exact(size)`); vnet controller `ControlSink::is_failed()` (queue-full no longer kills TUN pump); tun_macos AF_INET6=30; frpc health defaults `<=0`→default (health.go:57-64 parity, `.max(10)` floor removed); client server_addr default `"0.0.0.0"` (client.go:86); visitor validation mirrors Go validation/visitor.go:42-63 (name/serverName required, bindPort==0 rejected, negative = no-bind, XTCP ∈ kcp|quic); StartWorkConn ports `Option<i32>`→`Option<u16>` (Go uint16 — hostile -1/70000 frames now fail deserialization); LOWs: quic max_idle_timeout VarInt overflow → quinn default, OIDC jti 4KiB cap, ReplayTable `saturating_add`, login rejects `Some("")` run_id; **4 tests added** (1367 → 1371, 0 failed): u16 hostile-frame ×1, visitor validation ×1, vnet membership-guard ×1, vnet 64-cap ×1 (+ fixture for 4 existing vnet tests); documented divergences only: subdomain-expansion dedup (Go `buildDomains` dedups nothing — same routing result), keepTunnelOpenWorker architecture, NewWorkConn plugin order, yamux TooManyStreams session close, negative poolCount fail-fast |
| Round-11 divergence closure + review fixes (2026-08-29) | PR #273 commit `8487528` (round-10's 5 documented divergences closed, each verified against Go v0.71.0 source first; then 3 independent reviews A/B/C → 1 HIGH + 1 MEDIUM + 8 LOW, all fixed): **#19 vhost scheme partition** — routes carry `scheme`, HTTP/HTTPS same-domain proxies both register (Go per-muxer `Routers` in vhost/vhost.go), empty customDomains registers nothing (Go `buildDomains` skips `d != ""`); **#20 keepTunnelOpenWorker** — persistent XTCP tunnel session (`frp-core/src/xtcp_session.rs`, Go KCPTunnelSession/QUICTunnelSession): one hole-punched QUIC/yamux session per proxy reused across user connections; visitor `get_tunnel_conn` signals `startTunnel` on every error path (Go unbuffered-channel drop semantics via cap-1 channel + `AtomicBool` armed parked-gate); budget clamped to `min(20s, fallbackTimeoutMs)` (Go `openTunnel` WithTimeout); **#21 NewWorkConn plugin order** — hook runs BEFORE auth and may replace the message (Go RegisterWorkConn service.go:849-888); TCP path ctl-lookup-first, yamux path runs the mutating hook before validation; **#22 yamux cap hit** — vendored yamux 0.14 (`vendor/yamux`, `[patch.crates-io]`) with per-stream RST on inbound SYN at the stream cap (Go fatedier-fork semantics) instead of a session-killing GoAway; asymmetric-cap regression test; **#23 negative poolCount** — fail-fast kept (loader.rs comment documents the deliberate divergence; mirrors Go server login rejection control.go:438); review fixes: HIGH #19-regression (HTTP↔HTTPS same-domain cross-rejection — conflict check now matches route scheme), MEDIUM provider local dial moved into per-stream spawn with 15s timeout (Go per-stream goroutine model), LOWs (visitor dead-session re-punch signal armed-gated, pacing sleep cancellable, dispatch duplicate ctl re-fetch deleted, yamux `on_window_update` cap log error→debug); **27 tests added** (1371 → 1398, 0 failed); fmt + clippy `-D warnings` clean; compat-test.sh 86/86 green |
| Round-12 independent triple review (2026-08-29) | PR #273 commit `54b6eec` (3 independent reviewers of the full round-11 diff, no shared state, findings cross-checked + Go-source-verified before fixing → 3 MEDIUM + 6 LOW, all fixed): **XTCP tunnel outbound cap session-kill** — 257th outbound open returned TooManyStreams → yamux Cleanup → drop_all_streams killed all 256 bridges + re-punch (Go fatedier fork has no cap, fails per-open); driver now refuses per-open via live-outbound counter + `LiveP2pStream` drop decrement, mirroring the inbound per-stream RST; **vhost scheme-blind lookups** — after the round-11 scheme-partitioned conflict check, HTTP+HTTPS same-domain both register but lookups ignored scheme (no-auth HTTP could land on the HTTPS backend, 401-gate bypass; SNI could pick the HTTP route — Go impossible via separate httpVhostRouter/per-muxer registryRouter); scheme threaded through all lookup paths, false "pre-existing" comment corrected; **500ms probe kill of busy session** — >256-open burst made the probe timeout classify a live session as dead (close → all bridges die → re-punch cascade); timeout now = busy (retry, no close), capacity errors always busy, close only on genuine errors; **HTTPS route_by_http_user** — stored under routes[domain][rubu] while SNI lookup uses "" → unreachable + same-domain different-rubu pairs wrongly coexisted (Go HTTPSProxyConfig has no RouteByHTTPUser); https registers with ""; LOWs: protocol dispatch "" → QUIC (Go else-branch) + visitor empty-protocol normalization (Go EmptyOr), armed-gate Relaxed → Release/Acquire (3/3 reviewers), no-tcp-mux keep-alive probe skip (one-shot session consumption), hp_timeout 5s floor (Go MakeHole `> 0` guard), cancellation-aware punch (~50s teardown linger), QUIC tunnel `_with_params` carries user quic config (Go clientCfg.Transport.QUIC), inbound_tx.reserve 500ms stall raced against driver-drop, vendor yamux RST wire-shape comment; **7 tests added** (1398 → 1405, 0 failed); fmt + clippy `-D warnings` clean; compat-test.sh 86/86 green |
| Pre-release hardening round 13 (2026-08-30) | PR #273 (unified fix batch for the round-8..12 deferred findings + test-gap filling; 69 files, +4565/−769): **2 data-corruption BLOCKERs** — AEAD `claimed` / CipherWriter `first_write_data_len` stash a mid-frame flush claim across polls (old code re-encrypted the same buffer into a duplicate frame on re-poll; multi-chunk write_all could loop forever); XTCP raw-KCP HWM-park select stored as a struct field (`hwm_wait_fut` — round-10's select-inside-poll_write dropped both wakers on future drop → permanent high-water deadlock with tcp-mux off). **yamux lost-wakeup deadlock (vendor patch #2)** — `futures::channel::mpsc` one-poller-per-`Sender` contract broken by `tokio::io::split` read+write halves polling the same `Sender`: a `poll_read` window update overwrote a parked writer's stored waker → the receiver's notify woke the wrong task → writer orphaned forever (reproduced intermittently ~7.5% by `mux_2mib_bidirectional_byte_exact` — 2 MiB each way, 4 tasks, 1 MiB duplex — in both directions, incl. the `poll_close` park); fixed with a dedicated `sender_wu` clone for the read path (README-FRP-RS.md documents both vendor patches); 40/40 repro-loop runs green post-fix. **Go parity closures**: absolute-form (h2c/proxy) auth reads `Proxy-Authorization` only → 407 + Proxy-Authenticate; main-port SNI sniff removed (Go reads only the 0x17/0x16 TLS marker — a wildcard https route no longer hijacks frpc TLS control logins); run_id validation moved to ALL auth paths before VerifyLogin (Go order), `Some("")` normalized to a UUID, `unicode.IsPrint` parity incl. the Latin-1 fast path; 3600s heartbeat clamps removed both sides (Go frpc's 7200 disconnected in a reconnect loop vs Rust frps) with watchdog overflow degrade-to-never-fire; PROXY header only when src_addr non-empty AND src_port != 0; X-Forwarded-For in https2http/https2https preserving the inbound chain; WS control frames masked in client mode (RFC 6455 §5.3) + RSV/mask-direction enforcement; h2c `max_header_list_size(4096)` (was h2 default 16 MiB × 100 streams ≈ 1.6 GiB per conn; the client-side plugin-h2 listener deliberately kept Go's 16 MiB — see round 14) + hop-by-hop list completed (proxy-authenticate/proxy-authorization/te/trailer); CONNECT case-insensitive + 400-on-dial-failure; static_file 64 KiB streaming (old path blocked on `read_to_end`, truncated at 64 MiB with a lying Content-Length); dashboard PathUnescape Go parity (`+` literal, UTF-8 validity, lone `%` rejected); vnet TUN pump survives non-fatal write errors (EMSGSIZE drop, EPIPE/EBADF only terminate) + AF_INET6=30 on macOS; PROXY-v1 builder `Result` (both addrs must parse as `IpAddr` — CRLF injection impossible, Go ResolveTCPAddr parity). **DoS/hardening**: KCP hostile-ACK RTT clamped to KCP_RTO_MAX (u32 overflow = one-packet session kill), stream-mode PUSH frg>0 rejected non-fatally at input(), `send_chunked` splits >~176 KiB writes (was silent loss after UserBufTooBig), chunk pool → lock-free ArrayQueue, `MAX_SESSIONS_PER_IP` removed (same-NAT collateral DoS), dial-driver exit also gates on empty write_rx + no wait_snd; WS upgrade parsing bounded (16 KiB/line, 64 KiB total); config: `udp_packet_size` clamp [0, 65507] (hostile 2^31 = multi-GiB UDP buffers), INI range expansion cap 4096, levenshtein skipped for >256-char keys, `--config-dir` symlink-cycle guard (stack overflow SIGSEGV under panic=abort), unknown visitor types rejected at load; snappy meta-drain budget (4 feeds × ≤1024 frames per poll); ssh_gateway bridge head+payload reads bounded 30s; token-exec bounded 10s on both arms (kill_on_drop / SIGKILL); vnet >MTU pre-reject + 1/s rate-limited warnings; h2c preface slow-drip under ONE absolute `vhost_http_timeout` deadline. **52 tests added (1405 → 1457, 0 failed)**: login retry cadence 2/4/8/10s, Pong{error} single reconnect, registration watchdog during a stalled NewProxyResp, reload virtual_net survival, yamux RST wire shape, run_id + negative pool_count, pool replenishment, in-process Rust↔Rust KCP/QUIC e2e, mux 2 MiB bidirectional byte-exact + window-exhaustion stall, kcp 512 KiB volume, raw-KCP HWM recover (RED on round-10 code), raw-TCP work-conn auth chain, SNI no-hijack, tcpmux negative-window, h2c 431-header-block + 407 + slow-drip; fmt + clippy `-D warnings` clean; compat-test.sh 86/86; protocol-matrix 11/11 |
| Pre-release hardening round 14 (2026-08-30) | PR #273 (fourteenth full review, 5 finders + adversarial verify → 1 HIGH + 7 MEDIUM + 20 LOW, all fixed): **vnet default-net membership null normalization** — server stores empty `virtual_net` as `None` while the wire default is `""`; the old guard `as_deref() == Some(vn)` made `None == Some("")` always false, refusing EVERY default-net route advertise (availability); fixed via `unwrap_or("")` comparison + visitor host-route (/32,/128) admission for proxy-less default-net members (server cannot observe visitors — NewVisitorConn carries no plugin-type field), wide-subnet ads still require a default-net vnet proxy, named-net holders cannot inject default-net routes, 64-route per-client cap bounds all injection. **Control-loop half-frame loss** — consumed bytes were dropped with the discarded branch future when a competing internal msg landed mid-frame → garbage-header parse → control disconnect + reconnect (persistent-disconnect harassment vector); read future now persisted in a loop-outer `Option` (owns an `Arc<tokio::sync::Mutex<ReadHalf>>` clone) + deterministic regression test; fairness invariant (no `biased;`) preserved. **Generation-guarded cleanup** — `remove_if_control_id`: the 10s-barrier cleanup can no longer tear down a next-generation same-name re-registration that landed between snapshot check and removal (get-then-remove TOCTOU); https count decremented from the removed entry itself (double-decrement could silently disable SNI sniff at 0). **Invalid run_id throttle bypass** — flood of invalid-run_id logins never reached the 60s per-IP throttle; now consumes slots like every other pre-auth failure. **WS control-frame violations** — >125B ping truncated to pong; FIN=0 / 126-127 length encodings / stray continuations now protocol errors per RFC 6455 §5.5 (gorilla parity); tests build frames with explicit raw length fields pinning all three. **vhost/h2c** — X-Forwarded-For appended unconditionally (was skipped when response-header config present; Go always appends), `vhost_http_timeout <= 0` → 60s floor (was `.max(1)`), path routed WITHOUT query (Go URL.Path), `route_user` fallback (Authorization Basic username routes the request, 407 not 404), blank first-line 400, h2c declared-Content-Length enforcement (excess body → RST_STREAM PROTOCOL_ERROR — never forwarded as a pipelined request; smuggling closed). **Client** virtual_net reload false-"failed" guard (`plugin_type != "virtual_net"` — plugin_addrs never contains it). **tcpmux** same-call duplicate domains rejected wholesale (Go semantics; silent dedup left asymmetric by_proxy residue). **yamux vendor patches #3/#4** — per-stream receive-window cap + send-side body-buffer pool (ArrayQueue cap 16, returned at WriteState::Body; frame boundaries/write timing unchanged). LOW ×20 (stale comments ×6, Go parity edges ×5 incl. Latin-1 fast path + 400/505 gates, error-path discards ×4, dead code ×3, test determinism ×2). Gate-time regression caught by existing h2c integration tests: the CL-enforcement `oneshot` sender dropped on normal task end → closed channel fired the biased RST arm on EVERY forwarded request — fixed with `Arc<tokio::sync::Notify>` (production-only, no test expectations changed). **13 new test fns in 4 new files** (1457 → 1467, 0 failed); fmt + clippy `-D warnings` clean; compat-test.sh 86/86; protocol-matrix 11/11. **plugin-h2 16 MiB kept (round-13 deliberate revert)** — the round-13 `max_header_list_size(4096)` applies to the server-side vhost h2c surface only; the client plugin listener (`frp-client/src/plugin/h2.rs`) stays at Go's 16 MiB (x/net/http2 `defaultMaxHeaderListSize`): it binds the operator's own 127.0.0.1 port and serves only the local user's browser, so large Cookie jars/JWTs must not be rejected — the 4096 cap exists only on the untrusted public vhost surface. **Round-15 review (3 independent reviewers, 0 BLOCKER/HIGH, 6 LOW fixed)**: route_user malformed `Proxy-Authorization` empty bucket, `canonicalize_authority` empty-port unroutable, h2c chunk-tail error, CONNECT `split(' ')` request-line parsing, run_id P/S/M categories, yamux RST FIFO queue cap 32; tests added (h2c CL-excess RST, route_user 407, XFF, blank-line 400, WS n==0, clamp fn, yamux RST FIFO/drop-oldest) + ci.yml vnet test job; **+30 tests (1467 → 1497, 0 failed)**; fmt + clippy `-D warnings` clean; compat-test.sh 86/86; protocol-matrix 11/11 |
| Pre-release hardening round 16 (2026-08-30) | PR #273 (sixteenth full review, 3 independent reviewers + Go-source cross-verification of every contested finding → 1 HIGH + 4 MEDIUM + 8 LOW, all fixed): **header-scan byte-slice panics (HIGH, unauthenticated abort under panic=abort)** — 4 sites sliced `&str` at fixed byte offsets (`line[..header.len()]` ×2, `line[..5]`, h2c `value[..6]`) with length-only guards; a multibyte UTF-8 char straddling the cut (header lines in HTTP/1.1, obs-text 0x80-0xFF field values in h2) panicked on EVERY vhost request → all `get(..n).is_some_and(...)` (skip = non-match, no panic). **empty-port regression reverted (MEDIUM)** — round-15's `canonicalize_authority`/`host_from_authority` `port.is_empty() → ""` guard encoded a FALSE SplitHostPort claim: Go slices `port = hostport[i+1:]` unconditionally (net/ipsock.go:216, official test pins `{"golang.org:", "golang.org", ""}`) — `"example.com:"` routes `"example.com"` again; bracket errors now fail-closed per ipsock.go (`[::1]:80:90` → tooManyColons → `""`, `[::1]x]:8080` → missingPort → `""`, `[::1]:` → `"::1"` brackets stripped — all three oracles flipped in both vhost.rs and vhost_h2c.rs tests). **h2c origin-form auth (MEDIUM)** — Go's h2 server builds req.URL from `:path` ALONE (h2_bundle.go:6362-6430: CONNECT → `URL{Host: :authority}`, else `ParseRequestURI` → `URL.Host == ""`); round-15's "every h2 request is absolute-form" model read Proxy-Authorization on all h2 requests. Now: CONNECT / absolute-form `:path` → Proxy-Authorization + 407 + Proxy-Authenticate; path-form → Authorization (BasicAuth) + 401 + WWW-Authenticate (http.go:195-205, 231-246, 275-277). `h2_request_is_absolute_form` + `h2_select_auth` helpers carry the gate; 3 h2c integration oracles rewritten to Go semantics (no-creds 407→401, rubu valid-authorization 407→forwarded 200, malformed-proxy-auth GET→CONNECT 404). **CONNECT status-line full ReadResponse parity (MEDIUM)** — `parse_connect_status_line` mirrors response.go:168-184 exactly: CRLF strip, first-space Cut, TrimLeft (double-space legal), 3-char code length BEFORE Atoi ("0200" rejected), ParseHTTPVersion on proto ("FOO 200 OK" rejected); fixes 3 round-15 residuals ("HTTP/1.1 200\r\n" valid-minimal rejection, multi-space rejection, unvalidated version token). **LOWs**: Basic prefix `EqualFold` + payload verbatim no-trim (frp's own ParseBasicAuth http.go:81-97 — "Basic  xyz" now fails like Go StdEncoding; two round-14/15-era tests that pinned the trim behavior flipped); `has_nonempty_header` first-value semantics (Go Header.Get `v[0]` — first empty-valued line shadows later non-empty; was `.any()`); `parse_hex` rejects `+` (Go parseHexUint 0-9a-fA-F only); gorilla comments corrected (gorilla conn.go:841 also checks the RAW 7-bit length field against 125 before extended-length decode — frp-rs matches, not "stricter"); lowercase placement documented (Go CanonicalHost lowercases inline; frp-rs lowers at route lookup — get_locked/router.go `Get` parity, registration side lowered too, routing outcome byte-identical). **+8 tests (1497 → 1505, 0 failed)**: CONNECT 9-case Go matrix, multibyte panic-proof scans (3 header shapes), Basic case/no-trim matrix, `is_absolute_form_target` ×9, `h2_select_auth_fallbacks` ×7, 2 h2c e2e (origin-form authorization forwards + CONNECT malformed-proxy-auth empty-bucket 404), chunk EOF-mid-chunk (UnexpectedEof, no hang); fmt + clippy `-D warnings` clean; compat-test.sh 86/86 (XTCP pairwise skipped locally — no public internet on this host; daily xtcp-compat.yml VPS matrix covers it); protocol-matrix 11/11 |
| CI gate repair (2026-08-30) | PR #273 commits `6d6191d`/`a842417`/`0fdb0a5` (3 CI failures, all fixed; found while checking round-16 CI): **tiny/micro feature-set builds broken (E0425)** — `frp-client/visitor.rs` clamps against `frp_core::xtcp_p2p::MAX_HOLE_PUNCH_TIMEOUT_MS` unconditionally but the `#[cfg(not(feature = "kcp"))]` xtcp_p2p stub in `frp-core/src/lib.rs` mirrored only `DEFAULT_HOLE_PUNCH_TIMEOUT_MS` → Verify (feature sets) + Docker frpc-tiny/frpc-micro all failed; stub const added. **Dockerfile `|| true` swallowed the whole zigbuild chain** — `a && b && c || true` made compile failures exit 0, surface only as `COPY /usr/bin/frp not found` in the scratch stage; strip split into its own RUN because GNU strip cannot parse zig-produced binaries ("Unable to recognise the format", zig already strips in release mode — the `|| true` was strip's original purpose). **Tests job timeout 25 min → 35** — the 1505-test suite with `-j 1` serial integration runs 24.5-25.0 min (green run measured 24m39s); two runs cancelled at exactly 25m00s after test steps finished (during post-run cache actions — looked external, was the limit). CI now fully green on PR #273 |
| Cross-instance TCP auto-assign port flake (2026-08-30) | PR #273 commit `fa79700` (user-reported 🟠 Medium: `test_new_proxy_duplicate_name_fails` EADDRINUSE "TCP bind failed: Address already in use" in an independent full workspace run — flake, not regression): three-phase TCP allocation probes the OS OUTSIDE `used_ports`, so two parallel frps instances (cargo runs test *bins* as separate processes) probe the same auto-assign candidate and the loser's bind fails. **Production fix**: `bind_tcp_proxy_with_retry` — on bind EADDRINUSE with `remote_port == 0`, roll the failed registration back (`rollback_tcp_bind_failure`), clear the 24h `port_reservations` entry (it would otherwise hand back the SAME stolen port), re-allocate, and re-register via the extracted `register_proxy_entry` so ProxyInfo `remote_port` / `used_ports` / `client_ports_used` move together; ≤8 total bind attempts; final port flows to log, dashboard event, and NewProxyResp. Explicit `remote_port` keeps immediate reject (Go parity — Go's port manager is per-process, never faces this race; a requested-port conflict is a client config error). **Test fix**: 3 integration tests swapped `remote_port: Some(0)` full-range scans for flock-serialized `allocate_port()` (the observed flake site, the 200-proxy burst test, the V2 TCP test); remaining hardcoded literals audited — all inert config/message fields that never reach a bind/dial. **2 new deterministic unit tests** (used_ports read-lock seam + real thief socket): auto-assign steal retries with a fresh port, explicit port rejects immediately. Gates: workspace tests **1507/0 ×2 consecutive** (1505 → 1507), fmt + clippy `-D warnings` clean, compat-test.sh 86/86 vs Go frp v0.71.0 |

Key perf optimizations (3 audit cycles):
- Bridge: `compress_chunk`/`decompress_chunk` reuse buffers (zero alloc per iteration)
- CFB cipher: u128 XOR block path (~16x encrypt throughput)
- Linux TCP bridge: `splice(2)` zero-copy relay
- CipherWriter: shared `scratch` buffer reuse
- AEAD read: pre-allocated `scratch` retained across frames
- KCP: packet pool, FEC fast-path (skip 6 allocs when no loss), lazy `recv_buf`, O(1) write-path `conv_index`, write backpressure; send path single-copy offset segmentation (no `split_off` tail re-copy per segment)
- BandwidthLimiter: `f64` token bucket, zero alloc per check

Deep-dive architecture docs live in Claude memory files: `frp-core-deep-dive`, `frp-server-deep-dive`, `frp-client-deep-dive`, `frp-test-coverage`, `frp-vnet-architecture`.

## Architecture: Beyond the README

The README gives a solid overview. The sections below cover details that reading a single file won't reveal.

### Wire Protocol

**V1** (fully implemented): 9-byte header — 1 byte type + 8 bytes big-endian payload length (max 10 KiB; the 64 KiB cap belongs to V2 framing) — followed by UTF-8 JSON payload. Defined in `frp-core/src/protocol.rs`.

**V2** (fully implemented): 7-byte magic `FRP\0\x02\r\n` + different framing. V2 frame read/write (`write_v2_frame_raw`/`read_v2_frame_raw`), message dispatch (`write_msg_v2`/`read_msg_v2`), AEAD encryption (`v2_handshake.rs`: ClientHello/ServerHello, HKDF key derivation, `crypto.rs`: AeadAlgorithm trait for AES-256-GCM/ChaCha20-Poly1305), and capability negotiation all implemented. V2 compat tests run against the Go frp v0.71.0 pre-built binary.

**UDP packet binary codec (V2, Go frp v0.71.0)**: UDPPacket payloads use a compact binary codec (`binary-v1`) when negotiated via the V2 handshake's `udpPacketCodecs` capability; V1 stays JSON, V2 falls back to JSON UDPPacket (type 13) when not negotiated. Codec: `frp-core/src/udp_binary.rs` (EncodeUDPPacketBinary/DecodeUDPPacketBinary), frame type 19 `V2_TYPE_UDP_PACKET_BINARY`, negotiated in `v2_handshake.rs` and carried on V2 UDP/SUDP work-conn data planes (`read_msg_v2_with_udp_codec`/`write_msg_v2_with_udp_codec` in `protocol.rs`). The Rust-only V2 extension types were renumbered to 21/22 to stay clear of Go's new type 19.

Message type bytes and structs live in `frp-core/src/msg.rs`. The `FrpMessage` enum is `#[serde(untagged)]` — serde matches the first variant whose fields intersect the JSON, which means ordering of the enum variants matters.

### Authentication

Auth uses **MD5(token + timestamp)** → hex string. Matches Go frp v0.70.1 behavior — Go frp switched from HMAC-SHA256 to MD5 in commit `78f9394`. See `frp-core/src/auth.rs`.

### Encryption Key Derivation

Uses **PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16)** for AES-128-CFB control encryption. Go frp v0.70.1 pre-built binary uses PBKDF2 salt `"frp"` (NOT `"crypto"` — the golib source says `"crypto"` but the Go frp binary was compiled with salt `"frp"`). See `frp-core/src/encryption.rs`.

### Server Architecture: The InternalMsg Channel

The server's core is a pattern of cross-task message passing (`frp-server/src/service.rs`):

```
AppState
  ├── run_id_to_ctl_tx: DashMap<run_id, ControlTx>  // routes work conns to correct handler (lock-free reads)
  ├── proxy_manager: ProxyManager                     // global proxy registry
  ├── used_ports: HashSet<u16>                        // port allocation tracking
  ├── sk_index: HashMap<sk, proxy_name>              // STCP/XTCP secret-key → proxy lookup
  ├── vhost_manager: VhostManager                     // HTTP VHost routing
  ├── nat_hole: Arc<NatHoleCoordinator>              // XTCP NAT hole punch session mgmt
  ├── oidc_verifier: Option<Arc<OidcVerifier>>       // OIDC token verification
  └── oidc_subjects: HashMap<sub, proxy_name>        // OIDC subject → proxy routing
```

**Connection dispatch** (`service.rs`, accept loop):
- Every new TCP connection reads one frame. Dispatch by message type:
  - `Login` → `handle_control()` (new control connection)
  - `NewWorkConn` → `handle_work_conn_inner()` (routes to control handler via `run_id`)
  - `NewVisitorConn` → `handle_visitor_conn_inner()` (STCP visitor, looks up `sk_index`)
  - `NatHoleVisitor` → `handle_nat_hole_visitor()` (XTCP hole punch, fresh-connection path)
- WebSocket connections on main port also dispatch the same message types after upgrade.

**Control handler** (`control/mod.rs`): the most complex file. Runs a `tokio::select!` loop with:
1. **Fair** `internal_rx.recv()` — deliberately NOT biased: an always-ready internal queue must not starve control reads (heartbeat pings) or shutdown. A regression test in `mod.rs` enforces this (asserts no `biased;` in the loop and bounded control p99 under internal pressure).
2. `read_msg_v1(&mut reader)` — inbound messages from the client

Internal message variants drive the work connection lifecycle:
- `ProxyUserConn` / `VisitorConn` → check `work_pool` → if empty, send `ReqWorkConn` and push to `pending_requests`
- `NewWorkConn` → if `pending_requests` is non-empty, pop and bridge immediately; otherwise push to `work_pool`
- `UdpNeedsWorkConn` → triggers work connection creation for UDP proxy
- `NatHoleSidOnWorkConn` → sends StartWorkConn+NatHoleSid on pooled work conn to notify provider of XTCP visitor; if pool empty, queues in `pending_nat_hole_sids` + sends `ReqWorkConn` (Go frp compat: server coordinates control-plane only — NAT classify + behavior recommend, never relays XTCP data; provider does its own STUN)
- `WriteNatHoleSid` / `WriteNatHoleResp` / `WriteNatHoleReport` → forwarded to visitor via control channel (Go frp compat path)
- `Shutdown` → old control handler stops when superseded by new connection with same run_id

**Bridging** (`assign_work_to_proxy` in `frp-server/src/control/bridge.rs`): sends `StartWorkConn` over the work connection, writes any pre-read bytes (from HTTP VHost parsing), then either uses `tokio::io::copy_bidirectional_with_sizes` (plain, 32 KiB per direction) or `bridge::bridge_encrypted` (AES-128-CFB + Snappy, streaming — a single 16-byte IV then continuous ciphertext, no per-frame length prefix). The client-side plain relay mirrors this (`relay_plain_fast` with splice(2) on Linux, `copy_bidirectional_with_sizes` fallback elsewhere).

### Encryption

**Control connection:** AES-128-CFB. Key derived via PBKDF2-SHA1(token, salt="frp", iterations=64, keylen=16). See `frp-core/src/encryption.rs`.

**Encrypted bridge (data plane):** AES-128-CFB streaming with Snappy compression (applied first: compress → encrypt). Framing: one random 16-byte IV written before the first ciphertext block, then a continuous CFB stream (no per-frame length prefix) — `CipherWriter`/`CipherReader` in `frp-core/src/cipher_stream.rs`. See `frp-core/src/bridge.rs`.

`derive_key` is called in `Service::new()` with `auth_cfg.token` — the encryption key derives from the auth token, not a separate secret.

**XTCP P2P encryption:** Go frp encrypts hole-punched P2P connections with PBKDF2-SHA1(SecretKey, salt="frp", iter=64, keylen=16) → AES-128-CFB. Both provider and visitor P2P paths use `bridge_encrypted` with `derive_key(&sk)` when `use_encryption` is true. The `sk` (secret key) is the proxy's `sk` field from `ProxyConfig`, NOT the auth token — this is stored in `ProxyRuntimeInfo` for access in NAT hole punch handler paths.

Note: Go frp v0.70.1 golib source says salt `"crypto"` but the pre-built binary uses salt `"frp"`. This codebase uses `"frp"` for binary compatibility.

### Transport Abstraction

`IoStream` (`frp-core/src/transport/`) is a type-erased `Box<dyn Transport>` (newtype over the boxed trait object). The old 11-variant enum is gone: each variant is now a `Transport` implementor in its own file under `frp-core/src/transport/` — `tcp.rs` (`TcpStream`), `tls.rs` (`TlsTransport`), `kcp.rs` (`KcpStream`), `quic.rs` (`QuicStream`), `websocket.rs` (`WsByteStream`), `yamux.rs` (`YamuxStream`), `cipher.rs` (`CipherStream<S>`), `aead.rs` (`AeadStream`), `ssh_channel.rs` (`SshChannelTransport`), `pre_read.rs` (`PreReadTransport`), `buffered_read.rs` (`BufferedReadTransport`). The `WebSocket` adapter wraps WebSocket binary messages into `AsyncRead`/`AsyncWrite` so the V1 protocol can operate over WebSocket without changes.

The `Transport` trait bundles `AsyncRead + AsyncWrite + Unpin + Send + 'static` plus the consuming methods that used to be per-variant matches: `into_encrypted(self: Box<Self>)` (default wraps in `CipherStream`; Aead returns itself), `into_split(self: Box<Self>) -> (BoxedReadHalf, BoxedWriteHalf)` (default `tokio::io::split`; QUIC uses quinn's native halves), `into_tcp`/`try_tcp`/`try_tcp_mut` (splice(2) fast-path downcasts), `into_parts` (peels PreRead for the TLS/V1 accept paths), `is_yamux_wrappable` (false for QUIC only), and `bridge_split_err` (the `Cipher`/`Aead`-in-bridge guard). The old `ReadHalf`/`WriteHalf` enums are deleted — `into_split` returns the boxed halves directly, and `split_work_conn_halves` is a thin wrapper over it. `IoStream`'s constructors are named after the old variants (`IoStream::Tcp(stream)`, `IoStream::Yamux(stream)`, …) so construction sites read identically; per-transport files each own their `#[cfg]` gates.

**TCP_NODELAY:** every raw-`TcpStream` on the data path (client control/work dials via `connect_direct`/`connect_via_proxy`, server control/work/visitor + user-proxy + vhost + tcpmux accepts, client local-service dials, SSH gateway, plugin forwarders) calls `frp_core::transport::set_nodelay` — matches Go frp's `net.TCPConn` default (`NoDelay(true)`). For TLS/mux/WS-wrapped streams it is set on the underlying `TcpStream` before wrapping. Errors are logged at debug and ignored (a failed socket option must not kill a connection). KCP sets its own nodelay; QUIC/UDP are excluded. Wire-invisible.

**Bridge buffer size:** `frp_core::buffer_pool::BUFFER_SIZE` defaults to **32 KiB** (matches Go frp `io.Copy`; was 64 KiB — halved for per-connection footprint). Override with `FRP_BRIDGE_BUF_KB` (4–1024). The plain bridge copies with `copy_bidirectional_with_sizes(a, b, *BUFFER_SIZE, *BUFFER_SIZE)` (tokio ≥ 1.52), so `BUFFER_SIZE` applies to the plain path too; the encrypted/compressed path uses the `PoolGuard` buffer pool (also `BUFFER_SIZE`).

### Config Normalization

`frp-core/src/config/` (directory: `mod.rs`/`client.rs`/`server.rs`/`normalize.rs`/`loader.rs`/`strict.rs`) includes a full Go→Rust config compatibility layer:

- `[common]` sections are flattened to the top level
- `auth_method` / `auth_token` → nested under `[auth]`
- `log_file` / `log_level` → nested under `[log]`
- `web_server_*` → nested under `[web_server]`
- `tcp_mux` → nested under `[transport]`
- Client-side: `protocol` → `transport_protocol`, `serverAddr` → `server_addr`, `auth.token` → top-level `token`
- TOML values are converted via `toml_to_json()` to `serde_json::Value`, then deserialized into config structs

### XTCP NAT Hole Punching

`frp-server/src/nathole/`: `NatHoleCoordinator` manages hole-punch sessions. Module structure:
- `mod.rs` — module root, `NAT_HOLE_TIMEOUT = 10s`
- `controller.rs` — session management, provider registration, `build_nat_hole_response()`
- `classify.rs` — NAT feature classification (EasyNAT vs HardNAT, behavior detection)
- `analysis.rs` — 5-mode behavior table, score-based `Analyzer` with success feedback

Two paths for visitor connections:
1. **Fresh TCP connection** (accept loop): visitor sends `NatHoleVisitor` on a new TCP connection. Server creates session, sends `NatHoleSidOnWorkConn` internal msg → provider control handler writes `StartWorkConn`+`NatHoleSid` on work conn. Provider does STUN, sends `NatHoleClient` on control, server runs NAT analysis, sends `NatHoleResp` to both sides.
2. **Control connection** (Go frp compat): Go frpc v0.70.1 sends `NatHoleVisitor` on its existing control channel. Server creates session with `create_session_with_ctl`, spawns task that waits for provider's `NatHoleClient` on control, runs NAT analysis (classify + analyzer), and sends `NatHoleResp` to both sides via `InternalMsg::WriteNatHoleSid`/`WriteNatHoleResp`/`WriteNatHoleReport`.

Flow: Visitor→Server(NatHoleVisitor) → Server→Provider(NatHoleSidOnWorkConn → StartWorkConn+NatHoleSid on work conn) → Provider does STUN → Provider→Server(NatHoleClient on control) → Server NAT analysis (classify + 5-mode behavior recommend) → Server→Visitor(NatHoleResp) + Server→Provider(NatHoleResp, sender side delayed 1s) → both sides run MakeHole UDP probing per DetectBehavior → winner socket carries the KCP+yamux P2P data plane → bridge to local → Provider→Server(NatHoleReport) → session complete.

**Status:** Fully implemented (cross-compat verified: 17/17 XTCP pairwise scenarios with Go frp v0.71.0 (re-verified locally 2026-08-23; daily `xtcp-compat.yml` VPS matrix)). The server is a control-plane coordinator — it classifies NAT features, recommends a 5-mode `DetectBehavior`, and manages sessions — but never relays XTCP data nor sends probe packets (provider and visitor each do their own STUN). Hole punching is UDP-based: both sides run Go-style `MakeHole` probing (`punch_udp_hole_makehole_owned` in `frp-core/src/xtcp_p2p.rs`) and the KCP+yamux data plane runs on the socket that received the peer's detect reply (Go `result.lConn` semantics). Provider-side (`frp-client/src/service.rs`) reads StartWorkConn+NatHoleSid from work conn, does STUN, sends NatHoleClient on control, reads NatHoleResp, then `xtcp_p2p_connect_yamux` → bridge to local. Visitor-side (`frp-client/src/visitor.rs`) handles `NatHoleVisitor` → PreCheck + STUN + full NatHoleVisitor → `xtcp_p2p_connect_yamux` → bridge to user. STCP fallback if hole punch fails (uses `fallback_to` config field to point at separate STCP proxy, matching Go frp architecture). e2e test in `frp-server/tests/xtcp_hole_punch.rs`, loopback MakeHole tests in `frp-core/tests/xtcp_p2p.rs`.

**XTCP P2P bridging:** After successful hole punch, the P2P KCP-over-UDP stream (`XtcpP2pStream`, wrapped in yamux) is bridged to the local service with conditional `bridge_encrypted` (when `use_encryption=true` + `sk` non-empty) or `bridge_plain` (otherwise). Encryption key derived from proxy's `sk` (SecretKey) via `derive_key()` — same derivation as control connection but uses SecretKey instead of auth token. Probe packets (NatHoleSid) are AES-128-CFB encrypted with the same key; without a secret key Rust↔Rust probes fall back to the `"frp"` magic. `ProxyRuntimeInfo.sk` stores the SecretKey for access in NAT hole punch handler paths (`NatHoleClient` and `NatHoleResp` handlers in service.rs, visitor P2P path in visitor.rs). Both sides derive the same key from the shared SecretKey, matching Go frp.

### Transport Status

- **TCP**: fully implemented (control + work connections, TLS, WebSocket upgrade)
- **WebSocket**: fully implemented — dial, accept, message dispatch (control + work connections)
- **KCP**: fully implemented — dial, accept, TLS, yamux, message dispatch. Architecture: `KcpSocket` driver (UDP event loop), `KcpSession` per-peer (in-tree Kcp protocol + FEC), `KcpStream` (AsyncRead/AsyncWrite). The KCP state machine is implemented in-tree (`kcp/protocol.rs`, aligned with kcp-go v5.6.13 wire behavior) — the vendored `kcp` crate and its `[patch.crates-io]` entry are gone. `conv_index: HashMap<u32, SocketAddr>` provides O(1) write-path lookup. Write backpressure via `Arc<AtomicUsize>` shared between `KcpSocket` and `KcpStream` (gates `poll_write` at 200 unprocessed messages, `KCP_WRITE_BACKLOG_THRESHOLD` — pre-full gate for the 256-cap channel). Go frps dispatch order (service.go:670-710): read 1 byte → TLS detect (0x17=strip, 0x16=replay) → TLS accept → if tcpMux: yamux wrap → V2/V1 detection. frp-rs's KCP handler is functionally equivalent but checks the V2 magic first (7-byte read → V2? → TLS detect → TLS accept → tcpMux → V2/V1); both orders interop with Go frpc v0.70.1. Verified: KCP+TLS+tcpMux+CipherStream all working (RTT ~76ms). Integration test in `frp-core/tests/kcp.rs` (real UDP sockets).
- **QUIC**: fully implemented — dial, accept, message dispatch (requires TLS cert on server)
- **TcpMux** (`frp-core/src/mux.rs`, ~699 lines): full yamux implementation — server and client mode, keepalive, stream accept/spawn via `server_mux`/`client_mux`. Double-poll pattern flushes pending frames to socket. A zero keepalive interval is normalized to the 30s default instead of causing an immediate timeout or spin. Dead-conn detection: `MAX_IDLE_KEEPALIVE_TICKS = 3` (~90s idle). `open_stream` is wakeup-loss-proof (`watch` channel, not `Notify`) and fails fast once the driver has died (`alive` flag).
- **Dashboard** (`frp-server/src/dashboard.rs`, ~2757 lines): basic status API with axum (version, uptime, client/proxy counts)
- **VHost** (`frp-server/src/vhost.rs`, ~1300 lines): HTTP/HTTPS VHost routing with Host header parsing, SNI, pre-read byte forwarding

### Gotchas

- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README example shows `false` — be aware the code default is `true`
- `#[serde(untagged)]` on `FrpMessage` enum — ordering matters for serde matching, but V1 protocol dispatches by type byte first via `deserialize_v1()`, so untagged matching is not involved in wire deserialization
- `ProxyRuntimeInfo` must include `sk: String` field — XTCP P2P encryption derives its AES-128 key from the proxy's SecretKey via `derive_key(&sk)`. Adding new fields to `ProxyRuntimeInfo` requires updating all construction sites: `Service::new()`, `do_reload()` in `frp-client/src/reload.rs`, and any other future sites.
- **KCP handler dispatch order** (`service.rs:714-1174`): MUST interop with Go frps `service.go:670-710` (read 1 byte → TLS detect → TLS accept → tcpMux → V2/V1). frp-rs reads 7 bytes and detects the V2 magic first, then TLS detect, TLS accept, (tcpMux? yamux : direct), then V2/V1 — functionally equivalent and verified against Go frpc v0.70.1. Getting this wrong was root cause of both "invalid V1 message length" (yamux SYN interpreted as FRP) and TLS rejection bugs.
- **NewVisitorConn race**: STCP/XTCP visitors may send `NewVisitorConn` before the server's `proxy_manager.register()` completes. Go frp handles this via `startVisitorListener()` — the listener is pre-registered during `proxy.Run()` before registration returns. frp-rs equivalent: pre-populate `sk_index` in `proxy_ops.rs` BEFORE calling `proxy_manager.register()`, and use `sk_index` as fallback in both `handlers.rs` (accept loop) and `control/mod.rs` (control channel) when `proxy_manager.get()` returns `None`. Without this, visitor auth fails with "proxy not found" when the visitor connects before registration is visible.
- **Wire field naming**: NewProxy JSON fields MUST use snake_case for Go frp v0.70.1 wire compatibility (`http_user`, `http_pwd`, `host_header_rewrite`, `response_headers`, `route_by_http_user`, `bandwidth_limit_mode`). CamelCase variants are silently ignored by Go frp, causing silent config loss. (`proxy_protocol_version` is a Rust-only extension — Go frp v0.71.0's `NewProxy` has no such field — and IS serialized to the wire when set; Go ignores the unknown key. The config-level `proxyProtocolVersion` maps to this wire field.) Contract test in `msg.rs` verifies both serialize and deserialize paths.
- **V1 type bytes 7/8, V2 types 21/22**: Rust-only extensions. Must NOT be sent to Go frp peers — Go frp treats unknown message types as errors. Only send on Rust↔Rust connections after capability negotiation. (Renumbered from V2 19/20 in 0.71.0 because Go frp v0.71.0 assigned type 19 to `V2TypeUDPPacketBinary`.)

### Testing & Tooling

- **Benchmarks**: `cargo bench -p frp-core` (8 groups: key derivation, compression, cipher stream, STUN, V1+V2 protocol all-types, bridge plain/encrypted/compressed, bandwidth limiter) + `cargo bench -p frp-server` (`nathole` classify + analysis; `proxy_registration` register throughput + ProxyInfo construct). CI: `cargo bench --workspace --no-run` build-check in `ci.yml`. Note: connection-accept/setup latency is measured e2e by `scripts/latency-baseline.sh` (setup mode), NOT criterion — a real TCP+TLS+yamux accept is dominated by kernel/handshake noise, not code-path cost.
- **Property/fuzz tests**: proptest-based config normalization (`frp-core/src/config/tests.rs`, 9 proptest! blocks) and V1/V2 protocol frame fuzzing (`frp-core/src/protocol.rs`, 6 fuzz tests + 35 regular tests, 0 panics found).
- **Integration tests**: KCP real-UDP-socket test (`frp-core/tests/kcp.rs`), XTCP hole-punch e2e (`frp-server/tests/xtcp_hole_punch.rs`), plus 13+ server integration tests covering control handler, vhost, proxy registration, OIDC, reload, graceful drain.
- **Stress tests**: `scripts/stress-test.sh` runs frps + frpc under load with connection churn, monitored via `scripts/frp-stress/`. Weekly CI run in `stress-test.yml`.
- **Perf baselines** (4-axis program, host-specific JSONL committed under `scripts/frp-stress/baselines/`): `scripts/throughput-baseline.sh` (MB/s per cipher/transport config), `scripts/latency-baseline.sh` (steady-state RTT + connection-setup percentiles), `scripts/memory-baseline.sh` (idle-hold + churn footprint via the `mem-profile` counting allocator + `ps` RSS). Run manually before/after a data-plane change; not blocking CI gates. Gate rule: a change to one axis must not regress the others (>5% throughput/MB/s, or RTT p99).
- **Cross-compat tests**: `scripts/compat-test.sh` — 86 run_test scenarios + 17 XTCP pairwise scenarios against Go frp v0.71.0 (V2 included, plus KCP+TLS and KCP+tcpMux Go↔Rust scenarios since the in-tree KCP landed). Runs on every push via `compat.yml`; XTCP compat runs daily on VPS via `xtcp-compat.yml`. Subset runs: `compat-test.sh --test <display-name>` (matches scenario display name, e.g. `go-to-rust-oidc-proxy`).
- **Protocol connectivity matrix**: `scripts/protocol-matrix.sh` — end-to-end throughput through frps+frpc for 11 transport rows (tcp/ws/wss/kcp/quic × tls × tcp_mux). Each row asserts data actually moves (mbps > 0), catching "connects but bridges zero bytes" regressions like the WS-over-TLS lost-wakeup stall. Runs in `compat.yml` after the compat tests; also run locally after any transport change: `bash scripts/protocol-matrix.sh`.
- **Security audit**: Run `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071` and `cargo deny check` before each release. The three ignores are pre-existing issues with **no upstream fix** (cargo-audit ≥0.21 dropped `audit.toml` config file support — flags are the only mechanism; keep reasons in sync with the CI job in `ci.yml`):
  - `RUSTSEC-2026-0194/0195` (quick-xml 0.26, high): dev-only `profiling` feature chain pprof 0.15 → inferno 0.11.21 → quick-xml 0.26. pprof 0.15.0 is the latest release; nothing newer resolves. Never compiled into release binaries.
  - `RUSTSEC-2023-0071` (rsa 0.10.0-rc.18, Marvin attack, medium): pinned by russh 0.62.7 (latest) via ssh-key 0.7.0-rc.11. Advisory has no fixed upgrade. Affects frps SSH gateway (RSA host keys/auth) only. Re-check on every russh bump.

### Test Coverage Gaps

Known areas lacking e2e cross-compat test coverage:

- ~~UDP proxy: no Go frp cross-compat~~ — covered (test_g2r_udp + test_r2g_udp, both in Phase 4)
- HTTP/HTTPS proxy: basic VHost + basic auth + host_header_rewrite + subdomain tested (7 compat tests); response_headers, route_by_http_user, locations all now cross-compat tested
- Reload configuration: automated test added (reload_integration.rs, SIGUSR1 client-side reload path)
- **XTCP NAT traversal**: daily CI pairwise matrix (`xtcp-compat.yml`) runs frps on a VPS (public IP) with both frpc ends on the NATed GitHub runner — real STUN/NAT classify, but not two independent NATed networks

### Dependency Policy (mandatory)

**No new dependencies without explicit justification.** Every new crate added to the workspace must have a documented reason covering:

1. **Why it's needed** — what problem it solves that existing deps cannot
2. **Why the alternative was rejected** — why an existing dep can't be used (e.g., ring for crypto, `frp_core::base64`/`hex_encode` for encoding)
3. **Binary size impact** — approximate cost to frps/frpc release binary

Pre-approved tech stack. Use these unless strong reason to deviate:

| Domain | Crate | Notes |
|--------|-------|-------|
| Async runtime | `tokio` | net, io-util, time, sync, macros, rt-multi-thread, signal |
| Serialization | `serde` + `serde_json` | derive feature |
| Config | `toml` | 0.8 (TOML); `.yaml`/`.yml`/`.json`/`.ini` via `serde_yaml_ng`/`serde_json` — auto-detected by extension |
| Test certs (dev) | `rcgen` | optional under `tls` feature, dev/tests only (LTO-GC'd out of shipped binaries) |
| Crypto (general) | `ring` | 0.17 — SHA256, AES-256-GCM, HKDF, HMAC |
| Crypto (Go compat) | `aes` + `cfb-mode`, `pbkdf2` + `sha1`, `md-5` | AES-128-CFB, PBKDF2-SHA1, MD5 — ring lacks these |
| Crypto (V2 XChaCha20) | `chacha20poly1305` | ring only has ChaCha20 (96-bit nonce), V2 needs XChaCha20 (192-bit) |
| TLS | `rustls` + `tokio-rustls` + `rustls-platform-verifier` | ring backend, tls12, native cert verifier. **Vendored** at `vendor/rustls` 0.23.43 with a one-line SNI patch (`ServerNamePayload::Invalid` → treat as no-SNI) for Go XTCP QUIC visitor compat; delete the vendored copy when upgrading to rustls ≥0.24 (native `invalid_sni_policy`) and keep tracking 0.23.x security updates manually |
| SSH | `russh` | ring backend (NOT aws-lc-rs), features: ring+rsa only |
| HTTP client | inline `frp_core::http_client` | hyper + hyper-rustls direct (not reqwest — size-pruned); OIDC + http-proxy + dashboard health use it |
| HTTP server | `axum` | dashboard, admin auth |
| WebSocket | manual RFC 6455 framing (in-tree `websocket.rs`; `tokio-tungstenite` removed 2026-08-09) |
| Encoding | inline `frp_core::base64` (encode/decode) + `frp_core::hex_encode` | standard base64 alphabet + `=` padding, wire-compatible with Go `base64.StdEncoding` |
| Compression | `snap` | Snappy, pure Rust |
| QUIC | `quinn` | |
| TcpMux | `yamux` | |
| OIDC/JWT | `jsonwebtoken` | |
| Logging | `tracing` + `tracing-subscriber` + `tracing-appender` | env-filter |
| Error handling | `anyhow` + `thiserror` | |
| Random | `rand` | 0.8 |
| Misc | `bytes`, `uuid`, `futures-util`, `tokio-util`, `socket2`, `prometheus` | |

**Removed and banned as direct dependencies** (do not reintroduce without approval):
- `aws-lc-sys` / `aws-lc-rs` — replaced by ring (russh default → ring feature)
- `hmac` — dead dependency, ring covers HMAC
- `base64` — replaced by inline `frp_core::base64`
- `data-encoding` — replaced by inline `frp_core::base64` (2026-08-06; was ~47KB .text in frps)
- `sha2` — replaced by ring
- `aes-gcm` — replaced by ring (AES-256-GCM)
- `hkdf` — replaced by ring (HKDF-SHA256)
- `hickory-resolver` — replaced by custom DNS-over-UDP client
- `lazy_static` — replaced by `std::sync::LazyLock` (stable since Rust 1.80)
- `libc` — active direct dependency (frp-core Linux splice(2), frp-vnet TUN ioctl)

> Note: "banned" means no **direct** dependency. Several still exist **transitively** in the default frps dependency tree via the SSH feature chain (russh 0.62.7 → ssh-key 0.7.0-rc): `data-encoding`, `aes-gcm`, `sha2`, `hkdf`, `hmac` (and `base64`/`lazy_static` via dev-only pprof/tracing paths). They cannot be removed without replacing russh; only direct use is forbidden.

### Workspace Dependencies

Cargo workspace uses `resolver = "2"` with `[workspace.dependencies]` for all crates. Adding a new dependency: add to workspace level, then reference by name (no version) in sub-crates.
