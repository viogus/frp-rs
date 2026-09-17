# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Scope — read this first.** This file holds *rules and non-obvious invariants* only.
It is loaded into every agent context and has a **64 KB instruction budget**, so it
must stay small; anything longer belongs elsewhere:

| Content | Lives in |
|---|---|
| Architecture, wire protocol, transport internals, NAT hole punch | [`docs/architecture.md`](docs/architecture.md) |
| Round-by-round hardening / audit history | [`docs/history/development-log.md`](docs/history/development-log.md) |
| User-facing release notes | [`CHANGELOG.md`](CHANGELOG.md) |
| Config / proxies / plugins / deployment references | [`docs/README.md`](docs/README.md) |

**Rule: do not append history to this file.** When a hardening or audit round lands,
append it to `docs/history/development-log.md` and update only the snapshot table
under [Current Health](#current-health) here.

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
bash scripts/download-frp-rs.sh         # Download latest release into target/debug
cargo test --workspace --all-features    # Tests resolve FRPS_BIN/FRPC_BIN env, CARGO_BIN_EXE_<name>, then target/debug
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
# → frps (~8.5MB), frpc (~6.8MB)
#   (measured 2026-09-01 Linux x86_64/glibc/rustc 1.98.0 with the DECLARED
#   release profile: fat-LTO, opt-level=z, strip=symbols, panic=abort — see
#   [profile.release] in Cargo.toml; flags verified via `cargo build -v`.
#   Sizes are platform-dependent: the same profile on macOS arm64 measured
#   ~5.3/4.5MB on 2026-08-08. There is no local `.cargo/config.toml` override
#   anymore (removed 2026-08-09); local `cargo build --release` uses the
#   declared profile. CI workflows still write `lto=false opt-level=2` on
#   runners for build speed, so CI artifact sizes do not reflect release.)

# Full (all features; dashboard is the main opt-in on top of default)
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"
# → frps (~9.2MB), frpc (~6.8MB)

# Tiny (no QUIC/KCP/WS/SSH/OIDC/dashboard/compression; keeps TLS)
cargo build --release -p frps -p frpc --no-default-features --features tiny
# → frps-tiny (~5.2MB), frpc-tiny (~4.6MB)

# Micro (core only: no TLS, compression, chacha20, HTTP proxy, tcp-mux)
cargo build --release -p frps -p frpc --no-default-features --features micro
# → frps-micro (~3.2MB), frpc-micro (~3.5MB)
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
| `http2http` | frp-client | HTTP/2 (h2) support for the https2http/https2https plugins (enableHTTP2 path); implies `tls` |
| `tcp-mux` | frp-core/server/client | yamux stream multiplexing (~80KB) |
| `vnet` | frp-core/server/client | L3 VPN / TUN device routing |
| `admin` | frp-client | frpc admin API (axum) |
| `admin-auth` | frp-core | shared admin auth helpers (token/basic) |
| `mimalloc` | frps/frpc | mimalloc global allocator (exclusive with mem-profile) — measured no ≥5% throughput gain in the 2026-08 A/B (see `docs/archive/notes/2026-08-04-mimalloc-throughput-ab.md`), keep opt-in |
| `mem-profile` | frp-core/server/client | CountingAlloc global allocator + MEMPROFILE emitter (dev only) |
| `profiling` | frp-core | profiling feature gate (dev only) |
| `otel` | frp-core/server/client | OpenTelemetry tracing + OTLP export (~+2-3MB) — frp-server exposes no `otel` feature; frps/frpc forward frp-core's |
| `debug-logs` | frp-core | debug/trace logging (dev only) |

Default features: frps = websocket, kcp, quic, oidc, tls, http-proxy, compression, chacha20, tcp-mux, ssh; frpc = websocket, kcp, quic, oidc, tls, compression, chacha20, tcp-mux, http2http. `quic` implies `tls`. `oidc` implies `http-client` (hyper). `ssh` implies `rand`. Note: `frp-core`'s own default includes `vnet`/`stun`/`tcp-mux`, but frps/frpc default binaries do **not** include `vnet` (opt-in) — only the `stun` (NAT hole punch) and `tcp-mux` parts that they forward.

**Opt-in (NOT default):** `admin` (frpc — the axum-based admin API, ~1 MB; was default until the 2026-08-09 audit round), `dashboard`, `mimalloc`, `otel`, `debug-logs`, `profiling`, `mem-profile`, `vnet` (frps/frpc — L3 VPN/TUN routing, drops frp-vnet from default binaries); `http-proxy` is a server-side opt-in (the client http_proxy plugin compiles unconditionally). `mem-profile` installs a `CountingAlloc` global allocator + a 1 Hz `MEMPROFILE` stderr emitter and is mutually exclusive with `mimalloc` (the `#[global_allocator]` guards are cfg-exclusive — with both enabled neither allocator is installed and the emitter does not run). Off in every shipped build (full/tiny/micro) → production binaries are byte-identical. Enable only for the memory baseline: `cargo build -p frps -p frpc --features mem-profile`. std `GlobalAlloc` + `AtomicUsize`, no new dep.

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

## Current Health

Snapshot of `main` — full round-by-round history is in
[`docs/history/development-log.md`](docs/history/development-log.md).

| Metric | Current state |
|--------|---------------|
| `cargo fmt --all -- --check` | zero diffs |
| `cargo clippy --workspace --all-targets --all-features -D warnings` | zero warnings |
| `cargo test --workspace --all-features` | 2078 passed, 0 failed (needs an all-features `frps` binary — see Testing & Tooling) |
| `cargo build --release` | all 4 profiles pass, zero warnings — sizes in [Binary Variants](#binary-variants) |
| `scripts/compat-test.sh` vs Go frp v0.71.0 | 86 passed, 0 failed |
| `scripts/protocol-matrix.sh` | 11/11 transport rows move data |
| `unsafe` blocks | 17 in `frp-core`, ~38 in `frp-vnet` (each with `// SAFETY:`) |
| Security audit | `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071` + `cargo deny check` before release |
| Vendored crates | `rustls`, `yamux`, `russh` under `[patch.crates-io]` — **each has an exit condition, see [Vendored crates](README.md#vendored-crates)** |

**To update this file's history**: append the round to
`docs/history/development-log.md`, not here. This file is loaded into every agent
context and has a 64 KB instruction budget; keep it under ~25 KB.

## Gotchas

- `login_fail_exit` defaults to `true` in `ClientConfig::default()` but README example shows `false` — be aware the code default is `true`
- `#[serde(untagged)]` on `FrpMessage` enum — ordering matters for serde matching, but V1 protocol dispatches by type byte first via `deserialize_v1()`, so untagged matching is not involved in wire deserialization
- `ProxyRuntimeInfo` must include `sk: String` field — XTCP P2P encryption derives its AES-128 key from the proxy's SecretKey via `derive_key(&sk)`. Adding new fields to `ProxyRuntimeInfo` requires updating all construction sites: `Service::new()`, `do_reload()` in `frp-client/src/reload.rs`, and any other future sites.
- **KCP handler dispatch order** (`service.rs:714-1174`): MUST interop with Go frps `service.go:670-710` (read 1 byte → TLS detect → TLS accept → tcpMux → V2/V1). frp-rs reads 7 bytes and detects the V2 magic first, then TLS detect, TLS accept, (tcpMux? yamux : direct), then V2/V1 — functionally equivalent and verified against Go frpc v0.70.1. Getting this wrong was root cause of both "invalid V1 message length" (yamux SYN interpreted as FRP) and TLS rejection bugs.
- **NewVisitorConn race**: STCP/XTCP visitors may send `NewVisitorConn` before the server's `proxy_manager.register()` completes. Go frp handles this via `startVisitorListener()` — the listener is pre-registered during `proxy.Run()` before registration returns. frp-rs equivalent: pre-populate `sk_index` in `proxy_ops.rs` BEFORE calling `proxy_manager.register()`, and use `sk_index` as fallback in both `handlers.rs` (accept loop) and `control/mod.rs` (control channel) when `proxy_manager.get()` returns `None`. Without this, visitor auth fails with "proxy not found" when the visitor connects before registration is visible.
- **Wire field naming**: NewProxy JSON fields MUST use snake_case for Go frp v0.70.1 wire compatibility (`http_user`, `http_pwd`, `host_header_rewrite`, `response_headers`, `route_by_http_user`, `bandwidth_limit_mode`). CamelCase variants are silently ignored by Go frp, causing silent config loss. (`proxy_protocol_version` is a Rust-only extension — Go frp v0.71.0's `NewProxy` has no such field — and IS serialized to the wire when set; Go ignores the unknown key. The config-level `proxyProtocolVersion` maps to this wire field.) Contract test in `msg.rs` verifies both serialize and deserialize paths.
- **V1 type bytes 7/8, V2 types 21/22**: Rust-only extensions. Must NOT be sent to Go frp peers — Go frp treats unknown message types as errors. Only send on Rust↔Rust connections after capability negotiation. (Renumbered from V2 19/20 in 0.71.0 because Go frp v0.71.0 assigned type 19 to `V2TypeUDPPacketBinary`.)

## Testing & Tooling

- **Benchmarks**: `cargo bench -p frp-core` (8 groups: key derivation, compression, cipher stream, STUN, V1+V2 protocol all-types, bridge plain/encrypted/compressed, bandwidth limiter) + `cargo bench -p frp-server` (`nathole` classify + analysis; `proxy_registration` register throughput + ProxyInfo construct). CI: `cargo bench --workspace --no-run` build-check in `ci.yml`. Note: connection-accept/setup latency is measured e2e by `scripts/latency-baseline.sh` (setup mode), NOT criterion — a real TCP+TLS+yamux accept is dominated by kernel/handshake noise, not code-path cost.
- **Property/fuzz tests**: proptest-based config normalization (`frp-core/src/config/tests.rs`, 11 proptest! blocks) and V1/V2 protocol frame fuzzing (`frp-core/src/protocol.rs`, 6 fuzz tests + 35 regular tests, 0 panics found).
- **Integration tests**: KCP real-UDP-socket test (`frp-core/tests/kcp.rs`), XTCP hole-punch e2e (`frp-server/tests/xtcp_hole_punch.rs`), plus 13+ server integration tests covering control handler, vhost, proxy registration, OIDC, reload, graceful drain.
- **Stress tests**: `scripts/stress-test.sh` runs frps + frpc under load with connection churn, monitored via `scripts/frp-stress/`. Weekly CI run in `stress-test.yml`.
- **Perf baselines** (4-axis program, host-specific JSONL committed under `scripts/frp-stress/baselines/`): `scripts/throughput-baseline.sh` (MB/s per cipher/transport config), `scripts/latency-baseline.sh` (steady-state RTT + connection-setup percentiles), `scripts/memory-baseline.sh` (idle-hold + churn footprint via the `mem-profile` counting allocator + `ps` RSS). Run manually before/after a data-plane change; not blocking CI gates. Gate rule: a change to one axis must not regress the others (>5% throughput/MB/s, or RTT p99).
- **Cross-compat tests**: `scripts/compat-test.sh` — 86 run_test scenarios + 17 XTCP pairwise scenarios against Go frp v0.71.0 (V2 included, plus KCP+TLS and KCP+tcpMux Go↔Rust scenarios since the in-tree KCP landed). Runs on every push via `compat.yml`; XTCP compat runs daily on VPS via `xtcp-compat.yml`. Subset runs: `compat-test.sh --test <display-name>` (matches scenario display name, e.g. `go-to-rust-oidc-proxy`).
- **Protocol connectivity matrix**: `scripts/protocol-matrix.sh` — end-to-end throughput through frps+frpc for 11 transport rows (tcp/ws/wss/kcp/quic × tls × tcp_mux). Each row asserts data actually moves (mbps > 0), catching "connects but bridges zero bytes" regressions like the WS-over-TLS lost-wakeup stall. Runs in `compat.yml` after the compat tests; also run locally after any transport change: `bash scripts/protocol-matrix.sh`.
- **Security audit**: Run `cargo audit --ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195 --ignore RUSTSEC-2023-0071` and `cargo deny check` before each release. The three ignores are pre-existing issues with **no upstream fix** (cargo-audit ≥0.21 dropped `audit.toml` config file support — flags are the only mechanism; keep reasons in sync with the CI job in `ci.yml`):
  - `RUSTSEC-2026-0194/0195` (quick-xml 0.26, high): dev-only `profiling` feature chain pprof 0.15 → inferno 0.11.21 → quick-xml 0.26. pprof 0.15.0 is the latest release; nothing newer resolves. Never compiled into release binaries.
  - `RUSTSEC-2023-0071` (rsa 0.10.0-rc.18, Marvin attack, medium): pinned by russh 0.62.7 (latest) via ssh-key 0.7.0-rc.11. Advisory has no fixed upgrade. Affects frps SSH gateway (RSA host keys/auth) only. Re-check on every russh bump.

## Test Coverage Gaps

Known areas lacking e2e cross-compat test coverage:

- ~~UDP proxy: no Go frp cross-compat~~ — covered (test_g2r_udp + test_r2g_udp, both in Phase 4)
- HTTP/HTTPS proxy: basic VHost + basic auth + host_header_rewrite + subdomain tested (7 compat tests); response_headers, route_by_http_user, locations all now cross-compat tested
- Reload configuration: automated test added (reload_integration.rs, SIGUSR1 client-side reload path)
- **XTCP NAT traversal**: daily CI pairwise matrix (`xtcp-compat.yml`) runs frps on a VPS (public IP) with both frpc ends on the NATed GitHub runner — real STUN/NAT classify, but not two independent NATed networks

## Dependency Policy (mandatory)

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
| HTTP client | inline `frp_core::http_client` | hyper + tokio-rustls direct (not reqwest — size-pruned); OIDC + http-proxy + dashboard health use it |
| HTTP server | `axum` | dashboard, admin auth |
| WebSocket | manual RFC 6455 framing (in-tree `websocket.rs`; `tokio-tungstenite` removed 2026-08-09) |
| Encoding | inline `frp_core::base64` (encode/decode) + `frp_core::hex_encode` | standard base64 alphabet + `=` padding, wire-compatible with Go `base64.StdEncoding` |
| Compression | `snap` | Snappy, pure Rust |
| QUIC | `quinn` | |
| TcpMux | `yamux` | |
| OIDC/JWT | `jsonwebtoken` | |
| Logging | `tracing` + `tracing-subscriber` + `tracing-appender` | env-filter |
| Error handling | `anyhow` + `thiserror` | |
| Random | `rand` | 0.10 (0.8.7 remains in the lock only via the opt-in `otel` chain: opentelemetry_sdk → … → tonic → tower — third-party pins, latest releases) |
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

## Workspace Dependencies

Cargo workspace uses `resolver = "2"` with `[workspace.dependencies]` for all crates. Adding a new dependency: add to workspace level, then reference by name (no version) in sub-crates.
