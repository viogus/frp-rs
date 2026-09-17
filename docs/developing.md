# Developer Guide

frp-rs is a native Rust implementation of [frp](https://github.com/fatedier/frp), a reverse proxy that exposes services on private networks to the public internet. This guide covers the codebase architecture and development workflow for contributors.

## 1. Workspace Overview

The project is a Cargo workspace with six crates arranged in a layered dependency graph:

```
frps ──────────────► frp-server ──────► frp-core
(server binary)      (server logic)      (shared library)
                       │                   ▲
                       └──► frp-vnet ──────┘
                            (virtual net)

frpc ──────────────► frp-client ──────► frp-core
(client binary)      (client logic)      (shared library)
                       │                   ▲
                       └──► frp-vnet ──────┘
                            (virtual net)
```

Dependencies flow **upward** through this diagram (binaries depend on logic crates, which depend on the shared library):

| Crate | Purpose | Key Modules |
|-------|---------|-------------|
| **frp-core** | Shared library with no internal workspace dependencies | Protocol framing (`protocol.rs`), message types (`msg.rs`), config parsing (`config/`), transport abstraction (`transport/`), auth (`auth.rs`), encryption (`encryption.rs`), bridge (`bridge.rs`), mux (`mux.rs`), QUIC (`quic.rs`), KCP (`kcp/`), STUN (`stun.rs`), V2 handshake (`v2_handshake.rs`), cipher streams (`cipher_stream.rs`) |
| **frp-server** | Server logic -- control handler, proxy registration, connection bridging | Service + accept loop (`service.rs`), control handler (`control/mod.rs`), proxy management (`proxy.rs`), bridge assignment (`control/bridge.rs`), proxy registration (`control/proxy_ops.rs`), NAT hole punching (`nathole/`), VHost routing (`vhost.rs`), dashboard + admin API (`dashboard.rs`), SSH gateway (`ssh_gateway.rs`), TCPMux (`tcpmux.rs`), config reload (SIGUSR1, `service.rs`), state (`state.rs`), handlers (`handlers.rs`) |
| **frp-client** | Client logic -- service lifecycle, control connection, local bridging | Client service (`service.rs`), work connections (`work_conn.rs`), visitor mode (`visitor.rs`), admin API (`admin.rs`), health checks (`health.rs`), client plugins (`plugin/`) |
| **frps** | Server binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_server::Service::run()` |
| **frpc** | Client binary | CLI argument parsing (`frp_core::cli`), logging setup, calls `frp_client::Service::run()` |

`frp-core` has no dependencies on other workspace crates -- it defines the wire protocol, message types, and transport primitives that both server and client use. The `frp-server` and `frp-client` crates contain the protocol logic but no `main()` functions; binaries live in `frps/` and `frpc/`.

**Architecture internals** (wire protocol, control plane, transports, XTCP)
live in [architecture.md](architecture.md). The rules and gotchas an agent or
contributor must not break are in [CLAUDE.md](../CLAUDE.md#gotchas). For the
reference docs (config, proxies, plugins, deployment) see the
[documentation index](README.md).

## 2. Adding a New Proxy Type

This section walks through adding a new proxy type called `myproxy`:

### Step 1: Config Parsing (if needed)

If the new proxy type requires new config fields, add them to the proxy config struct in `frp-core/src/config/`. Existing proxy config fields are shared across all proxy types in `ProxyConfig` -- if your proxy type reuses those fields, no config changes are needed.

### Step 2: Register in ProxyManager

In `frp-server/src/control/proxy_ops.rs`, the `handle_new_proxy` function registers proxies in `ProxyManager`. Most proxy types reuse the existing registration logic. If your proxy type needs special registration:

- **Port allocation**: the function already handles port allocation via `allocate_port_multi()`. SUDP proxies get special shared-port handling.
- **sk_index**: STCP/XTCP proxies register in `sk_index` for secret-key routing. Add your proxy type here if it uses sk-based routing.
- **VHost routing**: HTTP/HTTPS proxies register in `VhostManager`. Add your proxy type here if it uses domain-based routing.
- **TcpMux routing**: TCPMux proxies register in `TcpMuxManager`.

### Step 3: Add Listener Setup

In `frp-server/src/control/proxy_ops.rs`, after proxy registration, the function spawns a listener task. The existing `listen_and_proxy()` helper starts TCP listeners for tcp/http/https/stcp/tcpmux proxy types. UDP proxies use `listen_and_proxy_udp()`.

For a new proxy type that needs a different listener pattern:
1. Add a branch in the proxy type match after registration
2. Spawn a `tokio::spawn` task that binds a `TcpListener` on the allocated port
3. On accept, send `InternalMsg::ProxyUserConn` with the user connection and pre-read bytes

Example pattern (simplified from existing code):

```rust
let listener = TcpListener::bind(&addr).await?;
let internal_tx_clone = internal_tx.clone();
tokio::spawn(async move {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = internal_tx_clone.send(InternalMsg::ProxyUserConn {
                    proxy_name: name.clone(),
                    user_conn: IoStream::Tcp(stream),
                    pre_read: vec![],
                });
            }
            Err(_) => break,
        }
    }
});
```

### Step 4: Implement Bridging Logic

The bridging is handled automatically by the control handler's `InternalMsg::ProxyUserConn` path -- it pops a work connection from the pool, sends `StartWorkConn`, and bridges. No special bridging code is needed for basic TCP-like proxy types.

If your proxy type needs special bridging (e.g., HTTP host header rewriting, protocol-specific framing), add the logic in `frp-server/src/control/bridge.rs`. The existing `assign_work_to_proxy` function handles plain vs encrypted bridging and pre-read byte forwarding.

For the client side, proxy type handling is in `frp-client/src/service.rs` and `frp-client/src/work_conn.rs` -- the client reads `StartWorkConn` to know which local service to connect to.

## 3. Building and Feature Flags

### Quick Reference

```bash
cargo build                  # Debug build (all crates)
cargo build --release        # Release build (opt-level=z, LTO, panic=abort)
cargo test --workspace       # Run all tests
cargo clippy                 # Lint
```

### Binary Variants

Four size tiers via feature flags. The authoritative tier list, exact commands
and measured binary sizes live in the README —
[**Binary Variants**](../README.md#binary-variants). The resulting binaries are
named `frps`/`frpc` (default/full), `frps-tiny`/`frpc-tiny`, and
`frps-micro`/`frpc-micro`.

### Feature Flags

| Feature | Crate | What it removes |
|---------|-------|-----------------|
| `quic` | frp-core | QUIC transport (quinn) — **default ON** (was opt-in) |
| `kcp` | frp-core | KCP transport (in-tree, kcp-go v5.6.13 aligned) |
| `websocket` | frp-core/server | WebSocket transport (manual RFC 6455 framing, no tungstenite since 2026-08-09) |
| `oidc` | frp-core | OIDC auth (jsonwebtoken, hyper via `http-client`) |
| `ssh` | frp-server | SSH gateway (russh, rand 0.10) |
| `dashboard` | frp-server | Metrics/status API (prometheus, axum) |
| `admin` | frp-client | frpc admin API (axum) — opt-in since 2026-08-09 |
| `http2http` | frp-client | HTTP/2 (h2) support for the https2http/https2https plugins; implies `tls` |
| `tls` | frp-core/server/client | TLS encryption (rustls — **vendored** at `vendor/rustls` 0.23.43 with an SNI patch, see below) |
| `compression` | frp-core | Snappy bridge compression (snap) |
| `chacha20` | frp-core | XChaCha20-Poly1305 V2 cipher (AES-256-GCM stays) |
| `http-proxy` | frp-server | HTTP proxy plugin (hyper/http-client) — server-side opt-in |
| `tcp-mux` | frp-core/server/client | yamux stream multiplexing (**vendored** at `vendor/yamux`, see below) |
| `vnet` | frp-core/server/client | L3 VPN / TUN device routing — opt-in |
| `admin-auth` | frp-core | shared admin auth helpers (token/basic) |
| `mimalloc` | frps/frpc | mimalloc global allocator — opt-in |
| `mem-profile` | frp-core/server/client | CountingAlloc + MEMPROFILE emitter (dev only; **exclusive with `mimalloc`**) |
| `profiling` | frp-core | profiling gate (dev only) |
| `otel` | frp-core/server/client | OpenTelemetry tracing + OTLP export — opt-in |
| `debug-logs` | frp-core | debug/trace logging (dev only) |

frps default ON: `websocket`, `kcp`, `quic`, `oidc`, `tls`, `http-proxy`, `compression`, `chacha20`, `tcp-mux`, `ssh`. frpc default ON: `websocket`, `kcp`, `quic`, `oidc`, `tls`, `compression`, `chacha20`, `tcp-mux`, `http2http` (**no `admin`** since 2026-08-09). Opt-in: `admin`, `dashboard`, `vnet`, `otel`, `mimalloc`, dev-only flags (`debug-logs`, `mem-profile`, `profiling`). `quic` implies `tls`. `oidc` implies `http-client` (hyper). `ssh` implies `rand`. `mem-profile` is mutually exclusive with `mimalloc` (cfg-exclusive global-allocator guards).

### Release Profile

```toml
# Cargo.toml
[profile.release]
opt-level = "z"       # Optimize for size
lto = "fat"           # Link-time optimization across all crates
codegen-units = 1     # Single codegen unit for better optimization
strip = "symbols"     # Strip debug symbols
panic = "abort"       # Abort on panic (smaller binary, no unwind tables)
```

After `cargo build --release`, further compress with UPX:

```bash
upx --best --lzma target/release/frps target/release/frpc
```

## 4. Debugging

### RUST_LOG Levels

The project uses `tracing` for structured logging. Available levels: `error`, `warn`, `info`, `debug`, `trace`.

```bash
# Debug logging for everything
RUST_LOG=debug cargo run --bin frps -- -c frps.toml

# Target-specific logging
RUST_LOG=frp_server::control=debug cargo run --bin frps -- -c frps.toml

# Trace-level for wire protocol inspection
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml

# Multiple targets
RUST_LOG=frp_server=debug,frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

Key tracing targets:
- `frp_core::protocol` -- V1 frame writes (`trace` level includes full JSON payloads)
- `frp_server::service` -- connection accept, TLS handshake, dispatch
- `frp_server::control` -- control handler lifecycle, internal message routing, heartbeat
- `frp_server::control::bridge` -- work connection bridging
- `frp_core::transport` -- connection type detection, magic byte stripping
- `frp_server::nathole` -- NAT hole punch session lifecycle
- `frp_client::service` -- client lifecycle, proxy registration
- `frp_client::work_conn` -- work connection management

### Inspecting Wire Protocol

Enable trace-level logging for `frp_core::protocol` to see every frame sent and received:

```bash
RUST_LOG=frp_core::protocol=trace cargo run --bin frps -- -c frps.toml
```

This outputs the type byte, payload length, and full JSON content for each V1 frame. For hex dumps of the raw bytes, use an external tool like `tcpdump` or `wireshark`:

```bash
# Capture frp traffic on loopback
sudo tcpdump -i lo -A -s 0 port 7000

# Capture with hex dump
sudo tcpdump -i lo -X -s 0 port 7000
```

### Common Issues

**"Connection reset by peer" on startup:**
- Check that `bind_port` is not already in use
- Verify the server and client `token` match
- Check that `server_addr` is reachable from the client

**Proxy connections time out:**
- Check `heartbeat_timeout` -- client must ping within this interval
- Check `pool_count` -- if too low, proxy connections queue and expire after 10s
- Verify firewall allows traffic on proxy ports

**Enrypted bridge corruption:**
- Both sides must agree on `use_encryption` and `use_compression`
- The encryption key derives from the auth token -- mismatched tokens = corrupted bridge

**TLS handshake failures:**
- TLS requires valid cert/key files (`tls_cert_file`, `tls_key_file`)
- When `tls_only` is true, non-TLS connections are rejected
- WebSocket over TLS requires the client to connect with `wss://` and `transport_protocol = "wss"`

**XTCP hole punch failures:**
- Both provider and visitor need public internet access for STUN
- Symmetric NAT on both sides usually prevents hole punching -- STCP fallback is needed
- Check that `sk` is set and identical on both provider and visitor proxies

## 5. Testing

### Unit Tests

Unit tests live inline in `#[cfg(test)] mod tests` blocks within source files. Integration tests live in the `frp-server/tests/` and `frp-client/tests/` directories (see "Writing New Tests" below).

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p frp-core
cargo test -p frp-server
cargo test -p frp-client

# Run a specific test by name
cargo test -p frp-core -- protocol::tests

# Run with output (show println! and tracing)
cargo test -- --nocapture

# Run ignored tests (e.g., tests requiring network access)
cargo test -- --ignored
```

### Cross-Compatibility Tests

The compat test suite verifies Go frp <-> Rust frp interop across all proxy types and transport protocols:

```bash
# Full suite (86 run_test scenarios, 2 of which are gated on Go frp V2)
bash scripts/compat-test.sh --verbose

# Filter by proxy type and direction
bash scripts/compat-test.sh tcp g2r     # TCP proxy, Go client -> Rust server
bash scripts/compat-test.sh xtcp        # All XTCP tests
bash scripts/compat-test.sh transport   # Transport protocol tests only

# Filter by direction
bash scripts/compat-test.sh g2r         # All Go->Rust tests
bash scripts/compat-test.sh r2g         # All Rust->Go tests
```

The compat tests require Go frp binaries. Download them first:

```bash
bash scripts/download-go-frp.sh
```

This downloads Go frp v0.71.0 binaries to `scripts/go-frp/`. The CI gate is `.github/workflows/compat.yml`.

### XTCP CI Tests

XTCP tests require public internet (for STUN) and run on a VPS:

```bash
# Setup VPS (one-time)
bash scripts/vps-setup.sh

# Run XTCP tests on VPS
bash scripts/remote-frps.sh xtcp
```

XTCP CI uses sharded matrix jobs (`.github/workflows/xtcp-compat.yml`) with per-shard directories for isolation. 17 tests covering the 2x2 implementation matrix (Go/Rust server × Go/Rust client) plus QUIC-data-plane and encrypted variants.

### Writing New Tests

Follow these conventions:

1. **Inline tests**: add to the relevant source file's `#[cfg(test)] mod tests`
2. **Integration tests**: add to `frp-server/tests/` or `frp-client/tests/`
3. **Use `test_utils`**: each crate may provide test helpers for spawning servers/clients
4. **Avoid port conflicts**: use port `0` for auto-allocation or pick unique ports
5. **Clean up**: ensure spawned tasks/processes are killed on test completion

### Benchmarks

Criterion micro-benchmarks in `frp-core/benches/crypto_bridge.rs` (8 groups) and `frp-server/benches/nathole.rs` (2 groups):

```bash
# Run all benchmarks (slow — runs each bench many times)
cargo bench -p frp-core
cargo bench -p frp-server

# Quick compile-time check (used in CI)
cargo bench --workspace --no-run

# Run specific groups
cargo bench -p frp-core -- protocol_all_types
cargo bench -p frp-core -- bridge
cargo bench -p frp-server -- nat_analysis
```

CI gate: `cargo bench --workspace --no-run` in `.github/workflows/ci.yml` ensures benchmarks don't bit-rot.

### Stress Tests

Long-running load test (`scripts/stress-test.sh`) that runs frps + frpc under connection churn:

```bash
bash scripts/stress-test.sh
```

Monitors memory, connection counts, and throughput. Runs weekly in CI via `.github/workflows/stress-test.yml`. The `scripts/frp-stress/` crate contains the load generator (not part of the main workspace).

### Property & Fuzz Tests

Proptest-based tests verify correctness under adversarial inputs:
- **Config normalization** (`frp-core/src/config/`): 9 proptest! blocks — idempotency, flat↔nested equivalence, camelCase→snake_case
- **Protocol fuzzing** (`frp-core/src/protocol.rs`): 6 fuzz tests + 35 regular tests — all 256 V1 type bytes × arbitrary payloads, V2 arbitrary type IDs, truncated frames, magic detection

## 6. Release Process

### Version Bumping

**frp-rs 自身版本号严格对齐 Go frp 的发布号** (mandatory): the version
equals the current compat target Go frp release — currently **0.71.0** — and
bumps only when Go frp releases a new number. Update the version in ALL
sync locations:

```bash
# All crates share the same version
# Update in:
#   Cargo.toml (workspace)
#   frp-core/Cargo.toml
#   frp-server/Cargo.toml
#   frp-client/Cargo.toml
#   frps/Cargo.toml
#   frpc/Cargo.toml
#   frp-core/src/lib.rs  (VERSION constant)
#   scripts/download-frp-rs.sh  (default version)
#   README.md
```

Exception: `frp-vnet` stays independent at `0.1.0`.

### Building Release Binaries

The release workflow (`.github/workflows/release.yml`) cross-compiles for 13 targets:

- **Linux**: x86_64, aarch64, armv7, arm, i686, riscv64gc — glibc builds for all six, musl only for x86_64/aarch64/armv7 (built with `cargo zigbuild`)
- **macOS**: x86_64, aarch64 -- native builds
- **Windows**: x86_64, aarch64 -- native builds

Each target produces three variants: full, tiny, and micro.

To build locally for your platform:

```bash
# Full
cargo build --release -p frps -p frpc

# Tiny
cargo build --release -p frps -p frpc --no-default-features --features tiny

# Micro
cargo build --release -p frps -p frpc --no-default-features --features micro
```

### UPX Compression

After building, compress with UPX for additional size reduction (optional):

```bash
upx --best --lzma target/release/frps target/release/frpc
```

UPX is not required -- the release profile already produces compact binaries via `opt-level=z`, `lto=fat`, and `strip=symbols`.

### Docker Image Publication

The Docker image is built from source in a multi-stage build (`docker/Dockerfile.source`):

```bash
# Build for frps (from repo root)
docker build --build-arg FRP_COMPONENT=frps -t frps:latest -f docker/Dockerfile.source .

# Build for frpc
docker build --build-arg FRP_COMPONENT=frpc -t frpc:latest -f docker/Dockerfile.source .
```

Also available: `frps-tiny`, `frpc-tiny`, `frps-micro`, `frpc-micro` variants. The release workflow (`.github/workflows/docker.yml`) builds and pushes multi-arch images for all 6 variants. The image uses a `scratch` base (~2 MB total) with a musl-static binary.

### Triggering a Release

Releases are triggered by pushing a version tag or manually via workflow dispatch:

```bash
# Tag and push (triggers .github/workflows/release.yml)
git tag v0.71.0
git push origin v0.71.0
```

The release workflow:
1. Builds all 13 targets (9 Linux via cargo-zigbuild + 2 macOS + 2 Windows)
2. Packages each as `.tar.gz` (Linux/macOS) or `.zip` (Windows)
3. Creates a GitHub Release with auto-generated notes
4. Uploads all artifacts

The Docker workflow runs separately (`.github/workflows/docker.yml`) and can be triggered manually or on release.

## Dependency Policy

**No new dependencies without explicit justification.** Every new crate must document:

1. **Why it is needed** -- what problem it solves that existing deps cannot
2. **Why the alternative was rejected** -- why an existing dep cannot be used
3. **Binary size impact** -- approximate cost to frps/frpc release binary

**Pre-approved tech stack** (use these unless strong reason to deviate):

| Domain | Crate |
|--------|-------|
| Async runtime | `tokio` |
| Serialization | `serde` + `serde_json` |
| Config | `toml` 0.8 |
| Crypto (general) | `ring` 0.17 |
| Crypto (Go compat) | `aes` + `cfb-mode`, `pbkdf2` + `sha1`, `md-5` |
| Crypto (V2 XChaCha20) | `chacha20poly1305` |
| TLS | `rustls` + `tokio-rustls` + `rustls-platform-verifier` — **vendored** at `vendor/rustls` 0.23.43 via `[patch.crates-io]` with a one-line SNI patch (`ServerNamePayload::Invalid` → treat as no-SNI) for Go XTCP QUIC visitor compat; delete the vendored copy when upgrading to rustls ≥0.24 (native `invalid_sni_policy`) |
| SSH | `russh` (ring backend, NOT aws-lc-rs) |
| HTTP client | `hyper` + `hyper-rustls` + `hyper-util` (inline `frp_core::http_client`; OIDC/proxy/plugin — no reqwest) |
| HTTP server | `axum` |
| WebSocket | manual RFC 6455 framing (in-tree `websocket.rs`; `tokio-tungstenite` removed 2026-08-09) |
| Encoding | inline `frp_core::base64` (encode/decode) + `frp_core::hex_encode` |
| Compression | `snap` |
| QUIC | `quinn` |
| TcpMux | `yamux` 0.14 — **vendored** at `vendor/yamux` via `[patch.crates-io]` with four patches (per-stream RST on stream-cap hit, lost-wakeup `sender_wu` fix, receive-window cap, body-buffer pools) |
| OIDC/JWT | `jsonwebtoken` |
| Logging | `tracing` + `tracing-subscriber` + `tracing-appender` |
| Error handling | `anyhow` + `thiserror` |
| Random | `rand` 0.10 (0.8.7 remains in the lock only via the opt-in `otel` chain: opentelemetry_sdk → … → tonic → tower — third-party pins, latest releases) |
| Misc | `bytes`, `uuid`, `futures-util`, `tokio-util`, `socket2`, `prometheus` |

**Banned** (do not reintroduce without approval): `aws-lc-sys`, `aws-lc-rs`, `hmac`, `base64`, `sha2`, `aes-gcm`, `hkdf`, `hickory-resolver`, `lazy_static`, `data-encoding`, `hex`, `tokio-tungstenite`. Note: `libc` is an **active** direct dependency (frp-core Linux `splice(2)`, frp-vnet TUN ioctl), not banned. "Banned" means no direct dependency — several still exist transitively via the SSH feature chain (russh → ssh-key).

Workspace dependencies use `resolver = "2"` with `[workspace.dependencies]` for all crates. To add a new dependency: add to the workspace level, then reference by name (no version) in sub-crates.
