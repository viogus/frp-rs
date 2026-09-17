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
a reverse proxy that exposes services on a private network to the public internet.
It speaks the same wire protocol as the Go version, so it can replace *either* the
client or the server side on its own.

**Current version: frp-rs 0.71.0**, the Go frp release it is compatible with — the
version number is deliberately not independent (see
[Versioning](CLAUDE.md#versioning-mandatory)).

- **Swap one side at a time — and swap back the same way.** An frp-rs `frpc` talks
  to a Go `frps`, and an frp-rs `frps` serves Go `frpc` clients, with the same config
  files, encryption and authentication. This is a CI gate rather than a claim:
  `scripts/compat-test.sh` runs 86 scenarios plus a 17-case XTCP pairwise matrix
  against the **real Go frp v0.71.0 release** in both directions on every push, and
  `scripts/protocol-matrix.sh` asserts that all 11 transport rows actually move
  bytes. Each of those counts is re-measured by `scripts/repo-health.sh`, which
  fails if this line drifts.
- **3.5× smaller and 2.7× lighter** at the default tier, and 1.9 MB of frps plus
  2.1 MB of frpc at `micro` — small enough for OpenWrt routers, IoT devices and
  size-capped images where a 17 MB Go binary does not fit at all. Every figure in
  this bullet is read off the measured, generated table in
  [Technical Differences](#technical-differences-vs-go-frp) (produced by
  `scripts/compare-go-frp.sh`, its only copy): 17.7/5.1 = 3.5×, 26.3/9.9 = 2.7×.
- **No garbage collector** — a stable heap instead of one that grows to roughly 2×
  live, and no stop-the-world component in the tail. Long-uptime head-to-head RSS
  is still an open measurement: see [TODO.md](TODO.md).
- **Operational knobs Go frp does not have** — UDP bandwidth limiting, SSH gateway
  per-IP login throttling with `ssh_session_idle_timeout`, and
  `frpc verify --strict-config`.
- **Verification over assertion** — every deliberate divergence from Go frp is
  recorded with the Go source `file:line` behind it. For what the tests do *not*
  prove, read
  [developing.md § What a green test run does and does not prove](docs/developing.md#what-a-green-test-run-does-and-does-not-prove).

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

### Known limitations

Each of these is a documented, deliberate boundary rather than an unknown; the full
detail with Go source references is in the
[compatibility audit § Known limitations](docs/go-frp-compat-audit.md#known-limitations).

- **HTTP vhost / plugin semantics** — `responseHeaders`, per-request
  `vhost_http_timeout` 504s, h2c, and the `enableHTTP2` paths on `https2http` /
  `https2https` are implemented to match Go's `httputil.ReverseProxy`. Remaining
  divergences are listed in the audit.
- **`pprof` endpoints** — `/debug/pprof/*` is a placeholder (no Go-style CPU
  profiles); `/healthz` and pprof sit outside auth, matching Go.
- **UDP bandwidth limiting is an frp-rs extension** — Go v0.71.0's UDP forwarder has
  no limiter. Direction semantics match the TCP bridge, and the default stays
  unlimited unless a rate is configured.
- **The SSH gateway fails closed** — with no `authorized_keys` and no server token it
  refuses to start. Set `ssh_tunnel_gateway.allowNoneAuth = true` to opt into Go's
  anonymous behaviour on a trusted network.
- **Windows vnet (TUN)** — Linux and macOS only; the Windows TUN is a stub pending
  Wintun integration. Go frp's vnet is Linux-focused too, so this is not a compat gap.

---

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

From the workspace root:

```bash
cargo build --release
```

The binaries land at `target/release/frps` and `target/release/frpc`.

### Binary Variants

Four size tiers, selected with feature flags. SSH and QUIC are on by default;
`dashboard` is opt-in. Sizes live in the generated table under
[Technical Differences vs Go frp](#technical-differences-vs-go-frp) — one copy only,
because two copies drift and the wrong one always looks authoritative.

```bash
cargo build --release -p frps -p frpc                                     # default
cargo build --release -p frps -p frpc --features "ssh,quic,dashboard"     # + dashboard
cargo build --release -p frps -p frpc --no-default-features --features tiny
cargo build --release -p frps -p frpc --no-default-features --features micro
```

The complete feature-flag table — every flag, the crate that owns it, and what it
adds or removes — is
[CLAUDE.md § Binary Variants](CLAUDE.md#binary-variants); the release profile and
build matrix are in
[docs/developing.md § 3. Building and Feature Flags](docs/developing.md#3-building-and-feature-flags).
`tiny` and `micro` are binary-level profiles that produce `frps-tiny`, `frpc-tiny`,
`frps-micro` and `frpc-micro`.

### Configuration

Both sides use Go frp's TOML format, so an existing Go frp config loads unchanged.
A minimal working pair:

```toml
# frps.toml
bind_port = 7000

[auth]
method = "token"
token = "change-me"
```

```toml
# frpc.toml
server_addr = "203.0.113.10"
server_port = 7000
token = "change-me"

[[proxies]]
name = "ssh"
type = "tcp"
local_port = 22
remote_port = 6000
```

Run them with `./frps -c frps.toml` and `./frpc -c frpc.toml`.

Every field — with its type, default and Go frp equivalent — is documented in the
**[Configuration Reference](docs/config.md)**: transports, TLS and mTLS, OIDC,
logging, the dashboard, the management REST API, health checks, bandwidth limits,
proxy groups, config-directory mode, and the `[[proxies]]` / `[[visitors]]` entry
schemas. Per-proxy-type walkthroughs are in the
[Proxy Type Guide](docs/proxies.md), and client-side plugins in
[Client Plugins](docs/client-plugins.md).

---

## Deployment

The production reference is **[docs/deployment.md](docs/deployment.md)** — systemd
units, Docker and Compose, TLS/mTLS, nginx fronting, Prometheus, health checks, log
aggregation, and performance tuning (file-descriptor limits, TCP and kernel sysctls,
connection pooling, bandwidth limiting).

### Docker

Images are published to GitHub Container Registry. `:latest` tracks release tags;
pushes to `main` build `:test` (plus `:testtiny` / `:testmicro` for the small tiers):

```bash
docker pull ghcr.io/viogus/frps-rs:latest   # server
docker pull ghcr.io/viogus/frpc-rs:latest   # client
docker run -d -p 7000:7000 -v $(pwd)/frps.toml:/app/frp.toml ghcr.io/viogus/frps-rs:latest
```

Build variants, UPX compression and a Compose example:
[deployment guide § Docker](docs/deployment.md#2-docker-deployment).

### Server config reload (SIGUSR1)

`SIGUSR1` hot-reloads `auth.token`, the allowed port range, and the TLS
certificate/key/CA paths. Settings that still require a restart — `bind_port`,
`bind_addr`, the `tls_enable` switch, OIDC, and the registration caps — are listed in
[Configuration Reference § Server Config Reload](docs/config.md#server-config-reload-sigusr1).

---

## Technical Differences vs Go frp

The full argument, including what frp-rs is *not*, is in
**[docs/why-frp-rs.md](docs/why-frp-rs.md)**. The short version:

1. **Adopt it one side at a time.** Wire-compatible in both directions with the same
   config files: replace one binary, leave the other side exactly as it is, roll back
   by putting the old file back. Evidence rather than promise — 86 `compat-test.sh`
   scenarios plus a 17-case XTCP pairwise matrix against the real Go frp v0.71.0, both
   directions, on every push; 11/11 transport rows moving bytes in
   `protocol-matrix.sh`. `scripts/repo-health.sh` re-measures each of those counts.
2. **It runs where a 17 MB binary does not fit.** The `tiny` and `micro` tiers are a
   *new deployment* rather than a replacement: OpenWrt, IoT, size-capped images.
3. **No GC.** A stable heap instead of one that grows to roughly 2× live, and no
   stop-the-world tail. *(Long-uptime head-to-head RSS is still open in
   [TODO.md](TODO.md) — until then, treat "stable over weeks" as a hypothesis.)*
4. **Operational knobs Go frp lacks:** UDP bandwidth limiting, SSH gateway per-IP
   login throttling plus `ssh_session_idle_timeout`, and
   `frpc verify --strict-config`.
5. **Verification posture:** every deliberate divergence is recorded with the Go
   source `file:line` that justifies it, in the
   [compatibility audit](docs/go-frp-compat-audit.md) and the
   [development log](docs/history/development-log.md), and the compat suite runs
   against the real Go binary on every push.

<!-- Generated by `bash scripts/compare-go-frp.sh --build --memory` — regenerate
     rather than editing these numbers by hand. -->

| Metric | Go frp v0.71.0 | frp-rs (default) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | 17.7 MB | **5.1 MB** | 3.2 MB | 1.9 MB |
| frpc binary | 14.2 MB | **4.1 MB** | 2.8 MB | 2.1 MB |
| Memory (idle, frps) | 26.3 MB | **9.9 MB** | — | — |
| Memory (idle, frpc) | 17.1 MB | **9.2 MB** | — | — |

Measured on **macOS arm64**, both implementations at **v0.71.0**, with the declared
release profile (`fat-LTO`, `opt-level=z`, `codegen-units=1`, `strip = "symbols"`,
`panic = "abort"`). The table is generated by
[`scripts/compare-go-frp.sh`](scripts/compare-go-frp.sh), which downloads the official
Go release for *this* platform and version and **aborts if either does not match**;
re-run it on your target platform rather than trusting these figures, which are
platform-dependent. CI builds override LTO/opt-level for speed, so CI artifacts are
larger than a release build.

**What frp-rs is not.** Go frp wins on ecosystem, documentation, community and
cross-compilation. frp-rs has a single maintainer and no third-party security audit.
`rustls`, `yamux` and `russh` are vendored, so `cargo update` does not deliver their
security releases — that check is manual (see [Vendored crates](#vendored-crates)).
And `panic = "abort"` means one panic takes down that frps process and every proxy on
it. "Memory safety" is **not** a difference: Go is memory-safe too; the Rust-specific
claims are *no GC*, *no runtime*, and *compile-time data-race freedom*.

---

## Vendored crates

Three crates are patched via `[patch.crates-io]` in the workspace `Cargo.toml`.
Each exists for a concrete, documented reason and **each has an exit condition** —
a vendored crypto/TLS tree is a maintenance liability, not a resting state.

| Crate | Version | Why it is vendored | Exit condition |
|---|---|---|---|
| [`rustls`](vendor/rustls/README-FRP-RS.md) | 0.23.45 | Go frp XTCP QUIC visitors send the peer `"ip:port"` as the TLS SNI; rustls 0.23 rejects it as invalid. Patch treats invalid SNI as *no SNI* (server-side only). | **Delete when the workspace moves to rustls ≥ 0.24** — `invalid_sni_policy = IgnoreAll` is native there. Until then, track 0.23.x `RUSTSEC` advisories manually on every release. 0.23.45 is the fix for GHSA-2mjx-qc3c-rqvc (affects 0.23.13–0.23.44). |
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

**Using frp-rs**

- **[Why frp-rs?](docs/why-frp-rs.md)** — the positioning argument, and what it is not
- **[Configuration Reference](docs/config.md)** — every config field with types, defaults, and Go frp equivalents
- **[Proxy Type Guide](docs/proxies.md)** — when and how to use each proxy type (TCP, UDP, HTTP, STCP, XTCP, …)
- **[Client Plugins](docs/client-plugins.md)** — HTTP proxy, SOCKS5, static file, TLS termination, `virtual_net`, …
- **[Deployment Guide](docs/deployment.md)** — systemd, Docker, TLS, monitoring, performance tuning

**Working on frp-rs**

- **[CLAUDE.md](CLAUDE.md)** — rules, invariants and dependency policy
- **[docs/architecture.md](docs/architecture.md)** — the canonical "how it works"
- **[docs/developing.md](docs/developing.md)** — workflow, testing, release process
- **[TODO.md](TODO.md)** — live backlog, each item with evidence and a done-when

Release history: [CHANGELOG.md](CHANGELOG.md).

---

## Developing

```bash
cargo build --release                  # frps + frpc → target/release/
cargo test --workspace --all-features  # needs an all-features frps binary
cargo clippy --workspace --all-targets --all-features -D warnings
bash scripts/repo-health.sh            # invariants: version, unsafe, doc paths and figures
bash scripts/compat-test.sh            # Go↔Rust cross-compat suite (needs Go frp)
```

The full workflow — adding a proxy type, feature flags, debugging with `RUST_LOG`,
the test tiers, and the release checklist — is in
[docs/developing.md](docs/developing.md).

---

## License

MIT. frp-rs is not affiliated with the original Go frp project.
