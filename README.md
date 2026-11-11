<div align="center">
  <h1>frp-rs</h1>
  <p><em>A fast reverse proxy written in Rust — protocol-compatible with frp.</em></p>
  <p>
    <a href="#overview">Overview</a> •
    <a href="#performance">Performance</a> •
    <a href="#features--usage">Features &amp; Usage</a> •
    <a href="#deployment">Deployment</a> •
    <a href="#technical-differences-vs-go-frp">Technical Differences</a> •
    <a href="#documentation">Documentation</a> •
    <a href="#developing">Developing</a>
  </p>
  <p>
    <a href="https://github.com/viogus/frp-rs">GitHub</a> •
    <a href="https://github.com/viogus/frp-rs/issues">Issues</a> •
    <a href="https://github.com/viogus/frp-rs/releases">Releases</a>
  </p>
</div>

---

## Overview

**frp-rs** is a native Rust implementation of [frp](https://github.com/fatedier/frp),
a reverse proxy that exposes services on a private network to the public internet.
It speaks the same wire protocol as the Go version, so it can replace *either* the
client or the server side on its own.

**Current version: frp-rs 0.72.0**, the Go frp release it is compatible with — the
version number is deliberately not independent (see
[Versioning](CLAUDE.md#versioning-mandatory)).

- **Swap one side at a time — and swap back the same way.** An frp-rs `frpc` talks
  to a Go `frps`, and an frp-rs `frps` serves Go `frpc` clients, with the same config
  files, encryption and authentication. This is a CI gate rather than a claim:
  `scripts/compat-test.sh` runs 86 scenarios plus a 17-case XTCP pairwise matrix
  against the **real Go frp v0.72.0 release** in both directions on every push, and
  `scripts/protocol-matrix.sh` asserts that all 11 transport rows actually move
  bytes and stay above a per-row throughput floor. Each of those counts is re-measured by `scripts/repo-health.sh`, which
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
- **Faster on the same bytes, with less of the machine.** In the configuration
  both projects ship by default (`tcpMux` + TLS), frp-rs moves **+41%** more
  bytes than the Go release it replaces, at **28–30% less CPU per MiB**, with
  **2–3.4× lower peak RSS** and a **2.4× smaller binary**. Tables, method and the
  caveats that go with them are in [Performance](#performance).
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

Client plugins: `http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `http2https`, `https2http`, `https2https`, `http2http`, `tls2raw`, `virtual_net`, `http2connect`.

**frp-rs extensions Go frp does not have:**
- **SOCKS5 `UDP ASSOCIATE`** (RFC 1928 §7) in the `socks5` plugin — Go frp's `socks5` plugin is CONNECT-only. Enable with `plugin.udp_enable`; frpc automatically registers a same-port UDP companion, so no second `[[proxies]]` block is needed. See [Client Plugins § SOCKS5](docs/client-plugins.md#2-socks5-plugintype--socks5).
- **`http2connect`** — an HTTP/2 `CONNECT` (TCP) and RFC 9298 `CONNECT-UDP` forward proxy. Go frp has no HTTP/2 CONNECT plugin; see [Client Plugins § HTTP/2 CONNECT](docs/client-plugins.md#10-http2-connect-plugintype--http2connect-frp-rs-extension).

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
- **UDP bandwidth limiting is an frp-rs extension in `client`/`both` mode** — Go applies
  the per-proxy limiter to its UDP forwarder only on the **server** side
  (`bandwidthLimitMode = "server"`); its client-side UDP forwarder has no limiter. frp-rs
  applies the same `bandwidthLimit` semantics in every mode, direction semantics match the
  TCP bridge, and the default stays unlimited unless a rate is configured.
- **The SSH gateway fails closed** — with no `authorized_keys` and no server token it
  refuses to start. Set `ssh_tunnel_gateway.allowNoneAuth = true` to opt into Go's
  anonymous behaviour on a trusted network.
- **Windows vnet (TUN)** — Linux and macOS only; the Windows TUN is a stub pending
  Wintun integration. Go frp's vnet is Linux-focused too, so this is not a compat gap.

---

## Performance

Measured against the real Go frp release frp-rs replaces — same host, same
config files, same client, both at v0.72.0. A dedicated 4-vCPU Linux VM, four
flows of a one-way stream, 8192 MiB per run, mean of three interleaved repeats:

| configuration | frp-rs | Go frp v0.72.0 | frp-rs lead |
|---|---|---|---|
| **`tcpMux` + TLS** — what both projects ship by default | **562 MiB/s** | 399 MiB/s | **+41%** |
| `tcpMux`, TLS off | 970 MiB/s | 647 MiB/s | **+50%** |
| no `tcpMux`, TLS on | 1298 MiB/s | 956 MiB/s | **+36%** |
| no `tcpMux`, TLS off | 2168 MiB/s | 1650 MiB/s | **+31%** |

and it does that with less of the machine, in the same session:

| resource | frp-rs | Go frp v0.72.0 |
|---|---|---|
| CPU per MiB, `tcpMux` + TLS | **3,723 µs** | 5,184 µs |
| CPU per MiB, `tcpMux`, no TLS | **2,248 µs** | 3,221 µs |
| Peak RSS, `tcpMux` + TLS | **16.0 / 15.4 MB** | 34.8 / 49.9 MB |
| Peak RSS, `tcpMux`, no TLS | **15.8 / 17.9 MB** | 34.3 / 60.1 MB |
| Release binary, `frps` / `frpc` | **8.5 / 7.2 MB** | 21.3 / 17.5 MB |

**The caveats matter as much as the numbers.** These are four flows on a
**four-vCPU box shared by client, sink and both proxies**, so the side that burns
fewer cycles per byte wins — on a host with idle cores the ordering can invert
(measured once on an 8-core M2: frp-rs used ~36% less CPU while Go pushed more
bytes by spending more cores). TLS costs about 40% of throughput on **both**
implementations, so it is not a differentiator. One host, one network path, two
repeats: every repeat-pair ratio was positive (+9% to +57%), the per-row spread
is ±6%, and nothing here predicts your hardware or your path.

**Why it is faster, and what is left.** The profile of the shipping
configuration is dominated by things frp-rs does not own: AES-GCM ~9%,
kernel copies ~10%. The one cost we did own — `rustls`'s deframer
re-allocating and re-faulting per record — was 16.9% of frpc's samples and is
fixed by a vendored read-size patch (see the changelog). No yamux,
bridge or protocol-frame code appears in the top 15 — which is why the three
structural rewrites that were built and measured (vectored yamux write, a
one-copy `poll_write_bufs` path, an inline writer) all landed inside the noise
and were not adopted. The changes that *did* move numbers were narrower and are
in the changelog: a 64 KiB bridge buffer, which is also one tcpMux frame
(+13.5% on the mux path), [one write per protocol frame][coalesce] (+46% UDP
packets/s under `tcpMux`), [no 1 ms timer per returned datagram][udp-reply]
(773 → 7,916 pps), and [KCP FEC parity from a lookup table][kcp-fec]
(~21 → ~63 MiB/s, ping-pong shape on macOS — that note's stream rows are withdrawn, so
read the paragraph below for KCP streams).

Method, host details, the retractions and the limits:
[`docs/archive/notes/2026-11-10-real-host-throughput.md`](docs/archive/notes/2026-11-10-real-host-throughput.md).

**Not every shape is faster.** On bulk KCP streams — one to four flows of a
2048 MiB one-way transfer over loopback, `tcpMux` and TLS on — frp-rs moves
65 MiB/s where Go moves 99-102, at about 1.5× the CPU per byte (72 against 45
CPU-seconds per 2048 MiB), while KCP's small-payload latency is far better
(394 round trips/s against 40 — a different harness and host, so direction
only). That gap was 49 versus 103 when it was first measured: the AVX2 parity
pass, one `sendmmsg` per flush and tick, filling segments before sending them,
one `recvmmsg` per wakeup, one flush per batch of writes, and a 1400-byte MTU
(matching kcp-go) have closed part of it. The rest is per-packet cost: frp-rs
sends 1.1× Go's datagrams (591k against 535k per 512 MiB), and most of the
remainder is one ack datagram per write (88k against Go's 18k) — batching those
to the tick was measured and costs 28% of throughput, so it stays. The numbers, the
evidence that separates them and the unestablished part are in
[`docs/archive/notes/2026-11-11-kcp-stream-vs-go.md`](docs/archive/notes/2026-11-11-kcp-stream-vs-go.md);
closing it is a tracked TODO, not a claim.

[coalesce]: docs/archive/notes/2026-11-09-yamux-inline-write.md
[udp-reply]: docs/archive/notes/2026-11-08-udp-spare-reuse.md
[kcp-fec]: docs/archive/notes/2026-11-09-kcp-fec-multiply-tables.md

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

`SIGUSR1` hot-reloads `auth.token` / `auth.tokenSource`,
`auth.additionalAuthScopes`, `auth.authenticationTimeout` /
`auth.tokenAuthTimeout`, the allowed port range, and the TLS
certificate/key/CA paths. Everything else it cannot apply — `auth.method` and
the OIDC settings, `[log]`, `[transport]`, the registration caps, `[web_server]`,
`[ssh_tunnel_gateway]`, `[observability]` and the rest — is **reported in the
reload summary** as restart-required rather than silently dropped; settings no
code reads (`auth.useEncryption`, `tls_enable`, `tls_server_name`, `web_server.pprof_enable`,
…) are deliberately not reported, because a restart would not change anything
either. The full list is in
[Configuration Reference § Server Config Reload](docs/config.md#server-config-reload-sigusr1).

---

## Technical Differences vs Go frp

The first five are argued in full, together with what frp-rs is *not*, in
**[docs/why-frp-rs.md](docs/why-frp-rs.md)**; item 6 lives in the notes it
links. The short version:

1. **Adopt it one side at a time.** Wire-compatible in both directions with the same
   config files: replace one binary, leave the other side exactly as it is, roll back
   by putting the old file back. Evidence rather than promise — 86 `compat-test.sh`
   scenarios plus a 17-case XTCP pairwise matrix against the real Go frp v0.72.0, both
   directions, on every push; 11/11 transport rows moving bytes in
   `protocol-matrix.sh`. `scripts/repo-health.sh` re-measures each of those counts.
2. **It runs where a 17 MB binary does not fit.** The `tiny` and `micro` tiers are a
   *new deployment* rather than a replacement: OpenWrt, IoT, size-capped images.
3. **No GC.** A stable heap instead of one that grows to roughly 2× live, and no
   stop-the-world tail. *(A 3-hour head-to-head RSS series against Go frp is published in
   [scripts/frp-stress/baselines/rss-soak-Mac.jsonl](scripts/frp-stress/baselines/rss-soak-Mac.jsonl);
   "stable over weeks" remains a hypothesis, see [TODO.md](TODO.md).)*
4. **Operational knobs Go frp lacks:** UDP bandwidth limiting, SSH gateway per-IP
   login throttling plus `ssh_session_idle_timeout`, and
   `frpc verify --strict-config`.
5. **Verification posture:** every deliberate divergence is recorded with the Go
   source `file:line` that justifies it, in the
   [compatibility audit](docs/go-frp-compat-audit.md) and the
   [development log](docs/history/development-log.md), and the compat suite runs
   against the real Go binary on every push.
6. **Faster on the paths we have measured.** +41% throughput in the shipping
   `tcpMux` + TLS configuration, +31% to +50% across the rest of the TCP matrix,
   28–30% less CPU per MiB and 2–3.4× lower peak RSS than the Go release this
   replaces — plus +46% UDP packets/s from writing each frame once, and 10.2×
   the datagram rate on the reply path. Tables, method and caveats:
   [Performance](#performance).

<!-- Generated by scripts/compare-go-frp.sh on 2026-11-06 —
     platform: darwin_arm64; frp-rs 0.72.0; Go frp 0.72.0;
     rustc 1.98.1 (48a229cea 2026-09-01); declared release profile.
     Regenerate rather than editing these numbers by hand. -->

| Metric | Go frp v0.72.0 | frp-rs (default) | frp-rs (`tiny`) | frp-rs (`micro`) |
|--------|---------------|------------------|-----------------|-------------------|
| frps binary | 18.4 MB | 5.1 MB | 3.3 MB | 2.0 MB |
| frpc binary | 14.9 MB | 4.3 MB | 2.9 MB | 2.2 MB |
| Memory (idle, frps) | 27.9 MB | 10.0 MB | 9.0 MB | 3.8 MB |
| Memory (idle, frpc) | 18.0 MB | 9.5 MB | — | — |

Measured on **macOS arm64**, both implementations at **v0.72.0**, with the declared
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
| [`rustls`](vendor/rustls/README-FRP-RS.md) | 0.23.46 | Two patches. (1) Go frp XTCP QUIC visitors send the peer `"ip:port"` as the TLS SNI and rustls 0.23 rejects it as invalid; the patch treats an invalid SNI as *no SNI* (server-side only). (2) The deframer reads in 4 KiB steps and frees the grown buffer whenever it empties, which cost `Vec::resize` 16.9% of frpc's samples in a bulk transfer; it now reads a whole record per syscall (+4.2% throughput, −4.8% CPU). | **Delete when the workspace moves to rustls ≥ 0.24** — `invalid_sni_policy = IgnoreAll` is native there. Until then, track 0.23.x `RUSTSEC` advisories manually on every release. 0.23.46 is the fix for RUSTSEC-2026-0346/-0347/-0348/-0349 (published 2026-10-14); the earlier 0.23.45 bump fixed GHSA-2mjx-qc3c-rqvc (affects 0.23.13–0.23.44). |
| [`yamux`](vendor/yamux/README-FRP-RS.md) | 0.14.1 | 5 patches: per-stream RST at the inbound stream cap (instead of a session-killing GoAway, matching Go frp's fork), a per-stream receive-window cap, window-growth RTT seeding, a send+read body-buffer pool, and an exact `outbound_unacked` ACK counter. | Upstream each patch, or re-apply on every yamux bump (each patch section lists its own upgrade note). The read-side lost-wakeup fix carried at 0.14.0 is upstream as of 0.14.1 (`libp2p/rust-yamux` PR #233, closing issue #232, commit `a9ea49e4`), so only those five remain. The vendored crate is not a workspace member, so no gate compiles its own tests; its README lists the two manual re-check commands. |
| [`russh`](vendor/russh/README-FRP-RS.md) | 0.65.0 | 2 patches dropping the `ssh-key` `encryption` + `ppk` and `pkcs8` `encryption` chains, which the SSH gateway never uses (`load_secret_key(path, None)` only). Upstream's version of that feature set would pull 11 extra packages (`aes-gcm`, `argon2`, `bcrypt-pbkdf`, `blake2`, `blowfish`, `hex`, `pkcs5`, `salsa20`, `scrypt`, `sha3`, `sponge-cursor`); the trim measured ~48.5 KiB off frps at 0.62.7 (not re-measured at 0.65.0). | Drop when upstream makes those `ssh-key` features optional. |

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
cargo clippy --workspace --all-targets --all-features -- -D warnings
bash scripts/repo-health.sh            # invariants: version, unsafe, doc paths and figures
bash scripts/compat-test.sh            # Go↔Rust cross-compat suite (needs Go frp)
```

The full workflow — adding a proxy type, feature flags, debugging with `RUST_LOG`,
the test tiers, and the release checklist — is in
[docs/developing.md](docs/developing.md). The compiler is pinned in
`rust-toolchain.toml` at the repo root, so local development and CI both lint
with the same `rustc`/`clippy`.

---

## License

MIT. frp-rs is not affiliated with the original Go frp project.
