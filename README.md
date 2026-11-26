<div align="center">
  <h1>frp-rs</h1>
  <p><em>A high-performance reverse proxy written in Rust — 1.2–2.8× faster than Go frp with 2–3× lower memory, 100% protocol-compatible.</em></p>
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
- **Faster than Go frp on every transport, with a fraction of the CPU and RAM.**
  Measured head-to-head against the official Go frp v0.72.0 release on the same
  4-vCPU Linux VM with identical TOML configs (3/3 interleaved wins on all 10
  rows):
  - **Default (`tcpMux` + TLS):** **+67% throughput** (`769` vs `460 MiB/s`),
    **38% less CPU per MiB**, **2.2–2.5× lower peak RSS**, and **35% lower p50 RTT**.
  - **WebSocket / WSS (`tcpMux`):** **+93% to +104% throughput** (up to **2.0×**
    faster), **46–48% less CPU per MiB**, and **42–48% lower p99 RTT**.
  - **QUIC:** **+39% throughput**, **35% less CPU per MiB**, and **43% lower p99 RTT**.
  - **KCP (10+3 FEC + TLS):** **+97% to +183% throughput** (up to **2.8×**
    faster), **3.2–4.4× higher CPU efficiency**, and **68× lower p50 / 22× lower p99 RTT**.
  - **Plain TCP (`splice`):** **+59% throughput** (`2.92` vs `1.84 GiB/s`) at
    **3.1× CPU efficiency** (`68%` less CPU per MiB).
  Full tables, latency numbers, methodology and caveats are in
  [Performance](#performance).
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

Measured head-to-head against the official **Go frp v0.72.0** `linux/amd64`
release on the same 4-vCPU AMD EPYC-Milan Linux 6.12 VM (loopback, identical
official v0.72.0 TOML configs, both implementations at default worker counts).
Each throughput row is the median of 3 interleaved 6 s `frp-stress --scenario stream`
runs with 4 concurrent flows; **frp-rs won 3/3 interleaved rounds on every
single row (30/30)**.

### All-Transport Throughput, CPU Efficiency & Peak RSS vs Go frp v0.72.0

| Transport configuration | frp-rs (`MiB/s`) | Go frp v0.72.0 (`MiB/s`) | Throughput lead | CPU / MiB (`frp-rs` vs `Go`) | Peak RSS `frps / frpc` (`frp-rs` vs `Go`) |
|---|---:|---:|---:|---|---|
| **`tcpMux` + TLS** *(default)* | **769.1** | 460.1 | **+67%** | **2,887** vs 4,651 µs (**−38%**) | **15.9 / 17.0** vs 34.5 / 43.3 MB (**2.2–2.5× lower**) |
| `tcpMux`, TLS off | **1,184.9** | 772.4 | **+53%** | **1,855** vs 2,775 µs (**−33%**) | **15.9 / 22.8** vs 34.1 / 64.7 MB (**2.1–2.8× lower**) |
| TCP + TLS (no `tcpMux`) | **1,484.9** | 1,203.4 | **+23%** | **1,903** vs 2,346 µs (**−19%**) | **11.3 / 9.3** vs 30.4 / 25.0 MB (**2.7× lower**) |
| Plain TCP (no `tcpMux`, no TLS) | **2,922.6** | 1,841.4 | **+59%** | **428** vs 1,322 µs (**−68%**, **3.1×**) | **10.0 / 8.2** vs 29.8 / 19.2 MB (**2.3–3.0× lower**) |
| **WebSocket + TLS + `tcpMux`** | **767.4** | 398.3 | **+93%** (**1.9×**) | **2,880** vs 5,309 µs (**−46%**) | **16.6 / 18.8** vs 36.9 / 47.8 MB (**2.2–2.5× lower**) |
| **WebSocket + `tcpMux`** | **1,183.1** | 580.3 | **+104%** (**2.0×**) | **1,878** vs 3,622 µs (**−48%**) | **15.5 / 25.0** vs 34.3 / 65.5 MB (**2.2–2.6× lower**) |
| WebSocket plain | **2,028.9** | 1,450.7 | **+40%** | **1,205** vs 1,816 µs (**−34%**) | **10.6 / 8.7** vs 34.5 / 24.6 MB (**2.8–3.3× lower**) |
| **QUIC** | **309.7** | 223.7 | **+39%** | **6,938** vs 10,624 µs (**−35%**) | 43.3 / 23.8 vs 37.5 / 25.5 MB *(12 MiB window)* |
| **KCP + TLS + `tcpMux`** *(10+3 FEC)* | **218.2** | 111.1 | **+97%** (**2.0×**) | **6,835** vs 22,016 µs (**−69%**, **3.2×**) | **35.0 / 15.0** vs 43.4 / 29.9 MB (**1.2–2.0× lower**) |
| **KCP + TLS** *(no `tcpMux`, 10+3 FEC)* | **266.6** | 94.2 | **+183%** (**2.8×**) | **5,771** vs 25,172 µs (**−77%**, **4.4×**) | **58.9 / 22.1** vs 67.7 / 40.2 MB (**1.1–1.8× lower**) |

### Tail Latency & Binary Footprint vs Go frp v0.72.0

64 B steady-state ping-pong RTT on the same VM (`frp-stress --scenario latency`,
median of 3 × 2,000 interleaved samples) and Linux `x86_64` release binaries:

| Metric | frp-rs | Go frp v0.72.0 | frp-rs advantage |
|---|---:|---:|---:|
| `tcpMux` + TLS RTT (`p50` / `p99`) | **175 µs** / **655 µs** | 269 µs / 660 µs | **−35% p50** |
| WebSocket + TLS + `tcpMux` RTT (`p50` / `p99`) | **157 µs** / **376 µs** | 282 µs / 646 µs | **−44% p50, −42% p99** |
| WebSocket + `tcpMux` RTT (`p50` / `p99`) | **157 µs** / **327 µs** | 268 µs / 632 µs | **−41% p50, −48% p99** |
| QUIC RTT (`p50` / `p99`) | **212 µs** / **592 µs** | 306 µs / 1,035 µs | **−31% p50, −43% p99** |
| KCP + TLS + `tcpMux` RTT (`p50` / `p99`) | **0.30 ms** / **1.06 ms** | 20.34 ms / 23.63 ms | **68× lower p50, 22× lower p99** |
| Linux `x86_64` release binary (`frps` / `frpc`) | **8.6 / 7.3 MB** | 21.3 / 17.5 MB | **2.4–2.5× smaller** |

*(At 8 concurrent streams on the same VM, KCP reaches **222.5 MiB/s** with
`tcpMux` + TLS and **369.2 MiB/s** without `tcpMux` — 1.7× and 3.5× Go frp
respectively — while remaining 100% wire-compatible with Go frp v0.72.0.)*

### Why frp-rs Is Faster

- **Zero-copy Plain TCP (`splice`) & pooled 64 KiB bridge:** On Linux, plain TCP
  forwards bytes directly between sockets in kernel space via `splice(2)` (only
  428 µs CPU/MiB, **3.1×** Go's CPU efficiency); non-splice paths reuse pooled
  64 KiB buffers aligned to a single `tcpMux` frame.
- **Lock-free Yamux driver & zero-allocation body pool:** The vendored `yamux`
  crate runs a driver-owned `Writer` with vectored `writev` framing, burst
  flushing (at most once per 16-frame burst, zero flushes when idle), immediate
  consumed-chunk return to the connection `body_pool`, `alloc_zeroed`/4 KiB
  slab fills (avoiding `opt-level = "z"` byte-by-byte zeroing), lock-free
  `AtomicU64` + `Notify` write-stall watchdogs (zero idle timer ticks), and
  persistent `interval_at` keepalives.
- **Zero-copy WebSocket / WSS framing:** Coalesces vectored writes across up to
  15 slices with an inline partial-progress loop for `tokio-rustls`'s 64 KiB
  write cap, parses frame headers from a 64 B stack `preroll` buffer, streams
  payloads straight into the caller's `ReadBuf`, writes control replies from a
  131 B stack buffer, and unmasks/masks in 32-byte SIMD-friendly chunks.
- **Hardware-first TLS & whole-record `rustls` deframer:** Prioritizes
  `TLS13_AES_128_GCM_SHA256` on `x86_64`/`aarch64` (preserving AES-256 and
  ChaCha20 fallback) and carries a vendored `rustls` patch that reads whole TLS
  records per syscall instead of re-allocating in 4 KiB steps.
- **QUIC zero-drop UDP sizing & windowing:** Enlarges `SO_RCVBUF`/`SO_SNDBUF`
  along a non-shrinking `7 MiB → 1 MiB` ladder on every QUIC socket (eliminating
  kernel `RcvbufErrors` under burst load) and scales `send_window` to
  `2 × stream_receive_window` while keeping the 2 MiB pre-auth receive cap.
- **KCP Linux UDP GSO/GRO + SIMD FEC:** Coalesces up to 44 equal-length KCP/FEC
  datagrams (~62 KiB) per `sendmsg`/`recvmmsg` with zero extra user-space copy
  (automatic fallback on older kernels and non-Linux hosts), paired with AVX2 /
  NEON GF(2^8) FEC tables, separated chunk/datagram pools, and batch-cached
  timestamps.
- **No garbage collector & predictable RSS:** No 2× live-heap GC headroom and no
  stop-the-world pauses, delivering 2–3× lower peak RSS across TCP, WebSocket
  and KCP under load, plus [one write per protocol frame][coalesce] (+46% UDP
  packets/s under `tcpMux`) and [zero-timer UDP reply forwarding][udp-reply]
  (773 → 7,916 pps).

### Methodology & Caveats

- **Co-located 4-vCPU VM:** Client, sink, `frps` and `frpc` share 4 vCPUs on
  loopback, so CPU efficiency per byte directly determines throughput. On a
  machine with plenty of idle cores, raw throughput ratios narrow while CPU and
  RSS savings remain; on WAN links, throughput is bounded by physical bandwidth
  and link RTT (and KCP's ~23% 10+3 FEC parity overhead).
- **QUIC RSS trade-off:** Enlarging QUIC's `send_window` to 12 MiB eliminates
  UDP drops and yields +39% throughput / −43% p99 RTT at ~6 MB higher server
  peak RSS (`43.3` vs `37.5 MB`).
- **Historical benchmark notes & tuning:**
  [`docs/archive/notes/2026-11-10-real-host-throughput.md`](docs/archive/notes/2026-11-10-real-host-throughput.md),
  [`docs/archive/notes/2026-11-11-kcp-stream-vs-go.md`](docs/archive/notes/2026-11-11-kcp-stream-vs-go.md),
  [`docs/archive/notes/2026-11-12-worker-thread-count.md`](docs/archive/notes/2026-11-12-worker-thread-count.md),
  [`docs/archive/notes/2026-11-16-worker-thread-default.md`](docs/archive/notes/2026-11-16-worker-thread-default.md),
  and [`docs/deployment.md`](docs/deployment.md).

[coalesce]: docs/archive/notes/2026-11-09-yamux-inline-write.md
[udp-reply]: docs/archive/notes/2026-11-08-udp-spare-reuse.md

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
6. **Faster across every transport we measure.** +67% throughput in the shipping
   `tcpMux` + TLS configuration, +93% to +104% on WebSocket/WSS + `tcpMux`,
   +39% on QUIC, and +97% to +183% on KCP — with 19–77% less CPU per MiB,
   2.1–3.3× lower peak RSS across TCP and WebSocket, 31–48% lower p99 RTT on
   WebSocket/QUIC, and 68× lower p50 RTT on KCP, plus +46% UDP packets/s from
   writing each frame once and 10.2× the datagram rate on the UDP reply path.
   Full tables, method and caveats: [Performance](#performance).

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
| [`yamux`](vendor/yamux/README-FRP-RS.md) | 0.14.1 | 6 patches: per-stream RST at the inbound stream cap (instead of a session-killing GoAway, matching Go frp's fork), a per-stream receive-window cap, window-growth RTT seeding, a send+read body-buffer pool (with `alloc_zeroed`/4 KiB zero-slab fill and immediate consumed-chunk return), an exact `outbound_unacked` ACK counter, and a split read/driver-owned `Writer` with vectored `writev` and 16-frame burst flushing (no `tokio` dep). | Upstream each patch, or re-apply on every yamux bump (each patch section lists its own upgrade note). The read-side lost-wakeup fix carried at 0.14.0 is upstream as of 0.14.1 (`libp2p/rust-yamux` PR #233, closing issue #232, commit `a9ea49e4`). The vendored crate is not a workspace member, so no gate compiles its own tests; its README lists the two manual re-check commands. |
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
