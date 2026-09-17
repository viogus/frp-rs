# Tiny Binary Variants — Feature Gate Design

**Date**: 2026-06-28
**Status**: approved
**Scope**: frp-rs workspace — feature-gate optional protocols for `-tiny` binary variants

## Goal

Provide `frps-tiny` / `frpc-tiny` binaries that drop heavyweight optional features
(KCP, QUIC, WebSocket, SSH, OIDC, metrics/dashboard) while preserving core frp
functionality: TCP + TLS + TcpMux + STCP/XTCP + all proxy types + compression + V2.

Default `frps` / `frpc` unchanged — all features included. Tiny variants built
with `--no-default-features`.

## Features

### frp-core features

| Feature | Dep gated | What it controls |
|---------|-----------|-----------------|
| `quic` | `dep:quinn` | QUIC transport (QuicListener, QuicStream, QuicConnection) |
| `kcp` | `dep:kcp` | KCP transport (KcpListener, KcpStream) |
| `websocket` | `dep:tokio-tungstenite` | WebSocket transport (IoStream::WebSocket, WsByteStream, accept/dial) |
| `oidc` | `dep:jsonwebtoken` | OIDC token verification (OidcVerifier, OidcClient) |

Default: `["quic", "kcp", "websocket", "oidc"]`

### frp-server features

| Feature | Dep gated | What it controls |
|---------|-----------|-----------------|
| `ssh` | `dep:russh` | SSH gateway (ssh_gateway module, SshListener) |
| `dashboard` | `dep:prometheus` | Metrics + dashboard (dashboard module, prometheus registry) |

Default: `["ssh", "dashboard"]`

### frp-client features

No extra features. Inherits `frp-core` features via `frp-core = { workspace = true }`.

### frps / frpc features

| Feature | What it enables |
|---------|----------------|
| `full` (default) | `frp-server/default` or `frp-client/default` — all protocols |

## Binary Targets

### frps

```toml
[[bin]]
name = "frps"
path = "src/main.rs"
required-features = ["default"]

[[bin]]
name = "frps-tiny"
path = "src/main.rs"
required-features = []
```

### frpc

```toml
[[bin]]
name = "frpc"
path = "src/main.rs"
required-features = ["default"]

[[bin]]
name = "frpc-tiny"
path = "src/main.rs"
required-features = []
```

## Build Commands

```bash
# Full (default)
cargo build --release -p frps -p frpc

# Tiny
cargo build --release -p frps --no-default-features -p frpc --no-default-features
```

## Code Changes — Gate Maps

### Transport Protocol enum (transport.rs)

```rust
pub enum TransportProtocol {
    Tcp,
    Tls,
    #[cfg(feature = "kcp")]
    Kcp,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "websocket")]
    WebSocket,
    Wss, // WSS uses WebSocket internally → gated with websocket
    TcpMux,
}
```

### IoStream enum (transport.rs)

```rust
pub enum IoStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    #[cfg(feature = "kcp")]
    Kcp(KcpStream),
    #[cfg(feature = "quic")]
    Quic(QuicStream),
    #[cfg(feature = "websocket")]
    WebSocket(WsByteStream),
    Yamux(YamuxStream),
    Cipher(CipherStream<Box<dyn AsyncReadWrite>>),
    Aead(AeadStream<Box<dyn AsyncReadWrite>>),
    SshChannel(Box<dyn AsyncReadWrite>),
}
```

### Config fields (config.rs)

```rust
pub struct ServerConfig {
    // ...
    #[cfg(feature = "quic")]
    #[serde(default)]
    pub quic_bind_port: u16,
    // kcp_bind_port, ws_bind_addr etc. — each gated by its feature
}
```

### Module declarations (lib.rs)

```rust
// frp-core/src/lib.rs
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "kcp")]
pub mod kcp;

// frp-server/src/lib.rs
#[cfg(feature = "ssh")]
pub mod ssh_gateway;
#[cfg(feature = "dashboard")]
pub mod dashboard;
```

### Server service startup (service.rs)

Each listener startup block gated:
```rust
#[cfg(feature = "kcp")]
{
    // KCP listener bind + accept loop
}
#[cfg(feature = "quic")]
{
    // QUIC listener bind + accept loop
}
#[cfg(feature = "websocket")]
{
    // WebSocket listener setup
}
#[cfg(feature = "ssh")]
{
    // SSH listener setup
}
#[cfg(feature = "dashboard")]
{
    // Dashboard + metrics setup
}
```

### Auth OIDC (auth.rs)

All OIDC functions (`OidcVerifier`, `OidcClient`, `OidcConfig`) gated with `#[cfg(feature = "oidc")]`.
Usage sites in `service.rs` also gated.

### Client control.rs + service.rs

QuicConnection, dial_quic() calls, TransportProtocol match arms — each gated.

## What stays (no gate)

| Component | Reason |
|-----------|--------|
| TCP (TcpStream) | Core transport |
| TLS (rustls) | Essential security |
| AES-128-CFB encryption | Go frp compat |
| Snappy compression | Data plane compression |
| STCP / XTCP | Core NAT traversal |
| All proxy types (TCP, UDP, HTTP, HTTPS, STCP, XTCP, SOCKS5) | Core functionality |
| V1 / V2 protocol | Wire protocol |
| PBKDF2-SHA1 key derivation | Go frp compat |
| MD5 auth token | Go frp compat |

## What's gated (post-v0.3.2)

| Component | Feature | When gated |
|-----------|---------|------------|
| TcpMux (yamux) | `tcp-mux` | PR #98 — ~80KB, default ON, micro OFF |

## Estimated Size Impact

| Binary | Full (macOS ARM64) | Tiny | Micro |
|--------|---------------------|------|-------|
| frps | 4.8 MB | 2.7 MB | 1.6 MB |
| frpc | 3.7 MB | 2.3 MB | 1.7 MB |

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| IoStream enum match arms missing cfg gates | Compiler catches — exhaustive match on non-exhaustive enum |
| Config deserialization fails on unknown fields | `#[serde(default)]` + `#[cfg]` ensures fields silently ignored when feature off |
| yamux uses `use crate::quic::QuicStream` | Already refactored to use IoStream; no direct quic dep from yamux |
| WebSocket gating affects main accept loop | Gate only WebSocket-specific branches; TCP/TLS path unchanged |
| SSH gateway tests | Gate entire test module with `#[cfg(feature = "ssh")]` |

## Tests

- Full variant: all 213 tests pass (unchanged)
- Tiny variant: exclude gated test modules; core tests pass
- Compat tests: not affected (compat test script uses release `frps`/`frpc` which are full)

## Rollback

Each feature is an independent Cargo feature flag. Remove `required-features` from
`[[bin]]` entry to delete tiny variant. Features are default-on — removing a feature
from `default` list disables it permanently.

Git: all changes on `worktree-dep-consolidation` branch, same as the dependency
consolidation work.
