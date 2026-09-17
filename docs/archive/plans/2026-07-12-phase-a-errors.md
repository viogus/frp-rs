# Phase A: Comprehensive Error Architecture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace flat `Error::Variant(String)` with structured `thiserror` sub-enums that preserve source chains (`#[source]`), extend `err_msg()` policy to all proxy rejection paths, and add config-load validation for headers/ports/bandwidth.

**Architecture:** Three new sub-error enums in `frp-core/src/lib.rs` — `ProtocolError`, `TransportError`, `AuthError`, `ConfigError` — each with specific variants + an `Other(String)` catch-all for the long tail. The parent `Error` enum maps each sub-error via `#[error(transparent)]` or explicit `#[error]`. `exit_code()` already maps correctly from Phase B. Call sites update from `Error::Protocol(format!(...))` to `Error::Protocol(ProtocolError::SpecificVariant { ... })`.

**Tech Stack:** Rust, thiserror, serde_json, anyhow

## Global Constraints

- No new crate dependencies (thiserror already in tree, anyhow already in workspace)
- Exit codes unchanged: 1=runtime, 2=config, 3=auth, 4=bind
- Phase B improvements preserved (config path context, exit codes, field suggestions)
- All existing tests pass: 412 workspace tests
- Compat tests: 57 passed, 0 failed

---

### Task 1: Define sub-error enums and update parent Error

**Files:**
- Modify: `frp-core/src/lib.rs:35-71` (Error enum + surrounding area)

Add four sub-error enums above the existing `Error` enum, then update `Error` to use them:

```rust
// ── Sub-error types with structured context ──────────────────────────

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("invalid V1 message length {length}, raw header: {header}")]
    InvalidV1Length { length: u64, header: String },
    #[error("V1 frame too large: {length} (max {max})")]
    V1FrameTooLarge { length: u64, max: u64 },
    #[error("V2 frame payload too large: {payload_len}")]
    V2PayloadTooLarge { payload_len: usize },
    #[error("read V1 payload: {source}")]
    ReadV1Payload { #[source] source: std::io::Error },
    #[error("read V2 payload: {source}")]
    ReadV2Payload { #[source] source: std::io::Error },
    #[error("deserialize {msg_type} (v1): {source}")]
    DeserializeV1 { msg_type: &'static str, #[source] source: serde_json::Error },
    #[error("deserialize {msg_type} (v2): {source}")]
    DeserializeV2 { msg_type: &'static str, #[source] source: serde_json::Error },
    #[error("write V1 frame: {source}")]
    WriteV1Frame { #[source] source: std::io::Error },
    #[error("write V2 frame: {source}")]
    WriteV2Frame { #[source] source: std::io::Error },
    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("TCP connect to {addr}: {source}")]
    TcpConnect { addr: String, #[source] source: std::io::Error },
    #[error("TLS handshake: {source}")]
    TlsHandshake { #[source] source: std::io::Error },
    #[error("KCP: {source}")]
    Kcp(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("QUIC: {source}")]
    Quic(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("WebSocket: {source}")]
    WebSocket(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("timestamp required for authentication")]
    TimestampRequired,
    #[error("timestamp outside acceptable window")]
    TimestampOutsideWindow,
    #[error("invalid authentication token")]
    InvalidToken,
    #[error("OIDC auth requires server-side verifier (not configured)")]
    OidcNotConfigured,
    #[error("authentication token must not be empty with token auth method")]
    EmptyToken,
    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Parse(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Other(String),
}

// ── Parent Error ────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum Error {
    #[error("protocol error: {0}")]
    Protocol(#[source] ProtocolError),
    #[error("transport error: {0}")]
    Transport(#[source] TransportError),
    #[error("auth error: {0}")]
    Auth(#[source] AuthError),
    #[error("config error: {0}")]
    Config(#[source] ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => EXIT_CONFIG,
            Error::Auth(_) => EXIT_AUTH,
            Error::Io(e) if e.kind() == std::io::ErrorKind::AddrInUse
                || e.kind() == std::io::ErrorKind::PermissionDenied => EXIT_BIND,
            _ => EXIT_RUNTIME,
        }
    }
}
```

Keep `pub const EXIT_RUNTIME`, `EXIT_CONFIG`, `EXIT_AUTH`, `EXIT_BIND` unchanged.

- Build check: `cargo build -p frp-core` — WILL FAIL (all call sites need updating). This is expected — Task 2 updates call sites.

### Task 2: Update all Error call sites

**Files:** ~17 files, ~102 call sites across frp-core, frp-server, frp-client

Migration rules:
- `Error::Protocol(format!("msg: {e}"))` → `Error::Protocol(ProtocolError::Other(format!("msg: {e}")))`
- `Error::Protocol(format!("read V1 payload: {e}"))` → `Error::Protocol(ProtocolError::ReadV1Payload { source: e })` where `e: io::Error`
- `Error::Protocol(format!("deserialize {t} (v1): {e}"))` → `Error::Protocol(ProtocolError::DeserializeV1 { msg_type: t, source: e })` where `e: serde_json::Error`
- `Error::Transport(format!("TLS connect: {e}"))` → `Error::Transport(TransportError::TlsHandshake { source: e })`
- `Error::Auth(format!("invalid authentication token"))` → `Error::Auth(AuthError::InvalidToken)`
- `Error::Config(format!(...))` → `Error::Config(ConfigError::Parse(format!(...)))`
- `Error::Other(msg)` → removed (drop the `Other` variant entirely — map to nearest sub-error)

Key files (by call count):
- `frp-core/src/protocol.rs` (~40 calls) — ProtocolError variants
- `frp-core/src/transport.rs` (~40 calls) — TransportError variants
- `frp-core/src/v2_handshake.rs` — Protocol/Transport
- `frp-server/src/control/mod.rs` — Protocol
- `frp-client/src/service.rs` — Protocol/Transport
- `frp-server/src/service.rs` — Transport/Config
- `frp-server/src/control/proxy_ops.rs` — Config

### Task 3: Consistent err_msg() policy

**Files:** `frp-server/src/control/proxy_ops.rs`

Extend `err_msg()` to all proxy registration rejection paths:
- `reject_new_proxy` calls currently pass raw error strings
- Apply `err_msg()` consistently: when `detailed_errors_to_client` is false, use generic message; when true, use real error

### Task 4: Config-load validation

**Files:** `frp-core/src/config.rs`

- Response headers (`ProxyConfig::response_headers`): validate no CR/LF in header names or values at deserialization time. Use `#[serde(deserialize_with)]` or a custom validator.
- Port numbers: add `#[validate(range(min = 1, max = 65535))]`-style checks (hand-rolled, no validator crate). Move port validation from `proxy_ops.rs` to config deserialization.
- Bandwidth limits: validate non-negative at parse time.

### Task 5: Integration verification

- `cargo build --workspace` — clean
- `cargo test --workspace` — all pass
- `cargo clippy --workspace` — no issues
- `bash scripts/compat-test.sh --ci` — 57/0
