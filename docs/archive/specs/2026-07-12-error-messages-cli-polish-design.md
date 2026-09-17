# Error Messages & CLI Polish — Design Spec

**Date:** 2026-07-12
**Status:** approved
**Approach:** Phase B (targeted top-5), then Phase A (comprehensive `Error` enum)

---

## Phase B: Targeted Top-5 Error Fixes

### Fix 1: Config Parse Errors with Context

**Files:** `frp-core/src/config.rs` (lines 917-930, 1522-1549)

**Current:** `load_server_config_from_str` / `load_client_config_from_str` propagate
raw `toml::from_str` and `serde_json::from_value` errors without file path or field
context. User sees `"invalid type: map, expected a sequence"` — no clue which file
or which field.

**Fix:** Wrap both deserialization steps with `.map_err()` that prepends config path:

```rust
let mut value: toml::Value = toml::from_str(content)
    .map_err(|e| format!("{path}: TOML parse error: {e}"))?;
// ...
let cfg: ServerConfig = serde_json::from_value(json_value)
    .map_err(|e| format!("{path}: config validation error: {e}"))?;
```

Also add file path to `strict_config` errors in `check_strict()`.

### Fix 2: Empty Token Security Gate

**Files:** `frp-core/src/auth.rs` (lines 124-130)

**Current:** When `token.is_empty() && method == Token`, logs `error!("CRITICAL:
token is empty...")` but returns `Ok`. Unauthenticated server if user misses the
log line.

**Fix:** Hard error. Remove the `return Ok` fallback:

```rust
if self.token.is_empty() && self.method == AuthMethod::Token {
    return Err("token must be set when auth.method='token'. \
                Set auth.token in config file or use --token CLI flag."
        .to_string());
}
```

Also verify `check_startup()` is called at every server start path. If not, add
it to `Service::new()` as a guard.

### Fix 3: Unknown Transport Hard Error

**Files:** `frp-client/src/service.rs` (lines 347-353)

**Current:** Unknown transport protocol logs a warning and silently falls back to
TCP. A typo like `protocol = "tpc"` connects successfully over wrong transport.

**Fix:** Return `Err` with valid variants listed:

```rust
let protocol: TransportProtocol = match self.cfg.transport_protocol.parse() {
    Ok(p) => p,
    Err(_) => {
        return Err(anyhow::anyhow!(
            "unknown transport protocol '{}'. Valid: tcp, kcp, quic, websocket",
            self.cfg.transport_protocol
        ));
    }
};
```

### Fix 4: Structured Exit Codes

**Files:** `frpc/src/main.rs`, `frps/src/main.rs`, `frp-core/src/lib.rs`

**Current:** All errors `process::exit(1)`. No way to distinguish config error
from connection error for health checks and supervisor scripts.

**Fix:** Define constants in `frp-core/src/lib.rs`:

```rust
pub const EXIT_RUNTIME: i32 = 1;   // connection lost, I/O error
pub const EXIT_CONFIG: i32 = 2;    // bad file, unknown field, invalid value
pub const EXIT_AUTH: i32 = 3;      // bad token, OIDC failure
pub const EXIT_BIND: i32 = 4;      // port in use, permission denied
```

Map error variants to codes in `main.rs`:
- Config loading errors → EXIT_CONFIG (2)
- Auth/login failures → EXIT_AUTH (3)
- Bind failures → EXIT_BIND (4)
- All other runtime errors → EXIT_RUNTIME (1)

### Fix 5: Unknown Field Suggestions

**Files:** `frp-core/src/config.rs` (lines 1522-1549)

**Current:** `check_strict()` says `"unknown field 'serverAddr'"` but never
suggests the correct name even though the known-keys set is available.

**Fix:** After detecting unknown key, compute Levenshtein distance against the
`known` set. If closest match ≤ 3 edits, append suggestion:

```
"unknown field 'serverAddr' — did you mean 'server_addr'?"
```

This catches Go frp camelCase→snake_case migrations: `serverAddr→server_addr`,
`bindPort→bind_port`, `authToken→auth_token`, etc.

---

## Phase A: Comprehensive Error Architecture

### New `Error` Enum

Replace current string-backed variants (`Protocol(String)`, `Transport(String)`,
`Auth(String)`, `Config(String)`, `Other(String)`) with proper thiserror variants
that preserve source chains and carry structured context:

```rust
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
```

Each sub-error is itself a `thiserror` enum with specific variants and exit codes.

### `.context()` Adoption

Add `anyhow` (already in workspace deps for frp-vnet) to frp-core for
user-facing paths. Use `.context("loading config from {path}")` instead of
`format!("prefix: {e}")` — preserves error chain, enables backtrace capture.

### Consistent `err_msg()` Policy

Extend the `err_msg()` helper to all proxy registration rejection paths. Define a
clear policy: when `detailed_errors_to_client` is false, ALL errors sent to the
client become a generic message. When true, the real error is sent.

### Validation at Config Load

- Response headers: validate against CRLF injection at config load time
- Bandwidth limits: validate ranges
- Port numbers: validate 1-65535 at config load, not at proxy registration

### Exit Code Mapping

| Error variant | Exit code |
|---|---|
| `Config` | 2 |
| `Auth` | 3 |
| `Io` (bind) | 4 |
| All others | 1 |

---

## CLI Ergonomics (Phase C — after errors)

### `frpc reload` Subcommand

New `FrpcCmd::Reload` variant. Sends HTTP POST to the frpc admin API at
`127.0.0.1:<admin_port>/api/reload`. Reads admin port from config file
(`web_server.port`) or `--admin-port` CLI flag. Prints result (success/failure
with error detail).

### `frpc status` Subcommand

New `FrpcCmd::Status` variant. Fetches `GET /api/status` from admin API, formats
as terminal table (proxy name, type, status, remote port, traffic). Falls back to
raw JSON if `--json` flag.

### `--log-level` on frpc

Add `log_level: Option<String>` to `FrpcRunArgs`. Wire into `resolve_log_settings()`.

### `--disable-log-color` on frpc

Add `disable_log_color: bool` to `FrpcRunArgs`. Wire into `init_logging()` with
`with_ansi(!disable_log_color)`.

---

## Implementation Order

1. Phase B fixes (1-2 days)
2. Phase A comprehensive error architecture (3-4 days)
3. Phase C CLI ergonomics (1-2 days)
4. Migration tooling (separate spec — tbd)

---

## Testing

- Each exit code fix: unit test that error type maps to correct code
- Config parse errors: integration test with deliberately broken TOML files
- Unknown field suggestions: unit test over common Go frp typos
- Empty token: integration test that server refuses to start
