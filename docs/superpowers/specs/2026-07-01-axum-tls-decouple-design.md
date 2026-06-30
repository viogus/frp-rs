# Decouple axum from frp-core TLS Feature

**Issue:** [#50](https://github.com/viogus/frp-rs/issues/50)
**Date:** 2026-07-01
**Status:** Design approved, transitioning to implementation

## Problem

`frp-core` `tls` feature pulls `axum` (~400KB HTTP framework) for `TlsListener` (implements `axum::serve::Listener`) and `admin_auth.rs` (axum middleware). This infects binaries that need TLS but not HTTP serving:

| Binary | TLS needed | axum needed | axum status |
|--------|-----------|-------------|-------------|
| frpc (full) | yes | yes (admin API) | used |
| **frpc-tiny** | yes | no | **wasted ~400KB** |
| **frpc-micro** | no | no | **wasted ~400KB** (hard dep in frp-client) |
| frps (full) | yes | yes (dashboard) | used |
| **frps-tiny** | yes | no | **wasted ~400KB** |
| frps-micro | no | no | ok |

Three binaries each waste ~400KB on an unused HTTP framework.

## Root Cause

Two design issues:

1. **`frp-core/tls` includes `dep:axum`**: `axum::serve::Listener` is only needed for `TlsListener` — a 60-line wrapper that belongs in consuming crates, not the core library.
2. **`frp-client` has axum as a hard dependency**: Even when admin API is disabled (`web_server.port = 0`), axum is compiled.

## Solution

Three independent changes:

### 1. Remove axum from frp-core/tls

```diff
# frp-core/Cargo.toml
- tls = ["dep:rustls", ..., "dep:axum"]
+ tls = ["dep:rustls", ...]
+ admin-auth = ["dep:axum"]    # new: gates admin_auth.rs only
```

`admin_auth.rs` gate changed from `#[cfg(feature = "tls")]` to `#[cfg(feature = "admin-auth")]`.

### 2. Move TlsListener to consumer crates

Remove `TlsListener` (60 lines) from `frp-core/src/transport.rs`. Each consumer implements it locally:

- `frp-server/src/dashboard.rs`: local `TlsListener` struct
- `frp-client/src/admin.rs`: local `TlsListener` struct

60 lines × 2 = 120 lines of intentional duplication. The struct implements `axum::serve::Listener` — a trait bound that should not live in frp-core.

### 3. Make axum optional in frp-client

```diff
# frp-client/Cargo.toml
- axum.workspace = true
+ axum = { workspace = true, optional = true }

  [features]
- default = ["tls", ..., "vnet"]
+ default = ["tls", ..., "vnet", "admin"]
+ admin = ["dep:axum"]
```

Gate `admin.rs` module and its call site in `service.rs` behind `#[cfg(feature = "admin")]`.

## Files Changed

| File | Change |
|------|--------|
| `frp-core/Cargo.toml` | Split `tls` feature: remove `dep:axum`, add `admin-auth` |
| `frp-core/src/transport.rs` | Remove `TlsListener` (lines 1993-2062) |
| `frp-core/src/admin_auth.rs` | Gate: `tls` → `admin-auth` |
| `frp-server/Cargo.toml` | `dashboard` adds `frp-core/admin-auth` |
| `frp-server/src/dashboard.rs` | Add local `TlsListener`, use `frp_core::admin_auth` |
| `frp-client/Cargo.toml` | axum optional + `admin` feature |
| `frp-client/src/admin.rs` | Gate: `#[cfg(feature = "admin")]` |
| `frp-client/src/service.rs` | Gate admin server start: `#[cfg(feature = "admin")]` |
| `frp-client/src/lib.rs` | Gate admin mod re-export |

## Expected Savings

| Binary | Before | After | Delta |
|--------|--------|-------|-------|
| frpc-tiny | ~2.6 MB | ~2.2 MB | **-400KB** |
| frpc-micro | ~1.9 MB | ~1.5 MB | **-400KB** |
| frps-tiny | ~2.8 MB | ~2.4 MB | **-400KB** |

## Compatibility

- Full builds (frpc, frps): zero behavioral change
- Tiny/micro: lose admin HTTP API (was already compiled but unused — `web_server.port` defaults to 0)
- Compat tests: unaffected (no admin/dashboard in test matrix)
- No new dependencies, no dependency removals

## Out of Scope

- Removing axum entirely from any crate (needed by full builds)
- Changing admin API protocol or endpoints
- Dashboard/metrics changes
