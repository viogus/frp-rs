# PR #172 Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix code quality issues and document breaking config changes from PR #172 (Go frp v0.70.1 compatibility audit).

**Architecture:** Two independent tasks: (1) simplify stun.rs parse_error_response API — dead Ok branch + unreachable!(), (2) document all breaking config default changes in CHANGELOG with migration notes.

**Tech Stack:** Rust, frp-rs codebase conventions.

## Global Constraints

- PR branch: `worktree-go-frp-v0701-audit` (already open as #172)
- Worktree required before file modification (EnterWorktree)
- All changes commit to the PR branch
- `cargo clippy --workspace --all-targets --all-features -D warnings` must pass
- `cargo test --workspace --all-features` must pass (485 passed, 2 ignored baseline)
- `cargo fmt --all -- --check` must pass
- No new dependencies
- Commit message format: `fix: <description>` or `docs: <description>`

---

### Task 1: Simplify parse_error_response API (dead code removal)

**Files:**
- Modify: `frp-core/src/stun.rs`

**Interfaces:**
- Consumes: `parse_error_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<String, String>` (currently always returns Err, never Ok)
- Produces: `parse_error_response(data: &[u8], expected_tx_id: &[u8; 12]) -> String`

**Context:** PR #172 added STUN error response parsing. `parse_error_response` returns `Result<String, String>` but every code path returns `Err(...)`. The `Ok` variant is dead. Call sites match on the result and `unreachable!()` the Ok arm. This is a misleading API — change it to return `String` directly.

- [ ] **Step 1: Change parse_error_response return type from `Result<String, String>` to `String`**

In `frp-core/src/stun.rs`, change the function signature and all `return Err(...)` to `return ...`:

```rust
// BEFORE (line 347):
fn parse_error_response(data: &[u8], expected_tx_id: &[u8; 12]) -> Result<String, String> {
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err("STUN error message truncated".into());
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(format!(
            "STUN error response: bad magic cookie: 0x{cookie:08x}"
        ));
    }

    if data[8..20] != *expected_tx_id {
        return Err("STUN error response: transaction ID mismatch".into());
    }

    // ... attribute parsing loop ...

    Err("STUN error response (no ERROR-CODE attribute)".into())
}

// AFTER:
fn parse_error_response(data: &[u8], expected_tx_id: &[u8; 12]) -> String {
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return "STUN error message truncated".into();
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return format!(
            "STUN error response: bad magic cookie: 0x{cookie:08x}"
        );
    }

    if data[8..20] != *expected_tx_id {
        return "STUN error response: transaction ID mismatch".into();
    }

    // ... attribute parsing loop — return Err(...) becomes return ... ...

    "STUN error response (no ERROR-CODE attribute)".into()
}
```

All `return Err(...)` in the function become `return ...` (drop the `Err` wrapper). The final `Err("...".into())` becomes `"...".into()`.

- [ ] **Step 2: Update call sites — remove `unreachable!()` and unwrap Err**

Two call sites in the same file need updating.

**Call site 1** — `parse_binding_response` (line ~220):

```rust
// BEFORE:
        0x0111 => match parse_error_response(data, expected_tx_id) {
            Err(e) => return Err(e),
            Ok(_) => unreachable!(),
        },

// AFTER:
        0x0111 => return Err(parse_error_response(data, expected_tx_id)),
```

**Call site 2** — `parse_binding_response_full` (line ~279):

```rust
// BEFORE:
        0x0111 => match parse_error_response(data, expected_tx_id) {
            Err(e) => return Err(e),
            Ok(_) => unreachable!(),
        },

// AFTER:
        0x0111 => return Err(parse_error_response(data, expected_tx_id)),
```

- [ ] **Step 3: Update doc comment**

Change the doc comment on `parse_error_response`:

```rust
// BEFORE:
/// Parse a STUN Binding Error Response (type 0x0111) and return a
/// human-readable error string including the error code and reason phrase.

// AFTER:
/// Parse a STUN Binding Error Response (type 0x0111).
/// Returns a human-readable error string including the error code and reason phrase.
```

- [ ] **Step 4: Build and test**

```bash
cargo build -p frp-core
cargo test -p frp-core -- stun
cargo clippy --workspace --all-targets --all-features -D warnings
cargo fmt --all -- --check
```

Expected: build passes, all stun tests pass (19 tests including the new IPv6 + CHANGED-ADDRESS tests), clippy zero warnings, fmt clean.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/stun.rs
git commit -m "fix: simplify parse_error_response return type (dead Ok branch)

parse_error_response always returns Err — changing return type from
Result<String, String> to String removes the dead Ok variant and the
unreachable!() at both call sites."
```

---

### Task 2: Document breaking config default changes in CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

**Context:** PR #172 changes several config defaults to match Go frp v0.70.1 behavior. These are breaking changes for existing frp-rs configs that relied on the old defaults. Each change needs a clear entry in CHANGELOG under an "Upgrade Notes" section.

The breaking default changes are:

| Field | Old Default | New Default | Reason |
|-------|------------|------------|--------|
| `tls_enable` (client) | `false` | `true` | Go frp v0.70.1 compat |
| `disable_custom_tls_first_byte` (client) | `false` | `true` | Go frp v0.70.1 compat |
| `tcp_mux` (client) | feature-gated (`cfg!(feature = "tcp-mux")`) | `true` | Go frp v0.70.1 compat |
| `nat_hole_stun_server` (client) | `""` (empty) | `"stun.easyvoip.com:3478"` | Go frp v0.70.1 compat |
| `max_ports_per_client` (server) | `50` | `0` (unlimited) | Go frp v0.70.1 compat |
| `authentication_timeout` (server auth) | `15` | `0` | Go frp v0.70.1 compat |
| `graceful_timeout` | `15` | `0` | Go frp v0.70.1 compat |
| `parse_bandwidth_limit` parsing | accepted bare `"500"`, `"500K"` | requires `"KB"/"MB"/"GB"` suffix | Go frp v0.70.1 compat |
| `parse_bandwidth_limit` empty string | returned `None` | returns `Some(0)` | Go frp v0.70.1 compat |
| `web_server.addr` (server) | `""` (all interfaces) | `"127.0.0.1"` (localhost only) | Security: Go frp v0.70.1 compat |
| `local_ip` (proxy) | `""` (empty) | `"127.0.0.1"` | Go frp v0.70.1 compat |
| `tcp_mux_keepalive_interval` (client) | not configurable | `30` (new field) | Go frp v0.70.1 compat |
| `heartbeat_timeout` (client) | not configurable | `90` (new field, -1 when tcp_mux) | Go frp v0.70.1 compat |

- [ ] **Step 1: Add "Upgrade Notes" section to CHANGELOG**

Add a new section at the top of CHANGELOG.md (after the title, before the release entries). The section documents all breaking config default changes with migration guidance for each:

```markdown
## Upgrade Notes: v0.7.0 → v0.7.1 (Go frp v0.70.1 compat)

This release changes several config defaults to match Go frp v0.70.1 behavior.
Existing configs that relied on previous defaults may need updating.

### Client defaults changed

- **`tls_enable`**: changed from `false` to `true`. If your frps does not
  have TLS configured, set `tls_enable = false` explicitly in frpc.toml.
- **`disable_custom_tls_first_byte`**: changed from `false` to `true`.
  Go frp v0.70.1 no longer sends the FRPTLSHeadByte before TLS handshake.
  If connecting to older frps (< v0.70.1), set this to `false`.
- **`tcp_mux`**: changed from feature-gated (`--features tcp-mux`) to
  always-on (`true`). If you do not want yamux multiplexing, set
  `tcp_mux = false` explicitly. When `tcp_mux` is enabled, heartbeats
  are disabled automatically (yamux provides keepalive).
- **`nat_hole_stun_server`**: changed from empty (`""`) to
  `"stun.easyvoip.com:3478"`. If you need a different STUN server,
  set it explicitly.
- **`tcp_mux_keepalive_interval`**: new field, defaults to `30`
  (seconds). Controls yamux keepalive ping interval.
- **`heartbeat_timeout`**: new field, defaults to `90` (seconds).
  Set to `-1` when `tcp_mux = true` (yamux provides keepalive).

### Server defaults changed

- **`max_ports_per_client`**: changed from `50` to `0` (unlimited).
  To restore the old limit, set `max_ports_per_client = 50`.
- **`auth.authentication_timeout`**: changed from `15` to `0`.
- **`graceful_timeout`**: changed from `15` to `0`.
- **`web_server.addr`**: changed from `""` (bind all interfaces) to
  `"127.0.0.1"` (localhost only). This is a security hardening change.
  If the dashboard/admin API must be reachable from remote hosts, set
  `web_server.addr = "0.0.0.0"`.

### Proxy defaults changed

- **`local_ip`**: changed from `""` (empty) to `"127.0.0.1"`.
  If your local service binds a different address, set `local_ip`
  explicitly.

### Bandwidth limit parsing tightened

The `bandwidth_limit` field now requires a "KB", "MB", or "GB" suffix
(case-insensitive). Bare numbers (e.g., `"500"`) and single-letter
suffixes (e.g., `"500K"`) are rejected. Update your config to use
the full suffix: `"500KB"`, `"10MB"`, `"1GB"`.

Empty `bandwidth_limit` now means "no limit" (previously was treated
as "not set"). This matches Go frp behavior.
```

- [ ] **Step 2: Verify CHANGELOG formatting**

```bash
head -80 CHANGELOG.md
```

Expected: "Upgrade Notes" section appears after the title, before the first release entry. All 13 default changes documented with migration guidance.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add upgrade notes for Go frp v0.70.1 config default changes

Document all breaking config default changes from PR #172, including
tls_enable, tcp_mux, bandwidth limit parsing, server limits, and
security-hardened web_server.addr default."
```

---

### Review Findings Disposition

These findings from the PR #172 review were verified and determined to be false positives or not requiring code changes:

| Finding | Disposition |
|---------|------------|
| stun.rs potential bounds panic at `data[8..20]` | **False.** The `data.len() < 20 + msg_len` check at line 351 guarantees `data.len() >= 20` before the tx_id slice at line 362. |
| InternalMsg::Shutdown variant change needs audit | **Verified complete.** Only 2 sites reference Shutdown: `login.rs` (send) and `dispatch.rs` (match). Both use the new `{ done }` format. |
| sk_index empty-string key insertion | **False.** The `needs_sk_index` guard already checks `!s.is_empty()` before `np.sk.clone().unwrap_or_default()`. The `unwrap_or_default()` is dead code (sk is non-empty at that point) but not a bug. |
| tls_enable default change silently breaks configs | **Addressed.** Documented in Task 2 CHANGELOG upgrade notes with explicit migration guidance. |
| parse_bandwidth_limit rejects bare numbers | **Addressed.** Documented in Task 2 CHANGELOG upgrade notes. |
| HTTP health check `Connection: close` | **No-op.** HTTP/1.1 with explicit `Connection: close` is valid and harmless for health checks. Not worth changing. |
| build_tls_connector_skip_verify naming | **No-op.** The name accurately describes the default behavior (skip verification). When ca_file is provided, verification against that custom root store is the override. |
| proxy_ops.rs is_tcp_group only matches "tcp" | **No-op.** Go frp also only creates group listeners for "tcp" proxy type. "tcpmux" groups are not supported in Go frp. |
| proxy.rs pool_indices fallback allocates on every call | **No-op.** Only allocates when ALL backends are unhealthy (degraded state). Healthy-path zero-alloc. Not worth optimizing. |
| service.rs heartbeat 1s sleep wakeup | **No-op.** The `select!` branch `if hb_timeout > 0` gates the sleep — when tcp_mux disables heartbeat (hb_timeout = -1), the branch is inactive. When active, 1s granularity for 90s timeout is negligible overhead. |
