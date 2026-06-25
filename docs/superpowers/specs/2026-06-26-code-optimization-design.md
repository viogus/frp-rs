# Code Optimization — Design Spec

**Goal:** Clean up debug leftovers, fix panic risks, optimize log output, split oversized files.

**Scope:** All crates. No behavior changes. clippy + test clean throughout.

---

## 1. Immediate Fixes

### 1.1 cipher_stream.rs: Remove `eprintln!` debug prints

5 `eprintln!` calls at lines 237, 252, 295, 296, 307 leak hex dumps to stderr.
These are test/debug artifacts, never removed.

**Fix:** Wrap in `#[cfg(test)]` blocks. Keep the hex dump logic as doc examples
or convert to `trace!` macro calls.

```rust
// Before:
eprintln!("Key: {}", hex::encode(key));

// After:
#[cfg(test)]
eprintln!("Key: {}", hex::encode(key));
// OR: tracing::trace!("Key: {}", hex::encode(key));
```

**Decision:** Convert to `trace!` — allows runtime enable via `RUST_LOG=trace`.

### 1.2 control.rs: Replace `unreachable!` with graceful handling

Two occurrences in `frp-server/src/control.rs`:
- Line 490: `IoStream::Cipher(_) => unreachable!("Cipher stream not used on server")`
- Line 584: same pattern in `assign_work_to_proxy`

One in `frp-client/src/control.rs`:
- Line 99: `_ => unreachable!("propose_mux only true for plain TCP")`

**Fix:**
```rust
IoStream::Cipher(_) => {
    warn!("Cipher stream unexpected in this context");
    return;
}
```

### 1.3 config.rs: Remove stale TODO

Line 323: `/// Extra params for token endpoint (TODO: wire into OidcClient).`
Already wired in OIDC auth implementation. Remove the TODO comment.

---

## 2. Log Output Audit

Current distribution: 99 warn!, 61 info!, 57 debug!, 17 error!

### 2.1 Downgrade non-actionable warns to debug

Pattern: connection resets, timeouts, peer disconnects are normal network
behavior — not actionable warnings. Audit each `warn!` call:

**Rules:**
- Keep `warn!`: auth failures, config errors, resource exhaustion, proxy not found
- Downgrade to `debug!`: connection reset, timeout, peer disconnect, idle cleanup
- Upgrade to `error!`: data corruption, internal state inconsistency

### 2.2 Audit debug! for sensitive data

57 `debug!` calls — check that none leak:
- auth tokens / privilege_key
- secret keys (sk)
- JWT tokens
- full hex dumps of encrypted frames

**Fix:** Mask sensitive fields: `token[..8]..` or `"***"` instead of full value.

### 2.3 Add trace! for raw protocol frames

`protocol.rs:25`: `tracing::debug!` logs full frame hex dump. Move to `trace!`
so it's only enabled for deep debugging.

---

## 3. File Splits

### 3.1 frp-server/src/control.rs (872 lines)

**Split into:**
```
frp-server/src/control/
├── mod.rs           (~450L)  handle_control, select loop, ping, message dispatch
├── proxy_ops.rs      (~250L)  handle_new_proxy, listen_and_proxy, run_udp_listener
├── bridge.rs         (~170L)  assign_work_to_proxy
```

**Boundaries:**
- `mod.rs`: imports, constants, `handle_control`, select loop, InternalMsg dispatch
- `proxy_ops.rs`: `handle_new_proxy`, `listen_and_proxy`, `run_udp_listener`, `unregister_control`
- `bridge.rs`: `assign_work_to_proxy`, `PendingRequest`, `PENDING_REQUEST_TIMEOUT`

All functions remain `pub(crate)`. No public API change.

### 3.2 frp-client/src/plugin.rs (1067 lines)

**Split into:**
```
frp-client/src/plugin/
├── mod.rs           (~60L)   PluginHandle, PluginConfig re-exports, shared helpers
├── http.rs          (~320L)  start_http_proxy, handle_http_proxy_conn, HttpProxyAuth
├── socks5.rs        (~380L)  start_socks5_proxy, handle_socks5_conn, parse_socks5_*
├── static_file.rs   (~310L)  start_static_file_proxy, handle_static_file_conn
```

**Boundaries:**
- `mod.rs`: `PluginHandle` struct + `Drop`, `base64_decode`, `split_host_port` (shared utils)
- Each plugin type gets its own file with `pub(crate)` factory and handler functions
- Tests split alongside: `#[cfg(test)] mod tests` in each file

### 3.3 frp-client/src/service.rs (892 lines, optional)

Borderline. If split:
```
frp-client/src/
├── service.rs       (~700L)  Service, run(), message loop
├── visitor.rs       (~200L)  run_visitor_listener, create_visitor_conn_msg
```

Decision: split only if >900 lines after XTCP implementation adds ~180 lines.

---

## 4. Dead Code Removal

### 4.1 KCP placeholder
`frp-core/src/kcp.rs` (333L): `KcpStream` struct is empty shell. Never instantiated.
Check `transport.rs` for `IoStream::Kcp` variant — if arm just logs warning,
the entire KCP module is dead weight.

**Action:** Remove `kcp.rs`, `IoStream::Kcp` variant, and match arms.
Keep the `#[cfg(feature = "kcp")]` pattern if preferred for future revival.

### 4.2 QUIC placeholder
`frp-core/src/quic.rs` (182L): same analysis as KCP.

### 4.3 bandwidth.rs (133L)
`BandwidthLimiter` struct and `limiter.rs` — check if actually wired anywhere.
If not, remove or `#[allow(dead_code)]` with comment explaining future use.

---

## 5. Testing & Verification

| Check | Command | Expected |
|-------|---------|----------|
| Compile | `cargo build` | clean |
| Tests | `cargo test --workspace` | all pass |
| Clippy | `cargo clippy --workspace` | no warnings |
| No eprintln in src | `grep -r 'eprintln!' --include='*.rs' frp-*/src/` | 0 matches |
| No unreachable | `grep -r 'unreachable!' --include='*.rs' frp-*/src/` | 0 matches |

---

## 6. Files Summary

| File | Action | Lines |
|------|--------|-------|
| `frp-core/src/cipher_stream.rs` | Modify | ~10 (eprintln → trace) |
| `frp-core/src/config.rs` | Modify | ~1 (remove TODO) |
| `frp-core/src/protocol.rs` | Modify | ~1 (debug → trace) |
| `frp-server/src/control/mod.rs` | Create | ~450 |
| `frp-server/src/control/proxy_ops.rs` | Create | ~250 |
| `frp-server/src/control/bridge.rs` | Create | ~170 |
| `frp-server/src/control.rs` | Delete | -872 |
| `frp-server/src/lib.rs` | Modify | ~1 (mod control → directory) |
| `frp-client/src/plugin/mod.rs` | Create | ~60 |
| `frp-client/src/plugin/http.rs` | Create | ~320 |
| `frp-client/src/plugin/socks5.rs` | Create | ~380 |
| `frp-client/src/plugin/static_file.rs` | Create | ~310 |
| `frp-client/src/plugin.rs` | Delete | -1067 |
| `frp-client/src/lib.rs` | Modify | ~1 |
| Log audit passes | Various | ~20 diff |
| **Total** | | **~250 net new (mostly moved)** |
