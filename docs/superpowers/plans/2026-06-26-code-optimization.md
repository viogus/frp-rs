# Code Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up debug leftovers, fix panic risks, optimize log output, split oversized files. Zero behavior changes.

**Architecture:** Mechanical refactor with 4 phases: immediate fixes → log audit → file splits → dead code removal. Each phase is a self-contained task. File splits follow existing module patterns (`pub(crate)` visibility, `#[cfg(test)] mod tests` inline).

**Tech Stack:** Rust, tokio, tracing crate for logging.

---

### Task 1: Immediate Fixes — eprintln, unreachable, stale TODO

**Files:**
- Modify: `frp-core/src/cipher_stream.rs:237,252,295,296,307`
- Modify: `frp-server/src/control.rs:490,584`
- Modify: `frp-client/src/control.rs:99`
- Modify: `frp-core/src/config.rs:323`

Fix 5 `eprintln!` leaks, 3 `unreachable!` panics, 1 stale TODO comment.

- [ ] **Step 1: Fix cipher_stream.rs — eprintln! → trace!**

In `frp-core/src/cipher_stream.rs`, change 5 `eprintln!` calls to `tracing::trace!`:

```rust
// Line 237: change eprintln!("Key: {}", hex::encode(key));
// to:
tracing::trace!("Key: {}", hex::encode(key));

// Line 252: change eprintln!("Ciphertext: {}", hex::encode(&ciphertext));
// to:
tracing::trace!("Ciphertext: {}", hex::encode(&ciphertext));

// Line 295: change eprintln!("Original: {}", hex::encode(&v1_frame));
// to:
tracing::trace!("Original: {}", hex::encode(&v1_frame));

// Line 296: change eprintln!("Decrypted: {}", hex::encode(&decrypted));
// to:
tracing::trace!("Decrypted: {}", hex::encode(&decrypted));

// Line 307: change eprintln!("Ping decrypted: {}", hex::encode(&decrypted2));
// to:
tracing::trace!("Ping decrypted: {}", hex::encode(&decrypted2));
```

- [ ] **Step 2: Fix server control.rs — unreachable! → warn! + return**

In `frp-server/src/control.rs`, replace two `unreachable!` calls:

Line 490 — in `handle_control`, change:
```rust
IoStream::Cipher(_) => unreachable!("Cipher stream not used on server"),
```
to:
```rust
IoStream::Cipher(_) => {
    warn!("Cipher stream unexpected in server context");
    return;
}
```

Line 584 — in `assign_work_to_proxy`, same pattern — find the `unreachable!` and replace with:
```rust
IoStream::Cipher(_) => {
    warn!("Cipher stream unexpected in bridge context");
    return;
}
```

- [ ] **Step 3: Fix client control.rs — unreachable! → warn! + return**

In `frp-client/src/control.rs`, line 99, change:
```rust
_ => unreachable!("propose_mux only true for plain TCP"),
```
to:
```rust
other => {
    warn!("Unexpected transport for mux proposal: {:?}", other);
    return Ok(stream);
}
```

- [ ] **Step 4: Fix config.rs — remove stale TODO**

In `frp-core/src/config.rs`, line 323, change:
```rust
/// Extra params for token endpoint (TODO: wire into OidcClient).
```
to:
```rust
/// Extra params for token endpoint.
```

- [ ] **Step 5: Build and verify**

```bash
cargo build
grep -rn 'eprintln!' --include='*.rs' frp-core/src/ frp-server/src/ frp-client/src/
grep -rn 'unreachable!' --include='*.rs' frp-core/src/ frp-server/src/ frp-client/src/
```

Expected: compiles cleanly, 0 `eprintln!` matches, 0 `unreachable!` matches.

- [ ] **Step 6: Commit**

```bash
git add frp-core/src/cipher_stream.rs frp-server/src/control.rs frp-client/src/control.rs frp-core/src/config.rs
git commit -m "fix: remove eprintln debug leaks, replace unreachable with graceful handling"
```

---

### Task 2: Log Output Audit

**Files:**
- Modify: `frp-core/src/protocol.rs:25` (debug → trace for frame hex)
- Audit: all `warn!` calls across workspace (99 total)
- Audit: all `debug!` calls for sensitive data (57 total)

- [ ] **Step 1: Move frame hex dump to trace!**

In `frp-core/src/protocol.rs`, find the `tracing::debug!` at line ~25 that logs the full frame hex. Change `debug!` to `trace!`:

```rust
// Before:
tracing::debug!("read frame: type={}, len={}, payload={}", msg_type, len, hex::encode(&payload));

// After:
tracing::trace!("read frame: type={}, len={}, payload={}", msg_type, len, hex::encode(&payload));
```

- [ ] **Step 2: Audit warn! calls — downgrade non-actionable to debug!**

Rules:
- `warn!` → keep: auth failures, config errors, resource exhaustion, proxy not found
- `warn!` → `debug!`: connection reset, timeout, peer disconnect, idle cleanup

Run audit command:
```bash
grep -rn 'warn!(' frp-core/src/ frp-server/src/ frp-client/src/ --include='*.rs' | grep -v 'test'
```

Key files to check and changes to make:

**frp-server/src/service.rs** — find warns about "connection reset", "peer disconnect", change to `debug!`.
**frp-client/src/service.rs** — find warns about "bridge error", "dial failed", change to `debug!`.
**frp-server/src/control.rs** — find warns about "timed out", "gone away", change to `debug!` unless they are unrecoverable (keep `warn!` for "provider gone" on ReqWorkConn failures).

Exact changes (verify line numbers match):

In `frp-server/src/service.rs`:
```rust
// Connection-level errors → debug
warn!("read error from {}: {}", addr, e);  // → debug!
warn!("Failed to read first message from {}: {}", addr, e);  // → debug!
```

In `frp-client/src/service.rs`:
```rust
// Bridge close/drop → debug
warn!("Control read error: {}. Reconnecting...", e);  // keep warn (actionable)
```

In `frp-server/src/control.rs`:
```rust
// Pending request timeout → debug
warn!("Pending request for proxy '{}' timed out after {:?}", ...);  // → debug!
```

- [ ] **Step 3: Audit debug! calls for sensitive data**

Run check:
```bash
grep -rn 'debug!(".*token\|debug!(".*privilege_key\|debug!(".*sk\|debug!(".*secret_key' frp-core/src/ frp-server/src/ frp-client/src/ --include='*.rs'
```

If any match, mask value. Example fix:
```rust
// Before:
debug!("Login with privilege_key: {}", pk);
// After:
debug!("Login with privilege_key: {}...", &pk[..pk.len().min(8)]);
```

- [ ] **Step 4: Build and verify**

```bash
cargo build
cargo clippy --workspace
```

Expected: compiles cleanly, clippy clean.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/protocol.rs frp-server/src/service.rs frp-server/src/control.rs frp-client/src/service.rs
git commit -m "chore: log audit — downgrade warn→debug for conn events, mask sensitive data"
```

---

### Task 3: Split frp-server/src/control.rs into control/ module

**Files:**
- Create: `frp-server/src/control/mod.rs`
- Create: `frp-server/src/control/proxy_ops.rs`
- Create: `frp-server/src/control/bridge.rs`
- Delete: `frp-server/src/control.rs`

Split 872-line control.rs into 3 files by responsibility.

- [ ] **Step 1: Create directory and mod.rs (core loop)**

```bash
mkdir -p frp-server/src/control
```

Create `frp-server/src/control/mod.rs` with the core select loop and helpers:

```rust
//! Control connection handler for frp-server.
//!
//! Handles the lifecycle of a single client control connection:
//! login, proxy registration, message dispatch, work connection
//! management, and NAT hole punch coordination.

mod proxy_ops;
mod bridge;

pub(crate) use proxy_ops::{handle_new_proxy, listen_and_proxy, run_udp_listener, unregister_control};
pub(crate) use bridge::{assign_work_to_proxy, PendingRequest, PENDING_REQUEST_TIMEOUT};

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use crate::nat_hole::NatHoleCoordinator;
use crate::proxy::ProxyManager;
use crate::service::{AppState, InternalMsg};

const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_WORK_POOL_SIZE: usize = 16;

/// Handle a new control connection (after successful LoginResp).
///
/// Spawns proxy listeners, processes incoming messages and internal
/// events in a biased select loop (InternalMsg prioritized over
/// client messages to reduce proxy connection latency).
pub async fn handle_control<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<std::net::SocketAddr>,
    yamux_incoming: Option<mux::Incoming>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ... [full handle_control function from original control.rs, lines 43-460] ...
    // Move the entire handle_control function body here.
    // The proxy_ops and bridge functions are now in submodules,
    // called as proxy_ops::handle_new_proxy(...), bridge::assign_work_to_proxy(...), etc.
}
```

**IMPORTANT:** Copy the EXACT code from `frp-server/src/control.rs`. Do not rewrite — the plan shows structure only. The implementer must:
1. Copy the full `handle_control` function (lines 43-460)
2. Copy `PendingRequest`, `PENDING_REQUEST_TIMEOUT`, `HEARTBEAT_TIMEOUT`, `MAX_WORK_POOL_SIZE`
3. Change internal calls: `assign_work_to_proxy(...)` → `bridge::assign_work_to_proxy(...)`
4. Change internal calls: `handle_new_proxy(...)` → `proxy_ops::handle_new_proxy(...)`
5. Change internal calls: `listen_and_proxy(...)` → `proxy_ops::listen_and_proxy(...)`
6. Change internal calls: `run_udp_listener(...)` → `proxy_ops::run_udp_listener(...)`
7. Change internal calls: `unregister_control(...)` → `proxy_ops::unregister_control(...)`

- [ ] **Step 2: Create proxy_ops.rs (proxy registration and listeners)**

Create `frp-server/src/control/proxy_ops.rs`:

```rust
//! Proxy lifecycle operations: registration, listener binding, cleanup.

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use crate::proxy::ProxyInfo;
use crate::service::{AppState, InternalMsg};

/// Handle NewProxy message from client.
pub(crate) async fn handle_new_proxy(
    state: &Arc<AppState>,
    np: msg::NewProxy,
    ctl_tx: &mpsc::UnboundedSender<InternalMsg>,
    proxy_bind_addr: &str,
    allow_ports: &[(u16, u16)],
) {
    // ... [copy exact code from control.rs:605-772, the entire handle_new_proxy function] ...
}

/// Spawn a TCP listener for a proxy and bridge incoming connections.
pub(crate) async fn listen_and_proxy(
    state: Arc<AppState>,
    proxy_name: String,
    proxy_type: String,
    listener: TcpListener,
    bind_addr: SocketAddr,
    use_encryption: bool,
    use_compression: bool,
    ctl_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    // ... [copy exact code from control.rs:775-817, the entire listen_and_proxy function] ...
}

/// Spawn a UDP listener for a proxy.
pub(crate) async fn run_udp_listener(
    state: Arc<AppState>,
    proxy_name: String,
    bind_addr: SocketAddr,
    ctl_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    // ... [copy exact code from control.rs:818-846, the entire run_udp_listener function] ...
}

/// Clean up all proxy listeners and state for a disconnecting client.
pub(crate) async fn unregister_control(state: &Arc<AppState>, run_id: &str) {
    // ... [copy exact code from control.rs:847-872, the entire unregister_control function] ...
}
```

- [ ] **Step 3: Create bridge.rs (work connection assignment)**

Create `frp-server/src/control/bridge.rs`:

```rust
//! Work connection bridging: assign pooled connections to pending proxy requests.

use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

use frp_core::msg::FrpMessage;
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_core::encryption;

/// Maximum time a proxy request waits for a work connection.
pub(crate) const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A pending proxy connection waiting for a work connection.
#[derive(Debug)]
pub(crate) struct PendingRequest {
    pub proxy_name: String,
    pub user_conn: IoStream,
    pub pre_read: Vec<u8>,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub created_at: Instant,
}

/// Send StartWorkConn on the work connection, then bridge user_conn ↔ work_conn.
pub(crate) async fn assign_work_to_proxy(
    work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
) {
    // ... [copy exact code from control.rs:469-601, the entire assign_work_to_proxy function] ...
}
```

- [ ] **Step 4: Update lib.rs**

In `frp-server/src/lib.rs`, change:
```rust
pub mod control;
```
to:
```rust
pub mod control;
// control is now a directory module (control/mod.rs)
```
(No change needed — `pub mod control;` auto-resolves to `control/mod.rs` when directory exists.)

- [ ] **Step 5: Delete old control.rs**

```bash
rm frp-server/src/control.rs
```

- [ ] **Step 6: Build and fix imports**

```bash
cargo build
```

Expected: compiles cleanly. Fix any import errors (add `use crate::control::proxy_ops;` etc. in mod.rs as needed).

- [ ] **Step 7: Run tests**

```bash
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add frp-server/src/control/ frp-server/src/lib.rs
git rm frp-server/src/control.rs
git commit -m "refactor: split control.rs into control/ module (mod, proxy_ops, bridge)"
```

---

### Task 4: Split frp-client/src/plugin.rs into plugin/ module

**Files:**
- Create: `frp-client/src/plugin/mod.rs`
- Create: `frp-client/src/plugin/http.rs`
- Create: `frp-client/src/plugin/socks5.rs`
- Create: `frp-client/src/plugin/static_file.rs`
- Delete: `frp-client/src/plugin.rs`

Split 1067-line plugin.rs into 4 files by plugin type.

- [ ] **Step 1: Create directory and mod.rs**

```bash
mkdir -p frp-client/src/plugin
```

Create `frp-client/src/plugin/mod.rs`:

```rust
//! Client-side plugin support (http_proxy, socks5, static_file).
//!
//! Each plugin type gets its own submodule with a factory function
//! returning a PluginHandle that owns the listener task.

mod http;
mod socks5;
mod static_file;

pub(crate) use http::{start_http_proxy, HttpProxyAuth};
pub(crate) use socks5::start_socks5_proxy;
pub(crate) use static_file::start_static_file_proxy;

use std::net::SocketAddr;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use frp_core::config::PluginConfig;

/// Handle to a running plugin listener. Dropping it sends a shutdown
/// signal and waits for the listener task to finish.
pub struct PluginHandle {
    pub local_addr: SocketAddr,
    handle: JoinHandle<()>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl PluginHandle {
    pub fn new(local_addr: SocketAddr, handle: JoinHandle<()>, shutdown: oneshot::Sender<()>) -> Self {
        Self {
            local_addr,
            handle,
            shutdown: Some(shutdown),
        }
    }
}

impl Drop for PluginHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.handle.abort();
    }
}

/// Decode base64 string (standard alphabet, with/without padding).
pub(crate) fn base64_decode(input: &str) -> Result<String, ()> {
    // ... [copy exact code from plugin.rs:129-159, the base64_decode function] ...
}

/// Split "host:port" into (host, port). Port defaults to 80.
pub(crate) fn split_host_port(s: &str) -> (&str, u16) {
    // ... [copy exact code from plugin.rs:291-324, the split_host_port function] ...
}

/// URL-decode a percent-encoded string.
pub(crate) fn urlencoding_decode(input: &str) -> String {
    // ... [copy exact code from plugin.rs:805-831, the urlencoding_decode function] ...
}
```

- [ ] **Step 2: Create http.rs**

Create `frp-client/src/plugin/http.rs`:

```rust
//! HTTP proxy plugin.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

use super::{base64_decode, split_host_port, PluginHandle};

pub(crate) struct HttpProxyAuth {
    pub user: String,
    pub pass: String,
}

impl HttpProxyAuth {
    fn from_config(cfg: &PluginConfig) -> Option<Self> {
        if cfg.http_user.is_empty() && cfg.http_password.is_empty() {
            return None;
        }
        Some(Self {
            user: cfg.http_user.clone(),
            pass: cfg.http_password.clone(),
        })
    }

    fn check(&self, header: &str) -> bool {
        // ... [copy exact code from original plugin.rs HttpProxyAuth::check] ...
    }
}

pub(crate) async fn start_http_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    // ... [copy exact code from plugin.rs:42-127, the start_http_proxy function] ...
}

// ... [copy handle_http_proxy_conn, handle_connect, handle_http_forward,
//      parse_http_url functions] ...

#[cfg(test)]
mod tests {
    // ... [copy http-related tests from original plugin.rs] ...
}
```

- [ ] **Step 3: Create socks5.rs**

Create `frp-client/src/plugin/socks5.rs`:

```rust
//! SOCKS5 proxy plugin (RFC 1928).

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

use super::PluginHandle;

pub(crate) async fn start_socks5_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    // ... [copy exact code from plugin.rs:326-373, the start_socks5_proxy function] ...
}

// ... [copy handle_socks5_conn, parse_socks5_addr, parse_socks5_target,
//      make_socks5_reply functions] ...

#[cfg(test)]
mod tests {
    // ... [copy socks5-related tests from original plugin.rs] ...
}
```

- [ ] **Step 4: Create static_file.rs**

Create `frp-client/src/plugin/static_file.rs`:

```rust
//! Static file serving plugin.

use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

use super::{base64_decode, urlencoding_decode, PluginHandle};

pub(crate) async fn start_static_file_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    // ... [copy exact code from plugin.rs:615-676, the start_static_file_proxy function] ...
}

// ... [copy handle_static_file_conn, resolve_static_path, mime_from_path functions] ...

#[cfg(test)]
mod tests {
    // ... [copy static_file-related tests from original plugin.rs] ...
}
```

- [ ] **Step 5: Update lib.rs**

In `frp-client/src/lib.rs`, verify `pub mod plugin;` exists (auto-resolves to `plugin/mod.rs`). No change needed.

- [ ] **Step 6: Delete old plugin.rs**

```bash
rm frp-client/src/plugin.rs
```

- [ ] **Step 7: Build and fix imports**

```bash
cargo build
```

Expected: compiles cleanly. Fix any import errors (ensure all `use crate::plugin::*` in service.rs still resolve).

- [ ] **Step 8: Run tests**

```bash
cargo test --workspace
```

Expected: all tests pass, including plugin unit tests.

- [ ] **Step 9: Commit**

```bash
git add frp-client/src/plugin/ frp-client/src/lib.rs
git rm frp-client/src/plugin.rs
git commit -m "refactor: split plugin.rs into plugin/ module (http, socks5, static_file)"
```

---

### Task 5: Dead Code Removal

**Files:**
- Modify: `frp-core/src/lib.rs` (remove kcp/quic mod if dead)
- Modify: `frp-core/src/transport.rs` (remove Kcp/Quic IoStream variants)
- Potentially delete: `frp-core/src/kcp.rs`, `frp-core/src/quic.rs`
- Check: `frp-core/src/bandwidth.rs`

Verify KCP/QUIC are truly dead, then remove. Check bandwidth for wiring.

- [ ] **Step 1: Verify KCP/QUIC are dead**

```bash
grep -rn 'IoStream::Kcp\|IoStream::Quic\|KcpStream\|QuicStream\|kcp::\|quic::' frp-core/src/ frp-server/src/ frp-client/src/ --include='*.rs'
```

If matches are only in `transport.rs` match arms (just logging warnings), the modules are dead.

- [ ] **Step 2: Remove KCP and QUIC from lib.rs**

In `frp-core/src/lib.rs`, remove:
```rust
pub mod kcp;
pub mod quic;
```

- [ ] **Step 3: Remove KCP and QUIC from transport.rs**

In `frp-core/src/transport.rs`, remove `IoStream` variants:

Delete:
```rust
Kcp(KcpStream),
Quic(QuicStream),
```

And remove their match arms in all methods (`write_v1_frame`, `read_v1_frame`, `peer_addr`, `into_split`, `into_encrypted`).

- [ ] **Step 4: Remove kcp.rs and quic.rs**

```bash
rm frp-core/src/kcp.rs frp-core/src/quic.rs
```

- [ ] **Step 5: Check bandwidth.rs wiring**

```bash
grep -rn 'BandwidthLimiter\|bandwidth::\|use.*bandwidth' frp-core/src/ frp-server/src/ frp-client/src/ --include='*.rs'
```

If zero matches (outside of its own file): remove `pub mod bandwidth;` from lib.rs and delete `frp-core/src/bandwidth.rs`.

If used: leave in place but add `#[allow(dead_code)]` on unused methods with a comment.

- [ ] **Step 6: Build and verify**

```bash
cargo build
cargo test --workspace
cargo clippy --workspace
```

Expected: compiles cleanly, all tests pass, clippy clean.

- [ ] **Step 7: Commit**

```bash
git add frp-core/src/lib.rs frp-core/src/transport.rs
git rm frp-core/src/kcp.rs frp-core/src/quic.rs  # + bandwidth.rs if dead
git commit -m "chore: remove dead KCP/QUIC placeholder modules"
```

---

### Task 6: Final Verification

**Files:**
- All modified files

Run full verification suite.

- [ ] **Step 1: Full test suite**

```bash
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 2: Clippy**

```bash
cargo clippy --workspace
```

Expected: no warnings.

- [ ] **Step 3: Grep checks**

```bash
grep -rn 'eprintln!' --include='*.rs' frp-core/src/ frp-server/src/ frp-client/src/
grep -rn 'unreachable!' --include='*.rs' frp-core/src/ frp-server/src/ frp-client/src/
```

Expected: 0 matches.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final code optimization verification"
```
