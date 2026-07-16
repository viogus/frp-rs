# handle_control Monolith Refactor — Implementation Plan v2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decompose the 1488-line `handle_control` function into focused modules without changing behavior, public API, or wire protocol semantics.

**Architecture:** Extract sub-modules from `mod.rs`: `login.rs` (auth, encryption setup), `pool.rs` (work conn lifecycle), `nathole.rs` (XTCP NAT hole punch), `proxy.rs` (proxy reg/ping), `dispatch.rs` (message routing). All handlers share two state containers (`ControlState` owned, `ControlContext` shared refs) passed by `&mut`. Writer is passed as generic `&mut W` to handlers that need it; reader stays in the main select! loop.

**Tech Stack:** Rust, tokio, frp-core protocol types. No new dependencies.

## Global Constraints

- `handle_control` public signature MUST NOT change.
- No behavior changes — message ordering, error handling, edge cases preserved verbatim.
- All existing tests MUST pass at every commit (`cargo test --workspace --all-features`).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` MUST pass at every commit.
- `cargo fmt --all -- --check` MUST pass at every commit.
- `cargo build --no-default-features --features tiny` MUST pass at every commit.
- `cargo build --no-default-features --features micro` MUST pass at every commit.

## Key Types (from actual code, verified 2026-07-16)

**`ReloadableState`** (`frp-server/src/state.rs:107`):
```rust
pub struct ReloadableState {
    pub auth_cfg: Arc<AuthConfig>,
    pub encryption_key: [u8; 16],
    pub allow_ports: Vec<(u16, u16)>,
    pub additional_auth_scopes: Vec<String>,
}
```

**`PoolEntry`** (`mod.rs:57-60`): `{ conn: IoStream, pooled_at: Instant }`
**`PendingRequest`** (`mod.rs:63-72`): `{ proxy_name, user_conn, pre_read, use_encryption, use_compression, created_at, response_headers, proxy_type }`

**Actual local state declarations** (`mod.rs:479-492`):
```rust
let mut work_pool: VecDeque<PoolEntry> = VecDeque::new();
let mut pending_requests: VecDeque<PendingRequest> = VecDeque::new();
let mut pending_udp: VecDeque<(String, Instant)> = VecDeque::new();
let mut pending_nat_hole_sids: VecDeque<(String, String, Instant)> = VecDeque::new();
let mut listener_handles: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
let mut udp_sockets: HashMap<String, Arc<tokio::net::UdpSocket>> = HashMap::new();
let mut udp_local_to_proxy: HashMap<String, String> = HashMap::new();
let mut shutting_down = false;
let mut last_ping = Instant::now();
```

**`pool_stats`** (`mod.rs:299`): `Arc<crate::state::PoolStats>`
**`reloadable`** (`mod.rs:249`): `ReloadableState` (cloned from `state.reloadable.read_ok()`)

---

### Task 1: Define ControlState and ControlContext structs

**Files:**
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Produces: `pub(crate) struct ControlState`, `pub(crate) struct ControlContext`

**Goal:** Add the two state containers. No logic extraction — dead-code warnings acceptable.

- [ ] **Step 1: Add structs after the WORK_POOL_EXTRA const (after line 54)**

Insert after `const WORK_POOL_EXTRA: usize = 10;` (line 54):

```rust
// ---- State containers for handle_control ----

/// Mutable local state owned by the control session. Passed by `&mut` to
/// all handler functions. Single-task — no synchronisation needed.
pub(crate) struct ControlState {
    pub shutting_down: bool,
    pub work_pool: VecDeque<PoolEntry>,
    pub pending_requests: VecDeque<PendingRequest>,
    pub pending_udp: VecDeque<(String, Instant)>,
    /// (sid, proxy_name, created_at) triples queued while waiting for a work connection.
    pub pending_nat_hole_sids: VecDeque<(String, String, Instant)>,
    pub listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
    pub udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    pub udp_local_to_proxy: std::collections::HashMap<String, String>,
    pub last_ping: Instant,
}

/// Immutable/shared context passed to every handler. Owns its data —
/// no lifetimes needed. Writer/reader are passed separately as generic
/// params to handlers that need them.
pub(crate) struct ControlContext {
    pub state: std::sync::Arc<crate::state::AppState>,
    pub pool_stats: std::sync::Arc<crate::state::PoolStats>,
    pub reloadable: crate::state::ReloadableState,
    pub v2: bool,
    pub run_id: String,
    pub pool_cap: usize,
    pub internal_tx: tokio::sync::mpsc::Sender<crate::state::InternalMsg>,
    pub peer: Option<std::net::SocketAddr>,
}
```

- [ ] **Step 2: Verify compilation**

```bash
cd "$(git rev-parse --show-toplevel)" && cargo build -p frp-server 2>&1 | tail -5
```

Expected: compiles (structs unused — dead-code warnings acceptable).

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/control/mod.rs
git commit -m "refactor(control): add ControlState and ControlContext structs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Extract login::authenticate

**Files:**
- Create: `frp-server/src/control/login.rs`
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: `ControlState`, `ControlContext` (from Task 1)
- Produces: `pub(crate) async fn authenticate(...)` → returns `Result<(ControlContext, ControlState, Sender, IncomingOpts, ...), ()>`
- `mod.rs` gains: `mod login;`

**Goal:** Move the login authentication block (L179 through L499 in current mod.rs — throttle, OIDC, token auth, crypto, duplicate run_id, LoginResp, encryption wrap, ReqWorkConn pre-split, local state init) from `handle_control` into `login::authenticate`.

**What authenticate returns (tuple):**
1. `ControlContext` — initialized with state, pool_stats, reloadable, v2, run_id, pool_cap, peer
2. `ControlState` — initialized with empty collections, last_ping = Instant::now()
3. `mpsc::Sender<InternalMsg>` — the internal_tx (needed by main loop for shutdown_token race)
4. `mpsc::Receiver<InternalMsg>` — the internal_rx (consumed by main select! loop)
5. `Box<dyn AsyncRead + Unpin + Send>` — reader half (consumed by main select! loop)
6. `Box<dyn AsyncWrite + Unpin + Send>` — writer half (passed to handlers)
7. `Option<IncomingStreams>` — yamux incoming (for TcpMux work conns)
8. `Interval` — ping_tick (for periodic pings)

- [ ] **Step 1: Create login.rs**

Write `frp-server/src/control/login.rs` with the authenticate function skeleton. The function signature:

```rust
//! Login authentication for control connections.
//!
//! Handles OIDC verification, token-based auth, PBKDF2 key derivation,
//! duplicate `run_id` shutdown, encryption setup, and per-client state
//! initialisation.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Interval;
use tracing::{debug, error, info, warn};
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;
use crate::state::{AppState, InternalMsg, ReloadableState};
use super::{
    ControlContext, ControlState,
    PoolEntry, PendingRequest,
    read_ctl_msg, write_ctl_msg, WORK_POOL_EXTRA,
};

/// Authenticate a new control connection and set up per-client state.
/// On success returns all state needed by the main select! loop.
/// On failure sends LoginResp with an error and returns `Err(())`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authenticate<S>(
    mut stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    mut incoming: Option<IncomingStreams>,
    v2: bool,
    crypto_ctx: Option<frp_core::v2_handshake::CryptoContext>,
) -> Result<(
    ControlContext,
    ControlState,
    mpsc::Sender<InternalMsg>,
    mpsc::Receiver<InternalMsg>,
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
    Option<IncomingStreams>,
    Interval,
), ()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // TODO: Move the entire block from handle_control here.
    // This is lines 179 through 499 of the original mod.rs:
    //   - Login throttle (L179-187)
    //   - OIDC + token auth (L189-247)
    //   - run_id setup, plugin login, internal channel, duplicate run_id shutdown (L249-328)
    //   - LoginResp send (L330-377)
    //   - Encryption wrap: V2 AEAD or V1 CipherStream (L379-466)
    //   - ReqWorkConn pre-split (for V1 path only) (L432-462)
    //   - Per-client state init: pool_cap, work_pool, pending_requests, etc. (L470-499)

    // When copying: replace `state` with `state` (same name — it's a parameter).
    // The `reloadable` variable at L249 becomes part of ControlContext.

    todo!()
}
```

- [ ] **Step 2: Move the login block (L179-L499) into authenticate, return the tuple**

1. Open the original `mod.rs`, lines 179-499.
2. Cut the entire block: from `// --- Login throttle` through the `ping_tick` setup (line 499 `ping_tick.set_missed_tick_behavior(...)`).
3. Paste into `login.rs`, replacing the `todo!()`.
4. At the bottom of authenticate, return the tuple:
```rust
    Ok((
        ControlContext {
            state: state.clone(),
            pool_stats: pool_stats.clone(),
            reloadable,
            v2,
            run_id,
            pool_cap,
            peer,
        },
        ControlState {
            shutting_down,
            work_pool,
            pending_requests,
            pending_udp,
            pending_nat_hole_sids,
            listener_handles,
            udp_sockets,
            udp_local_to_proxy,
            last_ping,
        },
        internal_tx,
        internal_rx,
        reader,
        writer,
        incoming,
        ping_tick,
    ))
```
5. Use the variable names already present in the block — they match the ControlState fields exactly.

- [ ] **Step 3: Replace login block in mod.rs with authenticate call**

Replace lines 179-499 in mod.rs with:
```rust
    info!(peer = ?peer, "New control connection from {:?}", peer);

    // 1. Authenticate and set up per-client state (login.rs)
    let (mut ctx, mut ctl, internal_tx, mut internal_rx, mut reader, mut writer, mut incoming, mut ping_tick) =
        match login::authenticate(stream, login, state, peer, incoming, v2, crypto_ctx).await {
            Ok(tuple) => tuple,
            Err(()) => return,
        };

    let run_id = ctx.run_id.clone();
    let pool_cap = ctx.pool_cap;
    let pool_stats = ctx.pool_stats.clone();
    let v2 = ctx.v2;
```

Note: `info!(peer = ?peer, "New control connection from {:?}", peer);` stays BEFORE the authenticate call (was line 179). The `let run_id` etc. are convenience bindings for the main loop to use without `ctx.` prefix everywhere — these can be gradually replaced with `ctx.` access in later tasks.

- [ ] **Step 4: Add `mod login;` to mod.rs**

After `mod bridge;` and `mod proxy_ops;` at the top, add:
```rust
mod login;
```

- [ ] **Step 5: Verify compilation and tests**

```bash
cargo build -p frp-server 2>&1 | tail -5
cargo test --workspace --all-features 2>&1 | tail -5
```

Expected: compiles, all tests pass.

- [ ] **Step 6: Run clippy and fmt**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

Expected: zero warnings, no format diffs.

- [ ] **Step 7: Commit**

```bash
git add frp-server/src/control/
git commit -m "refactor(control): extract login::authenticate from handle_control

Move OIDC, token auth, crypto setup, run_id dedup, encryption wrap,
and per-client state init into login.rs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Extract pool.rs — work connection lifecycle

**Files:**
- Create: `frp-server/src/control/pool.rs`
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: `ControlState`, `ControlContext`, `PoolEntry`, `PendingRequest`, `WORK_POOL_EXTRA`, `PENDING_REQUEST_TIMEOUT`, existing `assign_or_queue` function, `write_start_work_conn_with_nat_hole_sid` helper
- Produces:
  - `pub(crate) async fn handle_new_work_conn(ctx, ctl, writer, stream)` → `Result<(), ()>`
  - `pub(crate) async fn handle_visitor_conn(ctx, ctl, writer, proxy_name, visitor_conn)` → `Result<(), ()>`
  - `pub(crate) async fn handle_proxy_user_conn(ctx, ctl, writer, proxy_name, user_conn, pre_read)` → `Result<(), ()>`
  - `pub(crate) async fn handle_udp_work_conn(ctx, ctl, writer, proxy_name)` → `Result<(), ()>`
- `mod.rs` gains: `mod pool;`

**Goal:** Move pool-related types, constants, helpers, and InternalMsg handlers into pool.rs.

- [ ] **Step 1: Move types, constants, and helpers to pool.rs**

Move from `mod.rs` to `pool.rs` (cut from mod.rs, paste into pool.rs):
1. `PENDING_REQUEST_TIMEOUT` constant (line 51)
2. `WORK_POOL_EXTRA` constant (line 54) — make it `pub(crate)`
3. `struct PoolEntry` (lines 57-60)
4. `struct PendingRequest` (lines 63-72) — make it `pub(crate)`
5. `fn assign_or_queue` (lines 78-120)
6. `fn write_start_work_conn_with_nat_hole_sid` (lines 126-162)

Add `use super::{ControlContext, ControlState, read_ctl_msg, write_ctl_msg};` and necessary imports.

- [ ] **Step 2: Move InternalMsg pool handlers**

Cut these `InternalMsg` match arm bodies from the main select! loop and paste as functions in `pool.rs`:

1. `InternalMsg::NewWorkConn(stream)` — lines 549-613
2. `InternalMsg::VisitorConn { proxy_name, visitor_conn }` — lines 614-639
3. `InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }` — lines 640-715
4. `InternalMsg::UdpNeedsWorkConn { proxy_name }` — lines 716-723

Each becomes `pub(crate) async fn handle_<name><W>(ctx: &mut ControlContext, ctl: &mut ControlState, writer: &mut W, ...) -> Result<(), ()> where W: AsyncWriteExt + Unpin`.

**Implementation notes for handler extraction:**
- Replace `&mut writer` with the generic `writer: &mut W` parameter
- Replace `state` with `ctx.state`, `pool_stats` with `&ctx.pool_stats`, `run_id` with `&ctx.run_id`, `v2` with `ctx.v2`, `reloadable` with `&ctx.reloadable`, `peer` with `ctx.peer`
- Replace `work_pool` with `ctl.work_pool`, `pending_requests` with `ctl.pending_requests`, etc.
- Replace `pool_cap` with `ctx.pool_cap`
- `internal_tx` is not available in pool handlers — but the existing code doesn't pass it to pool operations. The `UdpNeedsWorkConn` handler only uses `writer`.
- When the original code does `break`, change to `return Err(())`
- When the original code does `continue`, keep as `continue` (it's still in the handler function, which returns to the dispatch layer)
- The `assign_or_queue` call already takes individual params — change to pass `&ctx.reloadable.encryption_key` for enc_key, `ctx.v2` for v2, `&ctx.state` for state, `&ctx.pool_stats` for pool_stats, `&mut ctl.work_pool` for work_pool, `&mut ctl.pending_requests` for pending_requests

- [ ] **Step 3: Replace InternalMsg arms with function calls**

In `mod.rs`, replace each cut arm body:
```rust
Some(InternalMsg::NewWorkConn(stream)) => {
    pool::handle_new_work_conn(&mut ctx, &mut ctl, &mut writer, stream).await?
}
Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
    pool::handle_visitor_conn(&mut ctx, &mut ctl, &mut writer, proxy_name, visitor_conn).await?
}
Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
    pool::handle_proxy_user_conn(&mut ctx, &mut ctl, &mut writer, proxy_name, user_conn, pre_read).await?
}
Some(InternalMsg::UdpNeedsWorkConn { proxy_name }) => {
    pool::handle_udp_work_conn(&mut ctx, &mut ctl, &mut writer, proxy_name).await?
}
```

- [ ] **Step 4: Add `mod pool;` to mod.rs**

- [ ] **Step 5: Verify compilation, tests, clippy, fmt**

```bash
cargo build -p frp-server 2>&1 | tail -5
cargo test --workspace --all-features 2>&1 | tail -5
cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
```

- [ ] **Step 6: Commit**

```bash
git add frp-server/src/control/
git commit -m "refactor(control): extract pool.rs — work conn lifecycle

Move assign_or_queue, NewWorkConn, VisitorConn, ProxyUserConn,
UdpNeedsWorkConn handlers into pool.rs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Extract nathole.rs — XTCP NAT hole punch

**Files:**
- Create: `frp-server/src/control/nathole.rs`
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: `ControlState`, `ControlContext`
- Produces:
  - `pub(crate) async fn handle_nat_hole_client(ctx, ctl, writer, client_msg)`
  - `pub(crate) async fn handle_nat_hole_sid(ctx, ctl, writer, sid_msg)`
  - `pub(crate) async fn handle_nat_hole_resp(ctx, ctl, writer, resp_msg)`
  - `pub(crate) async fn handle_nat_hole_report(ctx, ctl, writer, report_msg)`
  - `pub(crate) async fn handle_nat_hole_visitor_on_ctl(ctx, ctl, writer, nhv, login_user)`
  - `pub(crate) async fn handle_new_visitor_conn(ctx, ctl, writer, nvc, login_user)`
  - `pub(crate) async fn handle_write_sid(ctx, ctl, writer, sid, provider_addr)`
  - `pub(crate) async fn handle_write_resp(ctx, ctl, writer, transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs)`
  - `pub(crate) async fn handle_write_report(ctx, ctl, writer, sid)`
  - `pub(crate) async fn handle_sid_on_work_conn(ctx, ctl, writer, sid, proxy_name)`
- `mod.rs` gains: `mod nathole;`

**Goal:** Move all XTCP NAT hole punch handlers. This is the most complex extraction — careful with the spawned task in NatHoleVisitor.

**Implementation notes:**

Cut each handler body from mod.rs and paste as a function in nathole.rs with:
```rust
pub(crate) async fn handle_<name><W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    ...message-specific params...
) -> Result<(), ()>
```

For `handle_nat_hole_visitor_on_ctl`: this function needs `internal_tx` (now in `ctx.internal_tx`) and `login_user` (from `login.user` — pass as parameter). The spawned task clones `ctx.state`, `ctx.internal_tx`.

- [ ] **Step 3: Replace arms with function calls in mod.rs**

- [ ] **Step 4: Add `mod nathole;` to mod.rs**

- [ ] **Step 5: Verify compilation, tests, clippy, fmt**

- [ ] **Step 6: Commit**

```bash
git add frp-server/src/control/
git commit -m "refactor(control): extract nathole.rs — XTCP NAT hole punch

Move NatHoleClient, NatHoleSid, NatHoleResp, NatHoleReport,
NatHoleVisitor, NewVisitorConn, and InternalMsg NAT hole handlers
into nathole.rs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Extract proxy.rs — proxy registration, ping, and cleanup

**Files:**
- Create: `frp-server/src/control/proxy.rs`
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: `ControlState`, `ControlContext`
- Produces:
  - `pub(crate) async fn handle_new_proxy(ctx, ctl, writer, np)` → `Result<(), ()>`
  - `pub(crate) async fn handle_close_proxy(ctx, ctl, writer, cp)` → `Result<(), ()>`
  - `pub(crate) async fn handle_ping(ctx, ctl, writer, ping_msg)` → `Result<(), ()>`
  - `pub(crate) async fn handle_udp_packet(ctx, ctl, writer, up)` → `Result<(), ()>`
  - `pub(crate) async fn cleanup(ctx, ctl)` (called after loop exit)
- `mod.rs` gains: `mod proxy;`

**Goal:** Move NewProxy, CloseProxy, Ping, UDPPacket message handlers from the FrpMessage match arms into `proxy.rs`. Also move the cleanup block at the end of handle_control.

**Implementation notes:**
- `NewProxy` (L930-933): calls `proxy_ops::handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut listener_handles, &mut udp_sockets, &mut udp_local_to_proxy, v2)`. With refactor: `proxy_ops::handle_new_proxy(np, &ctx.run_id, &ctx.state, writer, &ctx.internal_tx, &mut ctl.listener_handles, &mut ctl.udp_sockets, &mut ctl.udp_local_to_proxy, ctx.v2)`.
- `CloseProxy` (L972-1029): complex block with proxy_manager lookup, port cleanup, sk_index cleanup, listener abort. Accesses `state`, `run_id`, `listener_handles`, `internal_tx` (for plugin spawn).
- `Ping` (L1127-1171): validates ping auth, updates last_ping, sends Pong. Accesses `reloadable`, `state`, `run_id`, `peer`.
- `UDPPacket` (L874-928): forwarding logic with decrypt/decompress, udp_sockets lookup. Accesses `state`, `reloadable`, `udp_sockets`, `udp_local_to_proxy`.
- Cleanup block (L1629-1655): drains listener_handles, emits dashboard events, calls `proxy_ops::unregister_control`, removes client. Accesses `state`, `run_id`, `shutting_down`, `listener_handles`.

- [ ] **Step 1: Create proxy.rs with handler functions**

Cut each handler from mod.rs, paste as `pub(crate) async fn handle_<name><W: AsyncWriteExt + Unpin>(...) -> Result<(), ()>`.

For the cleanup block: create `pub(crate) async fn cleanup<W: AsyncWriteExt + Unpin>(ctx: &mut ControlContext, ctl: &mut ControlState, writer: &mut W)`.

- [ ] **Step 2: Replace arms with function calls in mod.rs**

```rust
Ok(FrpMessage::NewProxy(np)) => proxy::handle_new_proxy(&mut ctx, &mut ctl, &mut writer, np).await?,
Ok(FrpMessage::CloseProxy(cp)) => proxy::handle_close_proxy(&mut ctx, &mut ctl, &mut writer, cp).await?,
Ok(FrpMessage::Ping(ping_msg)) => proxy::handle_ping(&mut ctx, &mut ctl, &mut writer, ping_msg).await?,
Ok(FrpMessage::UDPPacket(up)) => proxy::handle_udp_packet(&mut ctx, &mut ctl, &mut writer, up).await?,
```

Replace the cleanup block (L1629-1655) with:
```rust
    proxy::cleanup(&mut ctx, &mut ctl, &mut writer).await;
```

- [ ] **Step 3: Add `mod proxy;` to mod.rs**

- [ ] **Step 4: Verify compilation, tests, clippy, fmt**

- [ ] **Step 5: Commit**

---

### Task 6: Extract dispatch.rs — message routing

**Files:**
- Create: `frp-server/src/control/dispatch.rs`
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: All handler functions from pool.rs, nathole.rs, proxy.rs
- Produces:
  - `pub(crate) async fn dispatch_internal(ctx, ctl, writer, msg) -> Result<(), ()>`
  - `pub(crate) async fn dispatch_frp_message(ctx, ctl, writer, msg) -> Result<(), ()>`
- `mod.rs` gains: `mod dispatch;`

**Goal:** Move the `match msg { ... }` blocks out of the select! loop into dispatch.rs. mod.rs contains only the select! structure and the idle expiry / heartbeat logic between loop iterations.

- [ ] **Step 1: Create dispatch.rs**

Two functions that route message variants to the extracted handlers:

```rust
//! Control message dispatch — pure routing from message variants to handlers.
//!
//! These functions contain NO business logic. They match on message type
//! and delegate to the appropriate handler in `pool`, `nathole`, or `proxy`.

use tokio::io::AsyncWriteExt;
use frp_core::msg::{self, FrpMessage};
use crate::state::InternalMsg;
use super::{ControlContext, ControlState};

pub(crate) async fn dispatch_internal<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: InternalMsg,
) -> Result<(), ()> {
    match msg {
        InternalMsg::NewWorkConn(s) =>
            super::pool::handle_new_work_conn(ctx, ctl, writer, s).await,
        InternalMsg::VisitorConn { proxy_name, visitor_conn } =>
            super::pool::handle_visitor_conn(ctx, ctl, writer, proxy_name, visitor_conn).await,
        InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read } =>
            super::pool::handle_proxy_user_conn(ctx, ctl, writer, proxy_name, user_conn, pre_read).await,
        InternalMsg::UdpNeedsWorkConn { proxy_name } =>
            super::pool::handle_udp_work_conn(ctx, ctl, writer, proxy_name).await,
        InternalMsg::NatHoleSidOnWorkConn { sid, proxy_name } =>
            super::nathole::handle_sid_on_work_conn(ctx, ctl, writer, sid, proxy_name).await,
        InternalMsg::WriteNatHoleSid { sid, provider_addr } =>
            super::nathole::handle_write_sid(ctx, ctl, writer, sid, provider_addr).await,
        InternalMsg::WriteNatHoleResp { transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs } =>
            super::nathole::handle_write_resp(ctx, ctl, writer, transaction_id, error, sid, protocol, candidate_addrs, assisted_addrs).await,
        InternalMsg::WriteNatHoleReport { sid } =>
            super::nathole::handle_write_report(ctx, ctl, writer, sid).await,
        #[cfg(feature = "vnet")]
        InternalMsg::VnetPacketForward { proxy_name, data } => {
            super::nathole::handle_vnet_packet_forward(ctx, ctl, writer, proxy_name, data).await
        }
        InternalMsg::Shutdown => {
            ctl.shutting_down = true;
            Ok(())
        }
    }
}

pub(crate) async fn dispatch_frp_message<W: AsyncWriteExt + Unpin>(
    ctx: &mut ControlContext,
    ctl: &mut ControlState,
    writer: &mut W,
    msg: FrpMessage,
) -> Result<(), ()> {
    match msg {
        FrpMessage::NewProxy(m) =>
            super::proxy::handle_new_proxy(ctx, ctl, writer, m).await,
        FrpMessage::CloseProxy(m) =>
            super::proxy::handle_close_proxy(ctx, ctl, writer, m).await,
        FrpMessage::Ping(m) =>
            super::proxy::handle_ping(ctx, ctl, writer, m).await,
        FrpMessage::UDPPacket(m) =>
            super::proxy::handle_udp_packet(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleClient(m) =>
            super::nathole::handle_nat_hole_client(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleSid(m) =>
            super::nathole::handle_nat_hole_sid(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleResp(m) =>
            super::nathole::handle_nat_hole_resp(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleReport(m) =>
            super::nathole::handle_nat_hole_report(ctx, ctl, writer, m).await,
        FrpMessage::NatHoleVisitor(m) =>
            super::nathole::handle_nat_hole_visitor_on_ctl(ctx, ctl, writer, m).await,
        FrpMessage::NewVisitorConn(m) =>
            super::nathole::handle_new_visitor_conn(ctx, ctl, writer, m).await,
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteAdvertise(m) =>
            super::nathole::handle_vnet_route_advertise(ctx, ctl, m).await,
        #[cfg(feature = "vnet")]
        FrpMessage::VnetPacket(m) =>
            super::nathole::handle_vnet_packet(ctx, ctl, m).await,
        #[cfg(feature = "vnet")]
        FrpMessage::VnetRouteRemove(m) =>
            super::nathole::handle_vnet_route_remove(ctx, ctl, m).await,
        other => {
            tracing::debug!("unhandled control msg: {:?}", other.v1_type_byte());
            Ok(())
        }
    }
}
```

**Important:** The exact function signatures must match what was actually extracted in Tasks 3-5. Adjust parameter lists to match.

- [ ] **Step 2: Replace match blocks in mod.rs**

```rust
internal = internal_rx.recv() => {
    match internal {
        Some(msg) => dispatch::dispatch_internal(&mut ctx, &mut ctl, &mut writer, msg).await?,
        None => break,
    }
}

msg = read_ctl_msg(&mut reader, ctx.v2) => {
    match msg {
        Ok(msg) => dispatch::dispatch_frp_message(&mut ctx, &mut ctl, &mut writer, msg).await?,
        Err(e) => {
            info!(peer = ?ctx.peer, error = %e, run_id = %ctx.run_id, "Control connection closed");
            break;
        }
    }
}
```

- [ ] **Step 3: Add `mod dispatch;` to mod.rs**

- [ ] **Step 4: Verify compilation, tests, clippy, fmt**

- [ ] **Step 5: Commit**

---

### Task 7: Full regression gate

**Files:** None modified — verification only.

- [ ] **Step 1: Clean build**

```bash
cargo build --release 2>&1 | tail -3
```

- [ ] **Step 2: Clippy — zero warnings**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -3
```

- [ ] **Step 3: Format check**

```bash
cargo fmt --all -- --check
```

- [ ] **Step 4: Full test suite**

```bash
cargo test --workspace --all-features 2>&1 | tail -5
```

- [ ] **Step 5: Tiny feature set**

```bash
cargo build --no-default-features --features tiny 2>&1 | grep -c '^error'
```
Expected: 0.

- [ ] **Step 6: Micro feature set**

```bash
cargo build --no-default-features --features micro 2>&1 | grep -c '^error'
```
Expected: 0.

- [ ] **Step 7: Go compat tests**

```bash
bash scripts/compat-test.sh 2>&1 | grep 'RESULTS'
```
Expected: `RESULTS: 57 passed, 0 failed`.

- [ ] **Step 8: Commit verification**

```bash
git commit --allow-empty -m "chore: full regression gate passed for handle_control refactor

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Implementation Order

1. Task 1: ControlState + ControlContext structs (add only, no logic changes)
2. Task 2: login.rs extraction (largest single block, establishes pattern)
3. Task 3: pool.rs extraction (types + helpers + 4 handlers)
4. Task 4: nathole.rs extraction (most complex, needs internal_tx in ControlContext)
5. Task 5: proxy.rs extraction (NewProxy/CloseProxy/Ping/UDPPacket + cleanup)
6. Task 6: dispatch.rs (routing layer, depends on all handlers)
7. Task 7: Full regression gate

Each task ends with a commit. At every step: `cargo build`, `cargo test --workspace --all-features`, `cargo clippy`, `cargo fmt --all -- --check` must pass.
