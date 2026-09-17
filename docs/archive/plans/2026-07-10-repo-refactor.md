# Repo Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land two in-flight uncommitted work items, then remove duplication at four hotspots and group the `AppState` god-struct — all behavior-preserving.

**Architecture:** Six independent units, ordered 1→6, each in its own git worktree with one subagent and review between. Units 1–2 verify+commit already-written WIP. Units 3–6 are conservative extractions: no wire-protocol change, no new dependencies. The cross-compat suite (`scripts/compat-test.sh`) gates every unit that touches a data-plane or control-plane path.

**Tech Stack:** Rust, tokio, cargo workspace (frp-core / frp-server / frp-client / frp-vnet). Test tooling: `cargo test`, `scripts/compat-test.sh` (Go frp v0.69.1 cross-compat).

## Global Constraints

- No new dependencies (CLAUDE.md dependency policy — copy exact: "No new dependencies without explicit justification").
- `tiny` and `micro` feature variants must build: `cargo build --release -p frps -p frpc --no-default-features --features tiny` and `--features micro`.
- Cross-compat suite green vs Go frp v0.69.1: `bash scripts/compat-test.sh --verbose`.
- Every unit: own worktree (`EnterWorktree`), never edit `main` directly. One subagent per unit; review before next.
- Behavior-preserving: no change to wire framing, encryption order (compress→encrypt), metrics counter semantics, EOF/shutdown semantics, or biased-select ordering.
- These are refactors: the TDD cycle is **characterization** — the existing suite already passes; refactor; suite still passes. New unit tests are added only where a pure helper has testable I/O.

---

### Task 1: Land pool feature (frp-core + frp-server)

Verify the already-written work-conn pool observability + buffer pool compiles clean across the feature matrix and passes compat, then commit. **No code change.**

**Files (already modified, uncommitted on `main`):**
- Create: `frp-core/src/buffer_pool.rs`
- Modify: `frp-core/src/lib.rs`, `frp-core/src/bridge.rs`, `frp-server/src/state.rs`, `frp-server/src/control/mod.rs`, `frp-server/src/dashboard.rs`, `frp-server/src/metrics/prom.rs`

**Interfaces:**
- Produces: `frp_core::buffer_pool::PoolGuard` (`acquire() -> Self`, `as_mut_slice() -> &mut [u8]`, `data() -> &[u8]`); `frp_server::state::PoolStats { pool_size: AtomicI64, pending_requests: AtomicI64 }`; `ControlTx.pool_stats: Arc<PoolStats>`; `AppState.pool_hits/pool_misses/pool_drops: AtomicU64`, `AppState.pool_idle_timeout: Duration`. Units 4, 5, 6 consume these.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: land-pool-feature
```
The uncommitted changes live in the main working tree. Move them into the worktree by committing there (see Step 6). If using EnterWorktree with `head` base, the changes are visible; otherwise stage the specific paths listed above.

- [ ] **Step 2: Build full workspace**

Run: `cargo build --workspace`
Expected: `Finished` (exit 0).

- [ ] **Step 3: Build tiny + micro variants**

Run:
```bash
cargo build --release -p frps -p frpc --no-default-features --features tiny
cargo build --release -p frps -p frpc --no-default-features --features micro
```
Expected: both `Finished`. (`buffer_pool` has no feature gates, so it must compile in every variant.)

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: PASS. Note the 4 new `buffer_pool` tests (`test_default_creates_empty_pool`, `test_reuse_after_release`, `test_pool_does_not_grow_unbounded`, `test_global_pool_works`) and the 5 new `prom` pool-metric assertions all pass.

- [ ] **Step 5: Compat suite (bridge hot-path touched)**

Run: `bash scripts/compat-test.sh --verbose`
Expected: all default tests pass. If a TLS-encrypt test flakes with `got=''`, re-run `--failed` once (known timing race, see memory `compat-test-flaky-tls-encrypt`).

- [ ] **Step 6: Commit**

```bash
git add frp-core/src/buffer_pool.rs frp-core/src/lib.rs frp-core/src/bridge.rs \
  frp-server/src/state.rs frp-server/src/control/mod.rs \
  frp-server/src/dashboard.rs frp-server/src/metrics/prom.rs
git commit -m "perf(server): work-conn pool observability + buffer pool

Recycle 64KB bridge read buffers via a global BufferPool to cut allocator
pressure under connection churn. Add pool hit/miss/drop counters, per-client
pool_size/pending_requests, idle-conn expiry, 5 Prometheus gauges, and
dashboard/API fields.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Land client `service.rs` extraction (frp-client)

Verify the already-written `run()` helper extraction and commit. **No code change** beyond what is already in the working tree.

**Files (already modified, uncommitted on `main`):**
- Modify: `frp-client/src/service.rs` (extracted `spawn_health_checks`, `spawn_admin_server`, `handle_nat_hole_client` out of `run()`)

**Interfaces:**
- Produces: `Service::spawn_health_checks(&self, proxies, health_tx, health_cancels)` (async), `Service::spawn_admin_server(&self, reload_tx, stop_tx)`, `Service::handle_nat_hole_client(&self, ...)` (async). Internal to frp-client; no other unit consumes.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: land-client-extraction
```

- [ ] **Step 2: Build**

Run: `cargo build -p frpc`
Expected: `Finished`.

- [ ] **Step 3: Confirm no behavior drift in unused bindings**

The diff renamed `reload_tx`→`_reload_tx` and `stop_tx`→`_stop_tx` at the call site because they are now passed into helpers. Verify no `unused variable` warning:
Run: `cargo build -p frpc 2>&1 | grep -i "warning: unused" || echo "no unused warnings"`
Expected: `no unused warnings`.

- [ ] **Step 4: Tests + XTCP compat**

Run: `cargo test --workspace`
Expected: PASS.
Run: `bash scripts/compat-test.sh --verbose`
Expected: PASS. If Go frp source build is present locally, run the guarded XTCP matrix (touched by `handle_nat_hole_client`): `GO_FRP_XTCP=1 bash scripts/compat-test.sh --verbose` — otherwise note it is CI-skipped and rely on the daily `xtcp-compat.yml`.

- [ ] **Step 5: Commit**

```bash
git add frp-client/src/service.rs
git commit -m "refactor(client): extract run() helpers

Pull spawn_health_checks, spawn_admin_server, and handle_nat_hole_client out of
the oversized run() method. Pure code move, no behavior change.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Bridge loop dedup (frp-core/bridge.rs)

Remove the duplicated compress / decompress match blocks (5 sites) by extracting three small pure helpers. **Do NOT unify the loop structure, limiter placement, tracing, tail-flush, or shutdown logic** — those diverge across the three bridge fns and unifying them risks the data plane for marginal gain (YAGNI + risk).

**Files:**
- Modify: `frp-core/src/bridge.rs`
- Test: `frp-core/src/bridge.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces (module-private):
  - `fn compress_chunk(payload: &[u8], use_compression: bool) -> Option<Vec<u8>>` — `None` means compression error, caller breaks.
  - `fn make_decompressor(use_compression: bool) -> Option<encryption::SnappyDecompressor>`
  - `fn decompress_chunk(dec: &mut Option<encryption::SnappyDecompressor>, data: &[u8]) -> Option<Vec<u8>>` — `None` means decompress error, caller breaks.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: bridge-dedup
```

- [ ] **Step 2: Write failing unit tests for the helpers**

Add to `frp-core/src/bridge.rs` `mod tests`:

```rust
#[test]
fn test_compress_chunk_identity_when_disabled() {
    let out = compress_chunk(b"hello", false).unwrap();
    assert_eq!(out, b"hello");
}

#[test]
fn test_compress_decompress_roundtrip() {
    let original = b"AAAA".repeat(64);
    let compressed = compress_chunk(&original, true).expect("compress ok");
    let mut dec = make_decompressor(true);
    let out = decompress_chunk(&mut dec, &compressed).expect("decompress ok");
    assert_eq!(out, original);
}

#[test]
fn test_decompress_chunk_identity_when_none() {
    let mut dec: Option<encryption::SnappyDecompressor> = None;
    let out = decompress_chunk(&mut dec, b"raw").unwrap();
    assert_eq!(out, b"raw");
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p frp-core compress_chunk decompress`
Expected: FAIL — `cannot find function compress_chunk` / `make_decompressor` / `decompress_chunk`.

- [ ] **Step 4: Add the three helpers**

Insert above `bridge_encrypted_io` (top of `frp-core/src/bridge.rs`, after the `use` block):

```rust
/// Compress a plaintext chunk when compression is enabled, else copy it.
/// Returns `None` on compression failure — the caller should break its loop.
#[inline]
fn compress_chunk(payload: &[u8], use_compression: bool) -> Option<Vec<u8>> {
    if use_compression {
        encryption::compress(payload).ok()
    } else {
        Some(payload.to_vec())
    }
}

/// Build a streaming Snappy decompressor when compression is enabled and the
/// `compression` feature is present; otherwise `None` (plaintext passthrough).
#[inline]
fn make_decompressor(use_compression: bool) -> Option<encryption::SnappyDecompressor> {
    #[cfg(feature = "compression")]
    {
        if use_compression {
            Some(encryption::SnappyDecompressor::new())
        } else {
            None
        }
    }
    #[cfg(not(feature = "compression"))]
    {
        let _ = use_compression;
        None
    }
}

/// Feed a chunk through the decompressor if present, else copy it.
/// Returns `None` on decompress error — the caller should break its loop.
#[inline]
fn decompress_chunk(
    dec: &mut Option<encryption::SnappyDecompressor>,
    data: &[u8],
) -> Option<Vec<u8>> {
    match dec {
        Some(d) => d.feed(data).ok(),
        None => Some(data.to_vec()),
    }
}
```

- [ ] **Step 5: Replace the compress sites**

In `bridge_encrypted` `user_to_work` (currently the `let processed = if use_compression { match encryption::compress(payload) {...} } else { payload.to_vec() };` block) and the identical block in `bridge_plain` `user_to_work`, replace with:

```rust
            let processed = match compress_chunk(payload, use_compression) {
                Some(p) => p,
                None => break,
            };
```

- [ ] **Step 6: Replace the decompressor construction**

In both `bridge_encrypted` `work_to_user` and `bridge_plain` `work_to_user`, replace the `#[cfg(feature = "compression")] let mut decompressor = ...; #[cfg(not(...))] let mut decompressor: Option<...> = None;` block with:

```rust
        let mut decompressor = make_decompressor(use_compression);
```

- [ ] **Step 7: Replace the decompress-chunk sites**

In `bridge_encrypted` `work_to_user`, replace the `let plaintext = if let Some(ref mut dec) = decompressor { match dec.feed(decrypted) {...} } else { decrypted.to_vec() };` block with:

```rust
            let plaintext = match decompress_chunk(&mut decompressor, decrypted) {
                Some(p) => p,
                None => break,
            };
```

In `bridge_plain` `work_to_user`, replace the analogous block (`dec.feed(&buf.data()[..n])` / `buf.data()[..n].to_vec()`) with:

```rust
            let plaintext = match decompress_chunk(&mut decompressor, &buf.data()[..n]) {
                Some(p) => p,
                None => break,
            };
```

**Leave unchanged:** the tail-flush blocks (`dec.flush()` → write to `user_w`), all limiter `consume()` calls, all `tracing::` lines, the `shutdown()` calls, and `bridge_plain_rate_limited` entirely (no compression there).

- [ ] **Step 8: Run tests**

Run: `cargo test -p frp-core`
Expected: PASS — new helper tests plus the existing `test_bridge_plain_bidirectional`, `test_bridge_plain_pre_read`, and the three `test_encrypted_bridge_*_smoke` tests.

- [ ] **Step 9: Feature-matrix build (decompress cfg gate)**

Run: `cargo build --release -p frps -p frpc --no-default-features --features micro`
Expected: `Finished` — confirms `make_decompressor`'s `not(feature="compression")` arm compiles (micro drops compression).

- [ ] **Step 10: Compat suite (data plane)**

Run: `bash scripts/compat-test.sh --verbose`
Expected: PASS on the plain / encrypt / compress matrix.

- [ ] **Step 11: Commit**

```bash
git add frp-core/src/bridge.rs
git commit -m "refactor(core): extract bridge compress/decompress helpers

Collapse 5 duplicated compress/decompress match blocks in bridge_encrypted and
bridge_plain into compress_chunk/make_decompressor/decompress_chunk. Loop
structure, limiters, tracing, tail-flush, and shutdown untouched. No wire change.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Work-conn pool dedup (frp-server/control/mod.rs)

Collapse the repeated `pop_front → hit → assign / else → miss → ReqWorkConn → queue` blocks into one `assign_or_queue` helper. Apply only to the common proxy/visitor sites; leave the `NatHoleSid` and UDP paths specialized.

**Files:**
- Modify: `frp-server/src/control/mod.rs`

**Interfaces:**
- Consumes: `PoolEntry`, `PendingRequest`, `PoolStats` (Task 1), `bridge::assign_work_to_proxy`, `write_ctl_msg`.
- Produces (module-private):
  `async fn assign_or_queue<W: AsyncWriteExt + Unpin>(work_pool: &mut VecDeque<PoolEntry>, pending_requests: &mut VecDeque<PendingRequest>, pool_stats: &PoolStats, state: &Arc<AppState>, writer: &mut W, req: PendingRequest, enc_key: [u8; 16], v2: bool) -> Result<(), ()>` — `Err(())` means the `ReqWorkConn` write failed and the caller must `break`.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: control-pool-dedup
```

- [ ] **Step 2: Add the helper**

Add near the top of `frp-server/src/control/mod.rs` (after the `PoolEntry`/`PendingRequest` struct definitions), importing `Ordering` if not already in scope:

```rust
/// Assign `req` to a pooled work connection if one is available (pool hit),
/// otherwise record a miss, send `ReqWorkConn`, and queue the request.
/// Returns `Err(())` if the `ReqWorkConn` write failed — caller must break.
#[allow(clippy::too_many_arguments)]
async fn assign_or_queue<W>(
    work_pool: &mut VecDeque<PoolEntry>,
    pending_requests: &mut VecDeque<PendingRequest>,
    pool_stats: &crate::state::PoolStats,
    state: &Arc<AppState>,
    writer: &mut W,
    req: PendingRequest,
    enc_key: [u8; 16],
    v2: bool,
) -> Result<(), ()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    use std::sync::atomic::Ordering;
    if let Some(entry) = work_pool.pop_front() {
        state.pool_hits.fetch_add(1, Ordering::Relaxed);
        pool_stats.pool_size.store(work_pool.len() as i64, Ordering::Relaxed);
        bridge::assign_work_to_proxy(entry.conn, req, enc_key, state.clone(), v2).await;
    } else {
        state.pool_misses.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = write_ctl_msg(writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {}), v2).await {
            warn!(error = %e, "Failed to send ReqWorkConn: {}", e);
            return Err(());
        }
        pending_requests.push_back(req);
        pool_stats.pending_requests.store(pending_requests.len() as i64, Ordering::Relaxed);
    }
    Ok(())
}
```

- [ ] **Step 3: Replace the common sites**

For each `if let Some(entry) = work_pool.pop_front() { ... } else { ... ReqWorkConn ... pending_requests.push_back(...) }` block **whose else-branch sends `ReqWorkConn` and queues a `PendingRequest`** — i.e. the STCP `VisitorConn` handler and the `ProxyUserConn`/`VisitorConn` target-proxy handler — replace the whole if/else with (adapting the `PendingRequest { .. }` literal to that site's fields):

```rust
                        if assign_or_queue(
                            &mut work_pool, &mut pending_requests, &pool_stats, &state,
                            &mut writer,
                            PendingRequest { /* site-specific fields, unchanged */ },
                            reloadable.encryption_key, v2,
                        ).await.is_err() { break; }
```

The site-specific per-site `debug!()` text (e.g. "No pooled work conn for STCP") is dropped in favor of the helper's uniform `warn!` on write failure — logs only, no behavior change.

- [ ] **Step 4: Leave specialized paths untouched**

Do NOT modify:
- the `NatHoleSidOnWorkConn` handler (its pool hit sends `StartWorkConn`+`NatHoleSid`, not `assign_work_to_proxy`);
- the UDP (`UdpNeedsWorkConn`) path;
- the `NewWorkConn` drain that does `pending_requests.pop_front()` (opposite direction).

- [ ] **Step 5: Build + clippy**

Run: `cargo build -p frps && cargo clippy -p frps`
Expected: `Finished`, no new warnings.

- [ ] **Step 6: Tests + compat**

Run: `cargo test --workspace`
Expected: PASS.
Run: `bash scripts/compat-test.sh --verbose`
Expected: PASS (STCP / TCP / HTTP proxy paths exercise the changed sites).

- [ ] **Step 7: Commit**

```bash
git add frp-server/src/control/mod.rs
git commit -m "refactor(server): extract assign_or_queue for work-conn pool

Collapse the repeated pop_front/hit/assign vs miss/ReqWorkConn/queue blocks in
the control select loop into one helper. NatHoleSid and UDP paths stay
specialized. Counter and pool_stats updates preserved.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Dashboard handler dedup (frp-server/dashboard.rs)

`handle_status` and `handle_serverinfo` are byte-identical. Extract one builder both call.

**Files:**
- Modify: `frp-server/src/dashboard.rs`

**Interfaces:**
- Produces (module-private): `async fn build_status_response(state: &Arc<AppState>) -> StatusResponse`.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: dashboard-dedup
```

- [ ] **Step 2: Add the builder**

Insert above `handle_status` in `frp-server/src/dashboard.rs`:

```rust
/// Build the shared status payload for `/api/status` and its Go-frp-compat
/// alias `/api/serverinfo`.
async fn build_status_response(state: &Arc<AppState>) -> StatusResponse {
    let uptime = state.dashboard_start.elapsed().as_secs();
    let ctl_map = state.run_id_to_ctl_tx.read().await;
    let client_count = ctl_map.len();
    let proxies = state.proxy_manager.list().await;

    let (total_pool_size, total_pending) = ctl_map.values().fold((0i64, 0i64), |(s, p), ctl| {
        (s + ctl.pool_stats.pool_size.load(Ordering::Relaxed),
         p + ctl.pool_stats.pending_requests.load(Ordering::Relaxed))
    });
    drop(ctl_map);

    StatusResponse {
        version: frp_core::VERSION.to_string(),
        uptime_secs: uptime,
        client_count,
        proxy_count: proxies.len(),
        pool_hits: state.pool_hits.load(Ordering::Relaxed),
        pool_misses: state.pool_misses.load(Ordering::Relaxed),
        pool_drops: state.pool_drops.load(Ordering::Relaxed),
        pool_size: total_pool_size,
        pool_pending: total_pending,
    }
}
```

- [ ] **Step 3: Rewrite both handlers to delegate**

```rust
async fn handle_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(build_status_response(&state).await)
}

/// GET /api/serverinfo — Go frp compat alias for /api/status.
async fn handle_serverinfo(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(build_status_response(&state).await)
}
```

- [ ] **Step 4: Build + test**

Run: `cargo build -p frps && cargo test -p frps`
Expected: `Finished`, PASS. Both endpoints still serialize the identical `StatusResponse` shape.

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/dashboard.rs
git commit -m "refactor(server): share build_status_response across status endpoints

handle_status and handle_serverinfo were byte-identical; both now delegate to
one builder. Output unchanged.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: AppState grouping (frp-server/state.rs)

Group cohesive `AppState` fields into small sub-structs. Moderate scope only (YAGNI) — three groups: pool metrics, OIDC, XTCP. Mechanical accessor churn across the server crate; no logic change. Do this **last** — it renames field access sites that earlier tasks touch.

**Files:**
- Modify: `frp-server/src/state.rs` (define sub-structs, update `AppState` fields + `AppState::new`)
- Modify: every server file reading the moved fields (found via grep in Step 3)

**Interfaces:**
- Produces:
  - `pub struct PoolMetrics { pub hits: AtomicU64, pub misses: AtomicU64, pub drops: AtomicU64, pub idle_timeout: Duration }`
  - `pub struct OidcState { pub verifier: Option<Arc<OidcVerifier>>, pub subjects: Arc<RwLock<HashMap<String, String>>> }`
  - `pub struct XtcpState { pub nat_hole: Arc<Controller>, pub sk_index: Arc<RwLock<HashMap<String, String>>> }`
  - `AppState.pool: PoolMetrics`, `AppState.oidc: OidcState`, `AppState.xtcp: XtcpState`
- Migration: `state.pool_hits` → `state.pool.hits`, `pool_misses` → `pool.misses`, `pool_drops` → `pool.drops`, `pool_idle_timeout` → `pool.idle_timeout`, `oidc_verifier` → `oidc.verifier`, `oidc_subjects` → `oidc.subjects`, `nat_hole` → `xtcp.nat_hole`, `sk_index` → `xtcp.sk_index`.

- [ ] **Step 1: Worktree**

```bash
# via EnterWorktree tool, name: appstate-grouping
```

- [ ] **Step 2: Define sub-structs and update AppState**

In `frp-server/src/state.rs`, add before `pub struct AppState`:

```rust
/// Aggregate work-conn pool metrics, read by Prometheus / admin API.
#[derive(Debug, Default)]
pub struct PoolMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub drops: AtomicU64,
    /// Idle timeout for pooled work conns. `Duration::ZERO` = disabled.
    pub idle_timeout: Duration,
}

/// OIDC verification state.
pub struct OidcState {
    pub verifier: Option<Arc<OidcVerifier>>,
    pub subjects: Arc<RwLock<HashMap<String, String>>>,
}

/// XTCP NAT-hole-punch coordination state.
pub struct XtcpState {
    pub nat_hole: Arc<Controller>,
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
}
```

Replace the individual `AppState` fields (`sk_index`, `oidc_verifier`, `oidc_subjects`, `nat_hole`, `pool_hits`, `pool_misses`, `pool_drops`, `pool_idle_timeout`) with:

```rust
    pub pool: PoolMetrics,
    pub oidc: OidcState,
    pub xtcp: XtcpState,
```

- [ ] **Step 3: Update `AppState::new`**

Replace the corresponding initializers with:

```rust
            pool: PoolMetrics::default(),
            oidc: OidcState {
                verifier: oidc_verifier,
                subjects: Arc::new(RwLock::new(HashMap::new())),
            },
            xtcp: XtcpState {
                nat_hole: Arc::new(Controller::new(Duration::from_secs(
                    nat_hole_analysis_data_reserve_hours.saturating_mul(3600),
                ))),
                sk_index: Arc::new(RwLock::new(HashMap::new())),
            },
```

(`PoolMetrics::default()` gives `idle_timeout = Duration::ZERO` — matches the old default.)

- [ ] **Step 4: Find all access sites**

Run:
```bash
grep -rn "\.pool_hits\|\.pool_misses\|\.pool_drops\|\.pool_idle_timeout\|\.oidc_verifier\|\.oidc_subjects\|\.nat_hole\|\.sk_index" frp-server/src
```
Expected: a list across `control/mod.rs`, `service.rs`, `dashboard.rs`, `metrics/prom.rs`, `handlers.rs`, `nathole/*`, and any reload path. This is the exact churn set.

- [ ] **Step 5: Rewrite each access site**

Apply the migration map from Interfaces to every hit from Step 4 (`state.pool_hits` → `state.pool.hits`, etc.). Note the `pool_stats` (per-client `ControlTx.pool_stats`) is a **separate** type and is NOT renamed — only `AppState`-level fields move.

- [ ] **Step 6: Build workspace + feature matrix**

Run:
```bash
cargo build --workspace
cargo build --release -p frps -p frpc --no-default-features --features tiny
cargo build --release -p frps -p frpc --no-default-features --features micro
```
Expected: all `Finished`. (OIDC is feature-gated; confirm `oidc.verifier` access sites are behind the same `#[cfg(feature = "oidc")]` gates they were before — do not un-gate.)

- [ ] **Step 7: Tests + compat**

Run: `cargo test --workspace`
Expected: PASS.
Run: `bash scripts/compat-test.sh --verbose`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add frp-server/src
git commit -m "refactor(server): group AppState pool/oidc/xtcp fields into sub-structs

Collapse eight loose AppState fields into PoolMetrics, OidcState, and XtcpState
for cohesion. Mechanical accessor rename across the server crate; no logic or
wire change.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** Every spec unit maps to a task — Unit 1→Task 1, Unit 2→Task 2, Unit 3→Task 3, Unit 4→Task 4, Unit 5→Task 5, Unit 6→Task 6. Cross-cutting constraints (no new deps, tiny/micro build, compat green, worktree per unit) are in Global Constraints and repeated in the relevant task steps.

**Placeholder scan:** No "TBD"/"TODO". The one intentional literal placeholder — `PendingRequest { /* site-specific fields, unchanged */ }` in Task 4 Step 3 — is explicit: the executor copies the existing struct literal verbatim from each site (fields differ per site and must not change).

**Type consistency:** `PoolGuard` methods (`acquire`/`as_mut_slice`/`data`) match Task 1's produced interface and Task 3's usage. `PoolStats` (per-client, `pool_size`/`pending_requests`) is kept distinct from `PoolMetrics` (AppState-level, `hits`/`misses`/`drops`/`idle_timeout`) — Task 6 Step 5 explicitly calls out not renaming `pool_stats`. `assign_or_queue` signature in Task 4 matches its call in Step 3. `build_status_response` returns `StatusResponse`, consumed by both handlers in Task 5 Step 3.
