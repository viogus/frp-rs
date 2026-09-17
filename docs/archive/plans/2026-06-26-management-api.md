# Management REST API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HTTP REST management API to frps and frpc, matching Go frp v0.69.1, with per-proxy traffic metrics via atomic counters in bridge layer.

**Architecture:** `ProxyMetrics` (atomics) + `ProxyMetricsRegistry` in frp-core. Bridge functions accept optional `Arc<ProxyMetrics>` param to count bytes inline. `ConnGuard` tracks connection lifecycle. Shared Basic Auth middleware in frp-core. frpc gets admin HTTP server on separate port. frps dashboard gets proxy detail + traffic routes.

**Tech Stack:** Rust, tokio, axum 0.8.9, atomics (AtomicU64/AtomicI64), Basic Auth

**Spec:** `docs/superpowers/specs/2026-06-26-management-api-design.md`

---

## File Map

| File | Change | Responsibility |
|------|--------|---------------|
| `frp-core/src/metrics.rs` | NEW | `ProxyMetrics`, `ProxyMetricsRegistry`, `ConnGuard` |
| `frp-core/src/admin_auth.rs` | NEW | `apply_admin_auth()` — Basic Auth axum layer |
| `frp-core/src/bridge.rs` | MODIFY | Add optional `metrics` param to bridge functions |
| `frp-core/src/lib.rs` | MODIFY | Export `metrics`, `admin_auth` modules |
| `frp-core/src/config.rs` | MODIFY | Add `web_server` field to `ClientConfig` |
| `frp-core/Cargo.toml` | MODIFY | Add `axum` dep |
| `frp-server/src/control/bridge.rs` | MODIFY | Pass metrics registry + ConnGuard into bridge calls |
| `frp-server/src/control/mod.rs` | MODIFY | Update call sites with `state` param |
| `frp-server/src/dashboard.rs` | MODIFY | New routes, auth, expanded proxy list |
| `frp-server/src/service.rs` | MODIFY | Add `ProxyMetricsRegistry` to `AppState`; update `run_dashboard` call |
| `frp-client/src/admin.rs` | NEW | frpc admin HTTP server (5 endpoints) |
| `frp-client/src/service.rs` | MODIFY | Spawn admin server, `try_reload()`, pass metrics to bridge |
| `frp-client/src/proxy.rs` | MODIFY | Pass metrics into bridge calls; count copy_bidirectional |
| `frp-client/src/lib.rs` | MODIFY | Export `admin` module |
| `frp-client/Cargo.toml` | MODIFY | Add `axum` dep |
| `frpc/src/main.rs` | MODIFY | Pass `config_file` to `Service::new()` |

---

### Task 1: ProxyMetrics module

**Files:** Create `frp-core/src/metrics.rs`, Modify `frp-core/src/lib.rs`

- [ ] **Step 1: Write `frp-core/src/metrics.rs`**

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Per-proxy traffic counters using atomics for lock-free reads.
#[derive(Debug)]
pub struct ProxyMetrics {
    pub name: String,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub current_conns: AtomicI64,
    pub total_conns: AtomicU64,
}

impl ProxyMetrics {
    pub fn new(name: String) -> Self {
        Self {
            name,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            current_conns: AtomicI64::new(0),
            total_conns: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            current_conns: self.current_conns.load(Ordering::Relaxed),
            total_conns: self.total_conns.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub current_conns: i64,
    pub total_conns: u64,
}

#[derive(Debug, Default)]
pub struct ProxyMetricsRegistry {
    metrics: RwLock<HashMap<String, Arc<ProxyMetrics>>>,
}

impl ProxyMetricsRegistry {
    pub fn new() -> Self {
        Self { metrics: RwLock::new(HashMap::new()) }
    }

    pub async fn get_or_create(&self, name: &str) -> Arc<ProxyMetrics> {
        let mut map = self.metrics.write().await;
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(ProxyMetrics::new(name.to_string())))
            .clone()
    }

    pub async fn get(&self, name: &str) -> Option<Arc<ProxyMetrics>> {
        self.metrics.read().await.get(name).cloned()
    }

    pub async fn remove(&self, name: &str) {
        self.metrics.write().await.remove(name);
    }
}

/// Connection guard: +1 current_conns + total_conns on creation,
/// -1 current_conns on drop.
pub struct ConnGuard {
    metrics: Arc<ProxyMetrics>,
}

impl ConnGuard {
    pub fn new(metrics: Arc<ProxyMetrics>) -> Self {
        metrics.current_conns.fetch_add(1, Ordering::Relaxed);
        metrics.total_conns.fetch_add(1, Ordering::Relaxed);
        Self { metrics }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_counts() {
        let m = ProxyMetrics::new("t".into());
        m.bytes_in.fetch_add(100, Ordering::Relaxed);
        m.bytes_out.fetch_add(200, Ordering::Relaxed);
        let s = m.snapshot();
        assert_eq!(s.bytes_in, 100);
        assert_eq!(s.bytes_out, 200);
    }

    #[tokio::test]
    async fn test_registry_reuses_metrics() {
        let reg = ProxyMetricsRegistry::new();
        let m1 = reg.get_or_create("p1").await;
        m1.bytes_in.fetch_add(10, Ordering::Relaxed);
        let m2 = reg.get_or_create("p1").await;
        assert_eq!(m2.snapshot().bytes_in, 10);
    }

    #[tokio::test]
    async fn test_registry_remove() {
        let reg = ProxyMetricsRegistry::new();
        reg.get_or_create("p1").await;
        assert!(reg.get("p1").await.is_some());
        reg.remove("p1").await;
        assert!(reg.get("p1").await.is_none());
    }

    #[test]
    fn test_conn_guard_lifecycle() {
        let m = Arc::new(ProxyMetrics::new("g".into()));
        assert_eq!(m.snapshot().current_conns, 0);
        {
            let _g = ConnGuard::new(m.clone());
            assert_eq!(m.snapshot().current_conns, 1);
            assert_eq!(m.snapshot().total_conns, 1);
        }
        assert_eq!(m.snapshot().current_conns, 0);
        assert_eq!(m.snapshot().total_conns, 1);
    }
}
```

- [ ] **Step 2: Register in `frp-core/src/lib.rs`**

Add after `pub mod bandwidth;`:
```rust
pub mod bandwidth;
pub mod metrics;
pub mod args;
```

- [ ] **Step 3: Build and test**

```bash
cargo test -p frp-core -- metrics
```
Expected: 4 tests pass.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/metrics.rs frp-core/src/lib.rs
git commit -m "feat: add ProxyMetrics module with atomics, registry, ConnGuard"
```

---

### Task 2: Add metrics param to bridge functions

**Files:** Modify `frp-core/src/bridge.rs`

- [ ] **Step 1: Add imports and optional metrics param to all bridge functions**

Add at top of `frp-core/src/bridge.rs`:
```rust
use std::sync::Arc;
use std::sync::atomic::Ordering;
```

Change `bridge_encrypted` signature — add last param:
```rust
pub async fn bridge_encrypted(
    ...
    mut read_limiter: Option<&mut BandwidthLimiter>,
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
```

Inside `user_to_work` block, after `Ok(n) =>` reading from `user_r`:
```rust
Ok(n) => {
    if let Some(ref m) = metrics {
        m.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
    }
    n
}
```

Inside `work_to_user` block, after `user_w.write_all(&plaintext).await`:
```rust
if user_w.write_all(&plaintext).await.is_err() { break; }
if let Some(ref m) = metrics {
    m.bytes_out.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
}
if user_w.flush().await.is_err() { break; }
```

Apply same counting pattern to `bridge_plain` and `bridge_plain_rate_limited`.

Change `bridge_plain` signature:
```rust
pub async fn bridge_plain(
    ...
    pre_read: Vec<u8>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
```

Change `bridge_plain_rate_limited` signature:
```rust
pub async fn bridge_plain_rate_limited(
    ...
    mut write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
```

Change `bridge_encrypted_io` signature:
```rust
pub async fn bridge_encrypted_io(
    ...
    read_limiter: Option<&mut BandwidthLimiter>,
    write_limiter: Option<&mut BandwidthLimiter>,
    metrics: Option<Arc<crate::metrics::ProxyMetrics>>,
) {
    let (u_r, u_w) = user.into_split();
    let (w_r, w_w) = work.into_split();
    bridge_encrypted(u_r, u_w, w_r, w_w, key, use_compression, pre_read, read_limiter, write_limiter, metrics).await;
}
```

- [ ] **Step 2: Add `None` at all call sites**

Every call site gets `None` as the last argument (actual metrics passed in later tasks):

In `frp-server/src/control/bridge.rs` — 12 calls in `assign_work_to_proxy`:
- `bridge_encrypted(..., None, None)` → `bridge_encrypted(..., None, None, None)`
- `bridge_plain(..., comp_key, bridge_pre_read)` → `bridge_plain(..., comp_key, bridge_pre_read, None)`

In `frp-client/src/proxy.rs` — `bridge_streams`:
- `bridge_encrypted_io(..., &mut read_lim, &mut write_lim)` → `bridge_encrypted_io(..., &mut read_lim, &mut write_lim, None)`
- `bridge_plain(..., true, Vec::new())` → `bridge_plain(..., true, Vec::new(), None)`
- `bridge_plain_rate_limited(..., &mut read_lim, &mut write_lim)` → `bridge_plain_rate_limited(..., &mut read_lim, &mut write_lim, None)`

- [ ] **Step 3: Build and test**

```bash
cargo build --workspace
cargo test --workspace
```
Expected: builds, all 125+ tests pass.

- [ ] **Step 4: Commit**

```bash
git add frp-core/src/bridge.rs frp-server/src/control/bridge.rs frp-client/src/proxy.rs
git commit -m "feat: add optional metrics counting param to all bridge functions"
```

---

### Task 3: Admin auth middleware

**Files:** Create `frp-core/src/admin_auth.rs`, Modify `frp-core/src/lib.rs`, Modify `frp-core/Cargo.toml`

- [ ] **Step 1: Add axum to frp-core deps**

Edit `frp-core/Cargo.toml` — add after `bytes.workspace = true`:
```toml
axum.workspace = true
```

- [ ] **Step 2: Write `frp-core/src/admin_auth.rs`**

```rust
use axum::{
    extract::Request,
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    http::StatusCode,
    Router,
};
use std::sync::Arc;

#[derive(Clone)]
struct AuthState {
    enabled: bool,
    expected_header: String,
}

/// Apply HTTP Basic Auth middleware to a router.
/// When both `user` and `password` are empty, auth is skipped (pass-through).
pub fn apply_admin_auth(router: Router, user: &str, password: &str) -> Router {
    let enabled = !user.is_empty() || !password.is_empty();
    let expected = if enabled {
        format!(
            "Basic {}",
            data_encoding::BASE64.encode(format!("{}:{}", user, password).as_bytes())
        )
    } else {
        String::new()
    };

    let state = Arc::new(AuthState { enabled, expected_header: expected });

    async fn check_auth(mut req: Request, next: Next) -> Response {
        let state = req.extensions().get::<Arc<AuthState>>().cloned();
        if let Some(s) = state {
            if s.enabled {
                let ok = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == s.expected_header)
                    .unwrap_or(false);
                if !ok {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [("www-authenticate", "Basic realm=\"frp\"")],
                        "Unauthorized",
                    )
                        .into_response();
                }
            }
        }
        next.run(req).await
    }

    router.layer(middleware::from_fn(move |mut req: Request, next: Next| {
        let s = state.clone();
        async move {
            req.extensions_mut().insert(s);
            check_auth(req, next).await
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, body::Body};
    use tower::ServiceExt;

    async fn ok() -> &'static str { "ok" }

    #[tokio::test]
    async fn test_auth_disabled_when_empty() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "", "");
        let resp = app.oneshot(
            axum::http::Request::builder().uri("/api/test").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_rejects_no_header() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let resp = app.oneshot(
            axum::http::Request::builder().uri("/api/test").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_accepts_valid() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let creds = data_encoding::BASE64.encode(b"admin:secret");
        let resp = app.oneshot(
            axum::http::Request::builder()
                .uri("/api/test")
                .header("Authorization", format!("Basic {}", creds))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_rejects_wrong_password() {
        let app = apply_admin_auth(Router::new().route("/api/test", get(ok)), "admin", "secret");
        let creds = data_encoding::BASE64.encode(b"admin:wrong");
        let resp = app.oneshot(
            axum::http::Request::builder()
                .uri("/api/test")
                .header("Authorization", format!("Basic {}", creds))
                .body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
```

- [ ] **Step 3: Register in lib.rs**

Add after `pub mod metrics;`:
```rust
pub mod admin_auth;
```

- [ ] **Step 4: Build and test**

```bash
cargo test -p frp-core -- admin_auth
```
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/admin_auth.rs frp-core/src/lib.rs frp-core/Cargo.toml
git commit -m "feat: add admin Basic Auth middleware for axum"
```

---

### Task 4: Wire metrics into frps bridge + AppState

**Files:** Modify `frp-server/src/service.rs`, `frp-server/src/control/bridge.rs`, `frp-server/src/control/mod.rs`

- [ ] **Step 1: Add ProxyMetricsRegistry to AppState**

In `frp-server/src/service.rs`:

Add import:
```rust
use frp_core::metrics::ProxyMetricsRegistry;
```

Add field to `AppState` after `pub tcpmux_manager`:
```rust
pub tcpmux_manager: Arc<TcpMuxManager>,
/// Per-proxy traffic metrics for dashboard API.
pub proxy_metrics: Arc<ProxyMetricsRegistry>,
```

Init in `AppState::new()` after `tcpmux_manager`:
```rust
tcpmux_manager: Arc::new(TcpMuxManager::new()),
proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
```

- [ ] **Step 2: Pass metrics + ConnGuard in control/bridge.rs**

In `frp-server/src/control/bridge.rs`:

Add imports:
```rust
use std::sync::Arc;
use frp_core::metrics::ConnGuard;
use crate::service::AppState;
```

Change signature:
```rust
pub(crate) async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
    state: Arc<AppState>,
) {
```

After `info!("Bridging...")` but before `let pre_read = req.pre_read;`:
```rust
let proxy_name = req.proxy_name.clone();
let metrics = state.proxy_metrics.get_or_create(&proxy_name).await;
let _guard = ConnGuard::new(metrics.clone());
```

In ALL 12 bridge call branches (6 encrypted + 6 plain), replace `None` with `Some(metrics.clone())`:
- `bridge_encrypted(..., None, None, None)` → `bridge_encrypted(..., None, None, Some(metrics.clone()))`
- `bridge_plain(..., comp_key, bridge_pre_read, None)` → `bridge_plain(..., comp_key, bridge_pre_read, Some(metrics.clone()))`

- [ ] **Step 3: Update call sites in control/mod.rs**

All 4 `bridge::assign_work_to_proxy(...)` calls get `state.clone()` as 4th arg:

Line ~200:
```rust
bridge::assign_work_to_proxy(stream, req, state.reloadable.read().await.encryption_key, state.clone()).await;
```
Repeat for lines ~218, ~272, ~369.

- [ ] **Step 4: Build and test**

```bash
cargo build -p frp-server
cargo test -p frp-server
```

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/service.rs frp-server/src/control/bridge.rs frp-server/src/control/mod.rs
git commit -m "feat: wire ProxyMetrics counting into frps bridge"
```

---

### Task 5: Wire metrics into frpc bridge

**Files:** Modify `frp-client/src/proxy.rs`, `frp-client/src/service.rs`

- [ ] **Step 1: Add proxy_metrics to Service**

In `frp-client/src/service.rs`:

Add import:
```rust
use frp_core::metrics::ProxyMetricsRegistry;
```

Add field to `Service`:
```rust
oidc_client: Option<Arc<OidcClient>>,
proxy_metrics: Arc<ProxyMetricsRegistry>,
```

Init in `Service::new()`:
```rust
proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
```

Add accessor:
```rust
pub fn proxy_metrics(&self) -> &Arc<ProxyMetricsRegistry> {
    &self.proxy_metrics
}
```

- [ ] **Step 2: Add proxy_metrics to spawn_work_conn params**

Add param after `udp_enc_cfg`:
```rust
fn spawn_work_conn(
    ...
    udp_enc_cfg: Arc<tokio::sync::Mutex<HashMap<String, (bool, bool)>>>,
    proxy_metrics: Arc<ProxyMetricsRegistry>,
) {
```

Clone at top:
```rust
let repl_proxy_metrics = proxy_metrics.clone();
```

Update all 3 call sites to pass `self.proxy_metrics.clone()` or `repl_proxy_metrics.clone()`.

Replenishment call passes `repl_proxy_metrics`.

- [ ] **Step 3: Wire metrics in bridge_streams**

In `frp-client/src/proxy.rs`:

Add imports:
```rust
use std::sync::Arc;
use frp_core::metrics::{ProxyMetricsRegistry, ConnGuard};
use std::sync::atomic::Ordering;
```

Add param to `bridge_streams`:
```rust
pub async fn bridge_streams(
    ...
    bandwidth_limit_mode: &str,
    metrics: Arc<ProxyMetricsRegistry>,
) {
```

At top of function body:
```rust
let proxy_metrics = metrics.get_or_create(name).await;
let _guard = ConnGuard::new(proxy_metrics.clone());
```

Update bridge calls:
- `bridge_encrypted_io(..., None)` → `bridge_encrypted_io(..., Some(proxy_metrics.clone()))`
- `bridge_plain(..., None)` → `bridge_plain(..., Some(proxy_metrics.clone()))`
- `bridge_plain_rate_limited(..., None)` → `bridge_plain_rate_limited(..., Some(proxy_metrics.clone()))`

For `copy_bidirectional` path, count from return values:
```rust
match tokio::io::copy_bidirectional(&mut local, &mut work).await {
    Ok((to_work, to_local)) => {
        proxy_metrics.bytes_in.fetch_add(to_local, Ordering::Relaxed);
        proxy_metrics.bytes_out.fetch_add(to_work, Ordering::Relaxed);
        ...
    }
```

Update `bridge_streams` call in `spawn_work_conn` to pass `proxy_metrics.clone()`.

- [ ] **Step 4: Build and test**

```bash
cargo build -p frp-client
cargo test -p frp-client
```

- [ ] **Step 5: Commit**

```bash
git add frp-client/src/proxy.rs frp-client/src/service.rs
git commit -m "feat: wire ProxyMetrics counting into frpc bridge"
```

---

### Task 6: frps dashboard expansion

**Files:** Modify `frp-server/src/dashboard.rs`, `frp-server/src/service.rs`

- [ ] **Step 1: Rewrite dashboard.rs**

Full replacement — adds `/api/proxy/:name`, `/api/proxy/:name/traffic`, auth middleware, expanded proxy list fields, enhanced HTML. See `frp-server/src/dashboard.rs` for current content.

Key changes:
1. Add `MetricsSnapshot`, `ProxyDetail`, `ErrorResponse` types
2. Add `handle_proxy_detail`, `handle_proxy_traffic` handlers
3. Expand `ProxyEntry` with `status`, `traffic_in`, `traffic_out`
4. Expand `handle_proxies` to read from `proxy_metrics` registry
5. Apply `apply_admin_auth` to API routes (not `/`)
6. Update `run_dashboard` signature to accept `auth_user: String, auth_password: String`

- [ ] **Step 2: Update run_dashboard call in service.rs**

```rust
let dash_user = self.cfg.web_server.user.clone();
let dash_pwd = self.cfg.web_server.password.clone();
if let Err(e) = crate::dashboard::run_dashboard(dash_addr, dash_state, dash_user, dash_pwd).await {
```

- [ ] **Step 3: Build and test**

```bash
cargo build -p frp-server
cargo test -p frp-server
```

- [ ] **Step 4: Commit**

```bash
git add frp-server/src/dashboard.rs frp-server/src/service.rs
git commit -m "feat: expand frps dashboard with proxy detail, traffic stats, auth"
```

---

### Task 7: frpc admin HTTP server

**Files:** Create `frp-client/src/admin.rs`, Modify `frp-client/src/service.rs`, `frp-client/src/lib.rs`, `frp-client/Cargo.toml`, `frp-core/src/config.rs`, `frpc/src/main.rs`

- [ ] **Step 1: Add axum to frp-client + web_server to ClientConfig**

`frp-client/Cargo.toml`:
```toml
axum.workspace = true
```

`frp-core/src/config.rs` — add to `ClientConfig` after `visitors`:
```rust
#[serde(default)]
pub web_server: WebServerConfig,
```
And in `Default` impl:
```rust
web_server: WebServerConfig::default(),
```

- [ ] **Step 2: Write `frp-client/src/admin.rs`**

New module with:
- `AdminState` struct (Clone, with proxy_metrics, proxies, reload_tx, stop_tx, config_path)
- `ReloadRequest` struct (strict bool, reply oneshot)
- `handle_status` — returns proxies grouped by type (Go frp format)
- `handle_reload` — sends ReloadRequest on channel, waits 30s
- `handle_stop` — sends () on stop_tx, returns "stop success"
- `handle_get_config` — reads config file from disk
- `handle_put_config` — writes config file, triggers reload
- `run_admin_server` — builds Router with all 5 routes + auth, starts axum::serve

- [ ] **Step 3: Export module + integrate into Service**

`frp-client/src/lib.rs`:
```rust
pub mod admin;
```

`frp-client/src/service.rs`:
- Add `config_file: Option<String>` to `Service`
- Add `config_file` param to `Service::new()`
- In `run()`: spawn admin server if `web_server.port > 0`
- Add `reload_rx` and `stop_rx` to select loop
- Add `try_reload()` method (diff proxies, log changes, return summary)
- Add `AtomicBool` shutdown flag for clean stop

- [ ] **Step 4: Update frpc/src/main.rs**

```rust
// Single config mode:
let service = match Service::new(cfg, Some(cli.config.clone())).await {

// Config directory mode:
let service = match Service::new(cfg, Some(path_str.clone())).await {
```

- [ ] **Step 5: Build full workspace**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

- [ ] **Step 6: Commit**

```bash
git add frp-client/src/admin.rs frp-client/src/service.rs frp-client/src/lib.rs frp-client/Cargo.toml frpc/src/main.rs frp-core/src/config.rs
git commit -m "feat: add frpc admin HTTP server with status/reload/stop/config endpoints"
```

---

### Task 8: Integration tests + compat verification

- [ ] **Step 1: Add data-layer tests**

Create `frp-server/tests/api_tests.rs`:
```rust
use std::sync::Arc;
use std::sync::atomic::Ordering;
use frp_core::metrics::{ProxyMetricsRegistry, ConnGuard};

#[tokio::test]
async fn test_metrics_snapshot_after_counting() {
    let reg = ProxyMetricsRegistry::new();
    let m = reg.get_or_create("ssh").await;
    m.bytes_in.fetch_add(1024, Ordering::Relaxed);
    m.bytes_out.fetch_add(512, Ordering::Relaxed);
    {
        let _g = ConnGuard::new(m.clone());
        assert_eq!(m.snapshot().current_conns, 1);
    }
    assert_eq!(m.snapshot().bytes_in, 1024);
    assert_eq!(m.snapshot().current_conns, 0);
}

#[tokio::test]
async fn test_registry_multiple_proxies_independent() {
    let reg = ProxyMetricsRegistry::new();
    reg.get_or_create("p1").await;
    reg.get_or_create("p2").await;
    assert!(reg.get("p1").await.is_some());
    reg.remove("p1").await;
    assert!(reg.get("p1").await.is_none());
    assert!(reg.get("p2").await.is_some());
}
```

- [ ] **Step 2: Run full test suite**

```bash
cargo test --workspace
bash scripts/compat-test.sh --verbose
```

Expected: all Rust tests pass, all 31 compat tests pass.

- [ ] **Step 3: Commit**

```bash
git add frp-server/tests/
git commit -m "test: add API data-layer tests"
```
