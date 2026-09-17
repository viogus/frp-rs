# Management REST API Design

Date: 2026-06-26
Status: Draft
Target: Go frp v0.69.1 compatibility

## Overview

Add HTTP REST management API to both frps (server dashboard expansion) and frpc
(client admin server). Align with Go frp v0.69.1's HTTP API surface. Go frp has
no gRPC — management is REST-based with Basic Auth.

## Architecture

```
frps process                              frpc process
  ├── bind_port listener (main)             ├── control connection (to frps)
  ├── VHost/KCP/QUIC/TCPMux listeners       ├── proxy work connections
  ├── dashboard HTTP (:7500)                └── admin HTTP (:7400)  ← NEW
  │   ├── GET  /api/status                      ├── GET  /api/status
  │   ├── GET  /api/proxies                     ├── GET  /api/reload
  │   ├── GET  /api/proxy/:name      ← NEW      ├── POST /api/stop
  │   └── GET  /api/proxy/:name/traffic ← NEW   ├── GET  /api/config
  └── ProxyMetricsRegistry (shared)              └── PUT  /api/config
```

## Shared Components

### ProxyMetrics (frp-core/src/metrics.rs)

Per-proxy traffic counters using atomics for lock-free reads from admin endpoints.

```rust
pub struct ProxyMetrics {
    pub name: String,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub current_conns: AtomicI64,
    pub total_conns: AtomicU64,
}

pub struct ProxyMetricsRegistry {
    metrics: RwLock<HashMap<String, Arc<ProxyMetrics>>>,
}
```

- `get_or_create(name)` — returns Arc, creates if missing
- `remove(name)` — cleanup on proxy unregister
- `snapshot(name)` — returns MetricsSnapshot (plain struct, no atomics)
- Metrics only collected when connection actually transfers data
- Counters never reset (lifetime totals)

### CountedStream (frp-core/src/metrics.rs)

Wrapper around `AsyncRead`/`AsyncWrite` that increments byte counters on each
read/write operation. Used in `bridge::copy_bidirectional` and
`bridge::bridge_encrypted`.

```rust
pub struct CountedRead<R> { inner: R, metrics: Arc<ProxyMetrics>, direction: Direction }
pub struct CountedWrite<W> { inner: W, metrics: Arc<ProxyMetrics>, direction: Direction }
```

### AdminAuth (frp-core/src/admin_auth.rs)

Shared Basic Auth middleware for axum. Configuration from `WebServerConfig`:
- When `user` and `password` both empty: skip auth (pass-through)
- When set: require `Authorization: Basic base64(user:pass)` header
- 401 response includes `WWW-Authenticate: Basic realm="frp"`

```rust
pub fn admin_auth_layer(user: String, password: String)
    -> TowerLayer
```

### WebServerConfig (already exists)

```rust
pub struct WebServerConfig {
    pub addr: String,       // default "0.0.0.0"
    pub port: u16,          // 0 = disabled
    pub user: String,       // empty = no auth
    pub password: String,
}
```

Present in both `ServerConfig` and `ClientConfig`. Already parsed from flat
TOML keys (`web_server_port`, `web_server_user`, etc.). Zero config changes.

## frpc Admin HTTP Server

### Module: frp-client/src/admin.rs

New module. Started as `tokio::spawn` in `Service::run()` when
`cfg.web_server.port > 0`.

### AdminState

```rust
struct AdminState {
    proxy_metrics: Arc<ProxyMetricsRegistry>,
    proxies: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    reload_tx: mpsc::UnboundedSender<ReloadRequest>,
    stop_tx: mpsc::UnboundedSender<()>,
    config_path: Option<String>,
    auth_user: String,
    auth_pwd: String,
}
```

### Endpoints

#### GET /api/status

Returns all proxy statuses grouped by proxy type (matching Go frp format).

Response (200):
```json
{
  "tcp": [
    {
      "name": "ssh",
      "type": "tcp",
      "status": "online",
      "local_addr": "127.0.0.1:22",
      "remote_addr": "x.x.x.x:6000",
      "plugin": "",
      "err": ""
    }
  ],
  "http": [...]
}
```

- `status`: "online" if proxy has active control session, "offline" otherwise
- `err`: last error message, empty if online
- Traffic counters not included in this endpoint (Go frp doesn't include them here)

#### GET /api/reload

Triggers config hot-reload. Optional query param `?strictConfig=true` (matching
Go frp).

Response (200): `reload success`
Response (400): Error message

Flow:
1. Admin handler sends `ReloadRequest { strict: bool }` to `reload_tx`
2. Waits for response via oneshot channel (30s timeout)
3. Control loop: reads config → diffs proxy list → add/remove proxies
4. Existing control connection preserved
5. Returns result to admin handler

#### POST /api/stop

Graceful shutdown. Sends stop signal via `stop_tx`.

Response (200): `stop success`

Flow:
1. Admin handler sends `()` to `stop_tx`
2. Returns success immediately (doesn't wait for exit)
3. Main loop receives signal → disconnects → process exits

#### GET /api/config

Returns raw config file content.

Response (200): TOML string as plain text
Response (404): No config file path stored

#### PUT /api/config

Overwrites config file with request body, then triggers reload.

Response (200): `update success`
Response (400): Error message

### Reload Logic (frp-client/src/service.rs)

New method `Service::try_reload(config_path: &str, strict: bool) -> Result<String>`:

1. Read new `ClientConfig` from file
2. Diff new vs old proxy configs
3. New proxies: register via control connection (send `NewProxy`)
4. Removed proxies: close via control connection (send `CloseProxy`)
5. Updated proxies (config changed): close old, register new
6. Strict mode: fail entire reload on first error
7. Non-strict mode: skip errored proxies, apply rest, return warnings

## frps Dashboard Expansion

### Module: frp-server/src/dashboard.rs (modified)

#### New Routes

```
GET /api/proxy/:name         → proxy_detail()
GET /api/proxy/:name/traffic → proxy_traffic()
```

#### GET /api/proxy/:name

Single proxy detail with traffic stats.

Response (200):
```json
{
  "name": "ssh",
  "type": "tcp",
  "status": "online",
  "run_id": "abc123",
  "remote_port": 6000,
  "local_addr": "127.0.0.1:22",
  "use_encryption": false,
  "use_compression": false,
  "custom_domains": [],
  "multiplexer": "",
  "group": "",
  "traffic": {
    "bytes_in": 1048576,
    "bytes_out": 524288,
    "current_conns": 3,
    "total_conns": 142
  }
}
```

- `status`: "online" if `run_id` has active control handler in `run_id_to_ctl_tx`, else "offline"
- `traffic`: from `ProxyMetricsRegistry`, zero if no data yet
- Response (404): `{"error": "proxy not found"}`

#### GET /api/proxy/:name/traffic

Placeholder for traffic time-series. Returns current snapshot only (daily
breakdown deferred to future iteration).

Response (200):
```json
{
  "proxy_name": "ssh",
  "bytes_in": 1048576,
  "bytes_out": 524288,
  "current_conns": 3,
  "total_conns": 142
}
```

#### Existing Route Changes

**GET /api/proxies** — add `status` and traffic summary fields:
```json
[
  {
    "name": "ssh",
    "type": "tcp",
    "status": "online",
    "remote_port": 6000,
    "local_addr": "127.0.0.1:22",
    "traffic_in": 1048576,
    "traffic_out": 524288
  }
]
```

**GET /api/status** — unchanged.

#### Auth Middleware

Applied to all `/api/*` routes when `web_server.user` is non-empty.
HTML page (`/`) never requires auth (matches Go frp behavior).

### AppState Changes (frp-server/src/service.rs)

Add to `AppState`:
```rust
pub struct AppState {
    // ... existing fields ...
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,  // NEW
}
```

## Bridge Metrics Wiring

### frp-core/src/bridge.rs (modified)

`assign_work_to_proxy` and `bridge_encrypted`:
1. Before creating `copy_bidirectional`: get/update `ProxyMetrics` for proxy name
2. Increment `current_conns`, `total_conns` on start
3. Wrap reader/writer with `CountedRead`/`CountedWrite`
4. Decrement `current_conns` on drop (guard pattern)

Pseudo-diff:
```rust
let metrics = metrics_registry.get_or_create(&proxy_name);
metrics.current_conns.fetch_add(1, Ordering::Relaxed);
metrics.total_conns.fetch_add(1, Ordering::Relaxed);

struct ConnGuard { metrics: Arc<ProxyMetrics> }
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.metrics.current_conns.fetch_sub(1, Ordering::Relaxed);
    }
}

let _guard = ConnGuard { metrics: metrics.clone() };
let counted_a = CountedRead::new(a, metrics.clone(), Direction::In);
let counted_b = CountedWrite::new(b, metrics.clone(), Direction::Out);
tokio::io::copy_bidirectional(&mut counted_a, &mut counted_b).await
```

## Files Summary

| File | Change | Description |
|------|--------|-------------|
| `frp-core/src/metrics.rs` | NEW | `ProxyMetrics`, `ProxyMetricsRegistry`, `CountedStream` |
| `frp-core/src/admin_auth.rs` | NEW | Shared Basic Auth axum middleware |
| `frp-core/src/lib.rs` | MODIFY | Export `metrics`, `admin_auth` modules |
| `frp-core/Cargo.toml` | MODIFY | Add `axum` dependency |
| `frp-core/src/bridge.rs` | MODIFY | Wire counted streams into copy loops |
| `frp-client/src/admin.rs` | NEW | frpc admin HTTP server, all 5 endpoints |
| `frp-client/src/service.rs` | MODIFY | Spawn admin server, add `try_reload()` method |
| `frp-client/src/lib.rs` | MODIFY | Export `admin` module |
| `frp-client/Cargo.toml` | MODIFY | Add `axum`, `tokio` signal dependencies |
| `frp-server/src/dashboard.rs` | MODIFY | Add proxy detail/traffic routes, auth middleware |
| `frp-server/src/service.rs` | MODIFY | Add `ProxyMetricsRegistry` to `AppState` |

## Testing

### Unit Tests
- `ProxyMetrics` atomic counter correctness (increment, concurrent, snapshot)
- `AdminAuth` middleware: pass-through, 401, correct header parsing
- `CountedStream`: byte counting on read/write

### Integration Tests
- frpc admin `/api/status` returns correct proxy grouping
- frpc admin `/api/reload` with strict/non-strict modes
- frpc admin `/api/stop` graceful shutdown
- frpc admin `/api/config` get/put cycle
- frps `/api/proxy/:name` returns traffic data after connection
- frps `/api/proxies` includes new fields
- Basic Auth on all protected endpoints

### Compat Tests
- frpc admin endpoint format matches Go frp v0.69.1 responses
- Dashboard endpoint format matches Go frp structure

## Out of Scope (deferred)

- Client management panel (`/api/clients`) — deferred, structure defined
- Traffic time-series (hourly/daily breakdown) — deferred
- `/api/proxy/:name/traffic` history — current snapshot only
- gRPC API — not in Go frp v0.69.1, separate future project
- HTML dashboard enhancement (charts, JS improvements)
- frpc admin TLS/HTTPS support
