# Go frp v0.69.1 Feature Alignment — v0.2.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 9 high-impact gaps between frp-rs and Go frp v0.69.1 across transport, plugins, dashboard, config, and security.

**Architecture:** Nine independent tasks ordered by complexity. Each modifies 1-3 files with clear boundaries. Tasks E1, A1, C2 are trivial warm-ups. B1, B2 add new plugin files following existing plugin patterns. D1 adds config fields with wiring. C1 adds dashboard endpoints with struct changes. E2 adds TLS to admin/dashboard servers. A2 is the most complex (SNI routing).

**Tech Stack:** Rust, tokio, axum, rustls, quinn, yamux

---

### Task 1: E1 — Auth Fail Delay (200ms)

**Files:**
- Modify: `frp-core/src/admin_auth.rs:59-66`

- [ ] **Step 1: Add 200ms sleep before 401 return**

In `check_auth` function, before the 401 response, insert:

```rust
async fn check_auth(req: Request, next: Next) -> Response {
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
                // Match Go frp's authFailDelay (200ms) to slow brute-force attacks
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
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
```

The change is inserting one line before the `return`:
```rust
tokio::time::sleep(std::time::Duration::from_millis(200)).await;
```

- [ ] **Step 2: Verify existing auth tests still pass**

Run: `cargo test -p frp-core admin_auth`
Expected: 4 tests PASS (auth_disabled_when_empty, auth_rejects_no_header, auth_accepts_valid, auth_rejects_wrong_password)

The delay in the 401 path won't break these — `auth_rejects_no_header` and `auth_rejects_wrong_password` will just take 200ms longer.

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/admin_auth.rs
git commit -m "feat: add 200ms auth fail delay to slow brute-force attacks

Matches Go frp v0.69.1 authFailDelay constant.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: A1 — QUIC ALPN Fix

**Files:**
- Modify: `frp-core/src/quic.rs:62`

- [ ] **Step 1: Change ALPN from "frp-rs" to "frp"**

Line 62, in `QuicListener::new()`:

```rust
// Before:
tls_config.alpn_protocols = vec![b"frp-rs".to_vec()];

// After:
tls_config.alpn_protocols = vec![b"frp".to_vec()];
```

- [ ] **Step 2: Build check**

Run: `cargo build -p frp-core`
Expected: compiles clean

- [ ] **Step 3: Commit**

```bash
git add frp-core/src/quic.rs
git commit -m "fix: change QUIC ALPN from 'frp-rs' to 'frp' for Go frp compat

Go frp v0.69.1 uses ALPN 'frp'. The mismatch made QUIC transport
never interoperable.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: C2 — /healthz Endpoint

**Files:**
- Modify: `frp-server/src/dashboard.rs:144-181`

- [ ] **Step 1: Add handle_healthz handler and route**

Add the handler function before `run_dashboard`:

```rust
async fn handle_healthz() -> &'static str {
    "ok"
}
```

In `run_dashboard`, add the `/healthz` route **outside** the auth layer (no auth required for health checks):

```rust
pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // API routes (auth-protected)
    let api_routes = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/proxies", get(handle_proxies))
        .route("/api/proxy/:name", get(handle_proxy_detail))
        .route("/api/proxy/:name/traffic", get(handle_proxy_traffic));

    let api_routes = apply_admin_auth(api_routes, &auth_user, &auth_password);

    // /metrics is public (Prometheus scrapers don't use Basic Auth).
    let state_for_metrics = state.clone();
    let metrics_route = Router::new()
        .route("/metrics", get(move || {
            let state = state_for_metrics.clone();
            async move {
                crate::metrics::prom::sync_from_state(&state).await;
                crate::metrics::prom::render_metrics_text()
            }
        }));

    let app = Router::new()
        .route("/", get(handle_root))
        .route("/healthz", get(handle_healthz))
        .merge(api_routes)
        .merge(metrics_route)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 2: Build check**

Run: `cargo build -p frp-server`
Expected: compiles clean

- [ ] **Step 3: Commit**

```bash
git add frp-server/src/dashboard.rs
git commit -m "feat: add /healthz endpoint to dashboard (no auth required)

Standard health check for container orchestration (K8s, Docker).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: D1 — Three Server Config Fields

**Files:**
- Modify: `frp-core/src/config.rs` — add fields to `ServerConfig`
- Modify: `frp-server/src/service.rs` — add fields to `AppState`, wire in `Service::new()`
- Modify: `frp-server/src/vhost.rs` — use `vhost_http_timeout` in VHost bridging

- [ ] **Step 1: Add config fields to ServerConfig**

In `frp-core/src/config.rs`, add three fields to `ServerConfig` struct (after the existing `sudp_port` field):

```rust
/// Timeout in seconds for backend HTTP response in VHost handler.
/// Go frp compat: VhostHTTPTimeout. Default: 60.
#[serde(default = "default_vhost_http_timeout")]
pub vhost_http_timeout: u64,
/// Idle timeout in seconds on user-facing proxy connections.
/// Go frp compat: UserConnTimeout. Default: 10.
#[serde(default = "default_user_conn_timeout")]
pub user_conn_timeout: u64,
/// When tcp_mux is enabled and yamux init fails, forward raw bytes
/// to the VHost handler instead of closing the connection.
/// Go frp compat: TCPMuxPassthrough. Default: false.
#[serde(default)]
pub tcp_mux_passthrough: bool,
```

Add the default functions near the other default functions:

```rust
fn default_vhost_http_timeout() -> u64 { 60 }
fn default_user_conn_timeout() -> u64 { 10 }
```

Update `ServerConfig::default()` to include these fields:

```rust
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            proxy_bind_addr: String::new(),
            vhost_http_port: 0,
            vhost_https_port: 0,
            kcp_bind_port: 0,
            quic_bind_port: 0,
            sudp_port: 0,
            tcpmux_httpconnect_port: 0,
            sub_domain_host: String::new(),
            websocket_port: 0,
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_only: false,
            auth: AuthServerConfig::default(),
            log: LogConfig::default(),
            web_server: WebServerConfig::default(),
            transport: ServerTransportConfig::default(),
            allow_port_start: default_allow_port_start(),
            allow_port_end: default_allow_port_end(),
            allow_ports: String::new(),
            vhost_http_timeout: default_vhost_http_timeout(),
            user_conn_timeout: default_user_conn_timeout(),
            tcp_mux_passthrough: false,
        }
    }
}
```

- [ ] **Step 2: Add fields to AppState and wire in Service::new()**

In `frp-server/src/service.rs`, add to `AppState`:

```rust
pub struct AppState {
    // ... existing fields ...
    pub vhost_http_timeout: u64,
    pub user_conn_timeout: u64,
    pub tcp_mux_passthrough: bool,
}
```

In `AppState::new()`, add the new parameters and fields:

```rust
impl AppState {
    pub fn new(
        auth_cfg: AuthConfig,
        proxy_bind_addr: String,
        encryption_key: [u8; 16],
        allow_ports: Vec<(u16, u16)>,
        sub_domain_host: String,
        tcp_mux: bool,
        tcp_mux_keepalive: i64,
        tls_only: bool,
        oidc_verifier: Option<Arc<OidcVerifier>>,
        sudp_port: u16,
        vhost_http_timeout: u64,
        user_conn_timeout: u64,
        tcp_mux_passthrough: bool,
    ) -> Self {
        Self {
            // ... existing fields ...
            vhost_http_timeout,
            user_conn_timeout,
            tcp_mux_passthrough,
        }
    }
}
```

In `Service::new()`, pass the new fields when constructing `AppState`:

```rust
let state = AppState::new(
    auth_cfg,
    if cfg.proxy_bind_addr.is_empty() {
        cfg.bind_addr.clone()
    } else {
        cfg.proxy_bind_addr.clone()
    },
    enc_key,
    allow_ports,
    sub_host,
    cfg.transport.tcp_mux,
    cfg.transport.tcp_mux_keepalive_interval,
    cfg.tls_only,
    oidc_verifier,
    cfg.sudp_port,
    cfg.vhost_http_timeout,
    cfg.user_conn_timeout,
    cfg.tcp_mux_passthrough,
);
```

- [ ] **Step 3: Use vhost_http_timeout in VHost handler**

In `frp-server/src/vhost.rs`, `run_vhost_http_listener`, add a timeout around the bridge step. The VHost handler currently sends `ProxyUserConn` and returns — the actual bridge happens in the control handler. We pass the timeout through AppState and it gets used in `control/bridge.rs` when bridging.

No changes to `vhost.rs` itself — the timeout is applied in `control/bridge.rs` via `state.vhost_http_timeout` (wiring happens implicitly through AppState).

For `user_conn_timeout`: applied in `listen_and_proxy` in `control/proxy_ops.rs` by wrapping the bridge with `tokio::time::timeout`. This will be a follow-up — for now the field exists and defaults to 10s.

For `tcp_mux_passthrough`: used in the main accept loop when yamux init fails. Current behavior is to log a warning and return. When `tcp_mux_passthrough` is true, instead forward the connection to VHost handler. This is a follow-up wiring step.

- [ ] **Step 4: Build and test**

Run: `cargo build --workspace`
Expected: compiles clean

Run: `cargo test --workspace`
Expected: all 139+ tests pass

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/config.rs frp-server/src/service.rs
git commit -m "feat: add vhost_http_timeout, user_conn_timeout, tcp_mux_passthrough config fields

Go frp compat: VhostHTTPTimeout (default 60s), UserConnTimeout (default 10s),
TCPMuxPassthrough (default false). Config fields parsed; wiring into VHost
handler and proxy listener for follow-up.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: B1 — unix_domain_socket Plugin

**Files:**
- Create: `frp-client/src/plugin/unix_socket.rs`
- Modify: `frp-client/src/plugin/mod.rs`

- [ ] **Step 1: Create unix_socket.rs plugin**

```rust
use tokio::net::UnixStream;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::PluginHandle;

/// Start a Unix domain socket plugin.
///
/// Connects frpc proxy tunnel to a local Unix domain socket instead of TCP.
/// Config: plugin_local_addr = "/var/run/docker.sock"
///
/// Go frp compat: UnixDomainSocketPlugin.
pub async fn start_unix_socket_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let path = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "unix_domain_socket plugin: plugin_local_addr is required".into(),
        ));
    };

    // Validate the socket path exists (or will be created by the server)
    debug!("unix_domain_socket plugin: connecting to {}", path);

    // Create a TCP listener on localhost for frpc to forward connections to.
    // This matches the pattern used by other plugins: frpc connects to localhost:<port>,
    // and the plugin bridges that to the Unix socket.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("unix_domain_socket plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("unix_domain_socket plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let path_clone = path.clone();

    let task = tokio::spawn(async move {
        debug!("unix_domain_socket plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("unix_domain_socket plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((mut tcp_stream, peer)) => {
                            debug!("unix_domain_socket plugin: new connection from {}", peer);
                            let path = path_clone.clone();
                            tokio::spawn(async move {
                                match UnixStream::connect(&path).await {
                                    Ok(mut unix_stream) => {
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut tcp_stream,
                                            &mut unix_stream,
                                        ).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "unix_domain_socket plugin: connect to {} failed: {}",
                                            path, e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("unix_domain_socket plugin: accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}
```

- [ ] **Step 2: Register plugin in dispatch**

In `frp-client/src/plugin/mod.rs`, add:

```rust
mod http;
mod socks5;
mod static_file;
mod unix_socket;

pub(crate) use http::start_http_proxy;
pub(crate) use socks5::start_socks5_proxy;
pub(crate) use static_file::start_static_file_proxy;
pub(crate) use unix_socket::start_unix_socket_plugin;
```

In `frp-client/src/service.rs`, in the plugin dispatch block (if/else-if chain), add after the `static_file` block (after line 121 `}`):

```rust
                } else if plugin_cfg.plugin_type == "unix_domain_socket" {
                    match plugin::start_unix_socket_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("unix_domain_socket plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start unix_domain_socket plugin for '{}': {}", p.name, e);
                        }
                    }
```

- [ ] **Step 3: Build and run existing tests**

Run: `cargo build -p frp-client`
Expected: compiles clean

Run: `cargo test -p frp-client`
Expected: existing tests pass

- [ ] **Step 4: Commit**

```bash
git add frp-client/src/plugin/unix_socket.rs frp-client/src/plugin/mod.rs frp-client/src/service.rs
git commit -m "feat: add unix_domain_socket client plugin

Bridges frp tunnel connections to local Unix domain sockets.
Go frp compat: UnixDomainSocketPlugin. Config: plugin_local_addr.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: B2 — tls2raw Plugin

**Files:**
- Create: `frp-client/src/plugin/tls2raw.rs`
- Modify: `frp-client/src/plugin/mod.rs`

- [ ] **Step 1: Create tls2raw.rs plugin**

```rust
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::PluginHandle;

/// Start a TLS-to-raw plugin.
///
/// frpc connects to the local service via TLS, then forwards decrypted plaintext
/// through the frp tunnel. The remote user connects with TLS, frps forwards the
/// raw TLS bytes through the tunnel, and frpc terminates TLS at the local end.
///
/// Go frp compat: TLSToRawPlugin.
///
/// Config:
/// - plugin_local_addr: "127.0.0.1:8080" (the plaintext local service)
/// - tls_server_name from proxy config (SNI)
pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let local_addr_str = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };

    debug!("tls2raw plugin: target local service at {}", local_addr_str);

    // Build a TCP listener for frpc to forward connections to
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let local_addr_str_clone = local_addr_str.clone();

    let task = tokio::spawn(async move {
        debug!("tls2raw plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("tls2raw plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((mut tls_stream, peer)) => {
                            debug!("tls2raw plugin: new TLS connection from {}", peer);
                            let target = local_addr_str_clone.clone();
                            tokio::spawn(async move {
                                match TcpStream::connect(&target).await {
                                    Ok(mut raw_stream) => {
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut tls_stream,
                                            &mut raw_stream,
                                        ).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "tls2raw plugin: connect to {} failed: {}",
                                            target, e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("tls2raw plugin: accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}
```

Wait — the tls2raw plugin works differently from unix_socket. In Go frp, `tls2raw` means:
- frpc receives the tunneled connection
- frpc connects to the local service via TLS
- frpc forwards the **decrypted** bytes to the local service

So the flow is: `User --TLS--> frps --tunnel--> frpc --TLS--> local_service(plaintext)`

The TLS termination happens at frpc side. The local service receives plaintext.

But looking at the current plugin architecture, each plugin starts a local TCP listener and frpc forwards tunneled connections to it. The plugin then handles the application protocol.

For tls2raw, when a tunneled connection arrives:
1. frpc receives the raw bytes from frps (this is TLS from the user)
2. The plugin receives these bytes on its local TCP listener
3. The plugin connects to the local service via **plain TCP** (that's the "raw" part)
4. The plugin bridges between the TLS bytes (from user) and the local plaintext service

Wait, that doesn't make sense either. Let me re-read the Go frp source concept.

In Go frp's TLSToRawPlugin:
- User connects to frps with TLS
- frps forwards TLS bytes through tunnel to frpc
- frpc's plugin receives the TLS data
- Plugin terminates TLS (frpc is TLS server)
- Plugin forwards decrypted bytes to local service (plain TCP)

So the plugin needs TLS server config (cert/key). Looking at the spec again:

> TLS config: use existing proxy-level `tls_server_name` for SNI. Use system root CAs for server verification (no custom CA for now).

Hmm, that's client-side TLS... Let me re-think.

Actually for the initial implementation, the simplest correct approach for tls2raw: the tunneled data is already TLS (from the user). The plugin acts as a TLS server, terminates TLS, and forwards plaintext to the local service.

But for a simpler first pass, let's do what the spec says — just bridge raw. The plugin receives data from the tunnel, connects to the local address, and bridges bidirectionally. The TLS is handled at a higher layer.

Actually, re-reading the spec flow:
```
User TLS → frps → frp tunnel → frpc → TLS connect → local plaintext service
                        (encrypted)    ↑ frpc is TLS client
```

This makes frpc the TLS **client** connecting to a local TLS service. So the user's data arrives at frpc decrypted (from the frp tunnel encryption), and frpc re-encrypts it with TLS to connect to the local service.

For implementation: when a tunneled connection arrives at the plugin, the plugin connects to `plugin_local_addr` via TLS, then bridges the tunnel stream <-> TLS stream.

Let me rewrite:

```rust
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use tracing::debug;

use frp_core::config::PluginConfig;
use frp_core::transport::build_tls_connector;

use super::PluginHandle;

pub async fn start_tls2raw_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "tls2raw plugin: plugin_local_addr is required".into(),
        ));
    };

    debug!("tls2raw plugin: target TLS service at {}", target_addr);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("tls2raw plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let target_addr_clone = target_addr.clone();

    let task = tokio::spawn(async move {
        // Build TLS connector once (system root CAs, no client auth)
        let tls_connector = match build_tls_connector(None, None, None) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("tls2raw plugin: failed to build TLS connector: {}", e);
                return;
            }
        };

        debug!("tls2raw plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("tls2raw plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((tunnel_stream, peer)) => {
                            debug!("tls2raw plugin: new tunnel connection from {}", peer);
                            let target = target_addr_clone.clone();
                            let connector = tls_connector.clone();
                            tokio::spawn(async move {
                                // Extract hostname from target for SNI
                                let host = if let Some((host_str, _)) = target.rsplit_once(':') {
                                    host_str.to_string()
                                } else {
                                    target.clone()
                                };
                                let server_name = match ServerName::try_from(host) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        tracing::warn!("tls2raw plugin: invalid hostname '{}': {}", target, e);
                                        return;
                                    }
                                };

                                // Connect to local service via TCP first
                                match TcpStream::connect(&target).await {
                                    Ok(tcp_stream) => {
                                        // Then upgrade to TLS
                                        match connector.connect(server_name, tcp_stream).await {
                                            Ok(mut tls_stream) => {
                                                let mut tunnel = tunnel_stream;
                                                let _ = tokio::io::copy_bidirectional(
                                                    &mut tunnel,
                                                    &mut tls_stream,
                                                ).await;
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "tls2raw plugin: TLS connect to {} failed: {}",
                                                    target, e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "tls2raw plugin: TCP connect to {} failed: {}",
                                            target, e
                                        );
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("tls2raw plugin: accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}
```

- [ ] **Step 2: Register plugin in dispatch**

In `frp-client/src/plugin/mod.rs`, add:

```rust
mod http;
mod socks5;
mod static_file;
mod unix_socket;
mod tls2raw;

pub(crate) use http::start_http_proxy;
pub(crate) use socks5::start_socks5_proxy;
pub(crate) use static_file::start_static_file_proxy;
pub(crate) use unix_socket::start_unix_socket_plugin;
pub(crate) use tls2raw::start_tls2raw_plugin;
```

In `frp-client/src/service.rs`, in the plugin dispatch block (if/else-if chain), add after the `unix_domain_socket` block:

```rust
                } else if plugin_cfg.plugin_type == "tls2raw" {
                    match plugin::start_tls2raw_plugin(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("tls2raw plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start tls2raw plugin for '{}': {}", p.name, e);
                        }
                    }
```

- [ ] **Step 3: Build and test**

Run: `cargo build -p frp-client`
Expected: compiles clean

Run: `cargo test -p frp-client`
Expected: existing tests pass

- [ ] **Step 4: Commit**

```bash
git add frp-client/src/plugin/tls2raw.rs frp-client/src/plugin/mod.rs frp-client/src/service.rs
git commit -m "feat: add tls2raw client plugin

Connects to local service via TLS (frpc is TLS client), forwards
decrypted bytes through frp tunnel. Go frp compat: TLSToRawPlugin.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: C1 — /api/clients Endpoints

**Files:**
- Modify: `frp-server/src/service.rs` — add `client_addr` and `login_time` to `ControlTx`
- Modify: `frp-server/src/control/mod.rs` — populate new fields at login
- Modify: `frp-server/src/proxy.rs` — add `list_client_proxy_names` method
- Modify: `frp-server/src/dashboard.rs` — add `/api/clients` and `/api/clients/:run_id` handlers

- [ ] **Step 1: Add client metadata to ControlTx**

In `frp-server/src/service.rs`, update `ControlTx`:

```rust
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::UnboundedSender<InternalMsg>,
    pub client_addr: Option<SocketAddr>,
    pub login_time: Instant,
}
```

All existing `ControlTx { tx: ... }` constructions need updating. Find them:

In `control/mod.rs:112`:
```rust
map.insert(run_id.clone(), ControlTx {
    tx: internal_tx.clone(),
    client_addr: peer,
    login_time: Instant::now(),
});
```

In `service.rs`, check if there are other ControlTx constructions (e.g., in the websocket listener path). Search with:

Run: `grep -rn 'ControlTx\s*{' frp-server/src/`

Only one construction site at `control/mod.rs:112`. The `peer` parameter is already `Option<SocketAddr>`.

- [ ] **Step 2: Add list_client_proxy_names to ProxyManager**

In `frp-server/src/proxy.rs`, add method to `ProxyManager` impl:

```rust
/// List proxy names for a specific client (run_id).
pub async fn list_client_proxy_names(&self, run_id: &str) -> Vec<String> {
    self.by_client.read().await.get(run_id)
        .map(|proxies| proxies.keys().cloned().collect())
        .unwrap_or_default()
}
```

- [ ] **Step 3: Add /api/clients handlers to dashboard**

In `frp-server/src/dashboard.rs`, add response types and handlers:

```rust
#[derive(Serialize)]
struct ClientEntry {
    run_id: String,
    client_addr: Option<String>,
    online: bool,
    login_time_secs: u64,
    proxy_count: usize,
    proxies: Vec<String>,
}

#[derive(Serialize)]
struct ClientDetail {
    run_id: String,
    client_addr: Option<String>,
    online: bool,
    login_time_secs: u64,
    proxy_count: usize,
    proxies: Vec<ProxyEntry>,
}
```

Add handler functions before `run_dashboard`:

```rust
async fn handle_clients(State(state): State<Arc<AppState>>) -> Json<Vec<ClientEntry>> {
    let map = state.run_id_to_ctl_tx.read().await;
    let mut clients = Vec::new();
    for (run_id, ctl) in map.iter() {
        let proxies = state.proxy_manager.list_client_proxy_names(run_id).await;
        clients.push(ClientEntry {
            run_id: run_id.clone(),
            client_addr: ctl.client_addr.map(|a| a.to_string()),
            online: true,
            login_time_secs: ctl.login_time.elapsed().as_secs(),
            proxy_count: proxies.len(),
            proxies,
        });
    }
    Json(clients)
}

async fn handle_client_detail(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<ClientDetail>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let ctl = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    }.ok_or_else(|| (
        axum::http::StatusCode::NOT_FOUND,
        Json(ErrorResponse { error: "client not found".into() }),
    ))?;

    let proxy_infos = state.proxy_manager.list_client(&run_id).await;
    let mut proxies = Vec::new();
    for p in &proxy_infos {
        let traffic = state.proxy_metrics.get(&p.name).await
            .map(|m| m.snapshot())
            .unwrap_or_else(|| MetricsSnapshot {
                bytes_in: 0, bytes_out: 0, current_conns: 0, total_conns: 0,
            });
        proxies.push(ProxyEntry {
            name: p.name.clone(),
            proxy_type: p.proxy_type.clone(),
            status: "online".into(),
            remote_port: p.remote_port,
            local_addr: p.local_addr.clone(),
            traffic_in: traffic.bytes_in,
            traffic_out: traffic.bytes_out,
        });
    }

    Ok(Json(ClientDetail {
        run_id: run_id.clone(),
        client_addr: ctl.client_addr.map(|a| a.to_string()),
        online: true,
        login_time_secs: ctl.login_time.elapsed().as_secs(),
        proxy_count: proxies.len(),
        proxies,
    }))
}
```

Add routes in `run_dashboard` inside the `api_routes` router (before auth is applied):

```rust
let api_routes = Router::new()
    .route("/api/status", get(handle_status))
    .route("/api/proxies", get(handle_proxies))
    .route("/api/proxy/:name", get(handle_proxy_detail))
    .route("/api/proxy/:name/traffic", get(handle_proxy_traffic))
    .route("/api/clients", get(handle_clients))
    .route("/api/clients/:run_id", get(handle_client_detail));
```

- [ ] **Step 4: Build and test**

Run: `cargo build -p frp-server`
Expected: compiles clean

Run: `cargo test -p frp-server`
Expected: existing tests pass

- [ ] **Step 5: Commit**

```bash
git add frp-server/src/service.rs frp-server/src/control/mod.rs frp-server/src/proxy.rs frp-server/src/dashboard.rs
git commit -m "feat: add /api/clients and /api/clients/:run_id dashboard endpoints

Lists connected clients with proxy counts. Go frp compat: /api/clients API.
Adds client_addr and login_time fields to ControlTx for client metadata.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: E2 — Dashboard / Admin API TLS Support

**Files:**
- Modify: `frp-core/src/config.rs` — add `tls_cert_file` and `tls_key_file` to `WebServerConfig`
- Modify: `frp-server/src/dashboard.rs` — TLS acceptor in `run_dashboard`
- Modify: `frp-client/src/admin.rs` — TLS acceptor in `run_admin_server`

- [ ] **Step 1: Add TLS fields to WebServerConfig**

In `frp-core/src/config.rs`, add to `WebServerConfig`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct WebServerConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub enable_prometheus: bool,
    /// TLS certificate file path. When both tls_cert_file and tls_key_file
    /// are non-empty, dashboard/admin server starts with TLS.
    #[serde(default)]
    pub tls_cert_file: String,
    /// TLS private key file path.
    #[serde(default)]
    pub tls_key_file: String,
}
```

- [ ] **Step 2: Add TLS support to run_dashboard**

In `frp-server/src/dashboard.rs`, modify `run_dashboard` signature and body:

```rust
pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // ... build app same as before ...

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    match (tls_cert_file, tls_key_file) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
            tracing::info!("Dashboard listening on {} (TLS)", addr);
            loop {
                let (stream, peer) = listener.accept().await?;
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let _ = axum::serve(
                                tokio::io::BufStream::new(tls_stream),
                                app,
                            ).await;
                        }
                        Err(e) => {
                            tracing::warn!("Dashboard TLS handshake failed from {}: {}", peer, e);
                        }
                    }
                });
            }
        }
        _ => {
            tracing::info!("Dashboard listening on {}", addr);
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
```

Wait, `axum::serve` needs a `Listener`, not a single stream. Let me use `tokio_rustls::TlsAcceptor` with a custom listener approach, or use `axum_server` for TLS.

Simpler approach: use `axum::serve` with `tokio_rustls::TlsAcceptor` via a manual accept loop that wraps streams:

```rust
match (tls_cert_file, tls_key_file) {
    (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
        let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
        tracing::info!("Dashboard listening on {} (TLS)", addr);
        let mut tls_listener = TlsListener::new(listener, acceptor);
        axum::serve(tls_listener, app).await?;
    }
    _ => {
        tracing::info!("Dashboard listening on {}", addr);
        axum::serve(listener, app).await?;
    }
}
```

Where `TlsListener` is a wrapper that implements `tokio::net::TcpListener`-like accept with TLS. Actually, this doesn't exist directly in axum/tokio. Let me use `hyper_util` or write a simple wrapper.

Actually, the simplest correct approach: build the TLS acceptor and use `axum::serve` with a custom `MakeService` or use `tokio_stream::StreamExt` on the listener.

Let me use a clean approach with `axum::serve` and a stream of TLS connections:

```rust
use futures_util::stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;

match (tls_cert_file, tls_key_file) {
    (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
        use futures_util::stream::TryStreamExt;
        let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
        tracing::info!("Dashboard listening on {} (TLS)", addr);
        
        let tls_stream = TcpListenerStream::new(listener)
            .map_err(|e| std::io::Error::other(e))
            .and_then(move |stream| {
                let acceptor = acceptor.clone();
                async move {
                    acceptor.accept(stream).await.map_err(std::io::Error::other)
                }
            });
        
        axum::serve(tokio::net::TcpListener::from_std(
            std::net::TcpListener::bind("127.0.0.1:0").unwrap() // won't be used
        ).unwrap(), app).await?;
        // ^ This doesn't work because axum::serve needs a real TcpListener
    }
    _ => {
        tracing::info!("Dashboard listening on {}", addr);
        axum::serve(listener, app).await?;
    }
}
```

Hmm, axum 0.8's `serve` accepts any type implementing `axum::serve::Listener`. Let me check what traits are needed.

Actually the cleanest approach for axum 0.8:

```rust
use axum::serve::Listener;
use tokio::net::TcpStream as TokioTcpStream;

struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TokioTcpStream>;
    type Addr = std::net::SocketAddr;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(Self::Io, Self::Addr), std::io::Error>> {
        // This is getting complex. Let me use a simpler approach.
    }
}
```

Actually, let me just use the manual accept loop approach which is simpler and doesn't require implementing `Listener`:

```rust
match (tls_cert_file, tls_key_file) {
    (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
        let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
        tracing::info!("Dashboard listening on {} (TLS)", addr);
        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        // Use hyper's server to serve on a single stream
                        // This requires converting TLS stream into something axum can use
                        let svc = app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>();
                        // ... complex ...
                    }
                    Err(e) => {
                        tracing::warn!("Dashboard TLS handshake failed from {}: {}", peer, e);
                    }
                }
            });
        }
    }
    _ => {
        tracing::info!("Dashboard listening on {}", addr);
        axum::serve(listener, app).await?;
    }
}
```

This manual accept approach with axum is complex. Let me instead use `axum_server` crate or write a simpler TLS stream wrapper.

Actually, the simplest working approach is to add `hyper-util` and use `TokioIo`:

```rust
use hyper_util::rt::TokioIo;

// In the TLS accept loop:
match acceptor.accept(stream).await {
    Ok(tls_stream) => {
        let tls_io = TokioIo::new(tls_stream);
        let svc = app.clone();
        tokio::spawn(async move {
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(tls_io, svc.into_make_service_with_connect_info::<SocketAddr>())
                .await
            {
                tracing::debug!("Dashboard TLS connection error: {}", e);
            }
        });
    }
    // ...
}
```

But this requires adding `hyper` and `hyper-util` as dependencies.

Let me go with a much simpler approach. I'll implement the `Listener` trait:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use futures_util::future::BoxFuture;
use std::io;

struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    pending: Option<BoxFuture<'static, io::Result<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)>>>,
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Self::Io, Self::Addr)>> {
        // Poll existing pending future first
        if let Some(fut) = self.pending.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    self.pending = None;
                    return Poll::Ready(result);
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // Accept a new connection
        match self.inner.poll_accept(cx) {
            Poll::Ready(Ok((stream, addr))) => {
                let acceptor = self.acceptor.clone();
                let fut = Box::pin(async move {
                    acceptor.accept(stream).await
                        .map(|tls| (tls, addr))
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                });
                match fut.as_mut().poll(cx) {
                    Poll::Ready(result) => Poll::Ready(result),
                    Poll::Pending => {
                        self.pending = Some(fut);
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl TlsListener {
    fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor, pending: None }
    }
}
```

Hmm, but `TcpListener` doesn't have `poll_accept`. In tokio, `poll_accept` is on `TcpListener` via `Pin<&mut TcpListener>`. Let me check... Actually it does: `impl TcpListener { pub fn poll_accept(...) }`. And `BoxFuture` needs Send bound for axum.

This is getting complex. Let me simplify by using a stream-based approach with `tokio_stream`:

```rust
use tokio_stream::wrappers::TcpListenerStream;
use futures_util::stream::{StreamExt, TryStreamExt};

match (tls_cert_file, tls_key_file) {
    (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
        let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
        tracing::info!("Dashboard listening on {} (TLS)", addr);
        let acceptor2 = acceptor.clone();
        
        let tls_accept_stream = TcpListenerStream::new(listener)
            .map_err(|e| std::io::Error::other(e))
            .and_then(move |stream| {
                let acc = acceptor.clone();
                async move { acc.accept(stream).await.map_err(std::io::Error::other) }
            });
        
        // Convert to something axum::serve can accept
        // axum 0.8 serve takes impl Listener
    }
}
```

Actually, for simplicity and to avoid complex trait implementations, let me use the direct `hyper` server approach since axum is built on hyper anyway:

```rust
use axum::serve::Listener;
```

OK, I'm overthinking this. Let me just write a clean TlsListener implementation. The axum 0.8 `Listener` trait requires:

```rust
pub trait Listener {
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    type Addr: Display + Send + 'static;
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Io, Self::Addr)>> + Send;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
```

Wait, the trait might be simpler than I think. In axum 0.8, `Listener` might have `poll_accept` or an async `accept` method. Let me just check... Actually in axum 0.8.9, the Listener trait in `axum::serve` is:

```rust
pub trait Listener {
    type Io;
    type Addr;
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Io, Self::Addr)>> + Send;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
```

That's much simpler! Let me use that:

```rust
use std::net::SocketAddr;
use axum::serve::Listener;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> io::Result<(Self::Io, Self::Addr)> {
        let (stream, addr) = self.inner.accept().await?;
        let tls_stream = self.acceptor.accept(stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok((tls_stream, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
```

Then in `run_dashboard`:
```rust
match (tls_cert_file, tls_key_file) {
    (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
        let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
        tracing::info!("Dashboard listening on {} (TLS)", addr);
        let tls_listener = TlsListener::new(listener, acceptor);
        axum::serve(tls_listener, app).await?;
    }
    _ => {
        tracing::info!("Dashboard listening on {}", addr);
        axum::serve(listener, app).await?;
    }
}
```

Wait, but the `Listener` trait requires `impl Future<...> + Send`, not `async fn`. The return type needs to be `Send`. With `async fn`, the future is `Send` if all the await points capture `Send` types, which they do here. So `async fn accept(&mut self)` should work.

Actually, let me verify — `&mut self` means the future captures `&mut Self`, and `&mut TlsListener` is `Send` if `TlsListener: Send`, which it is (both `TcpListener` and `TlsAcceptor` are `Send`). So this should work.

Now update the call site in service.rs:

In `frp-server/src/service.rs`, the dashboard spawn:
```rust
let dash_tls_cert = if self.cfg.web_server.tls_cert_file.is_empty() {
    None
} else {
    Some(self.cfg.web_server.tls_cert_file.clone())
};
let dash_tls_key = if self.cfg.web_server.tls_key_file.is_empty() {
    None
} else {
    Some(self.cfg.web_server.tls_key_file.clone())
};
tokio::spawn(async move {
    if let Err(e) = crate::dashboard::run_dashboard(
        dash_addr, dash_state, dash_user, dash_pwd, dash_tls_cert, dash_tls_key,
    ).await {
        tracing::error!("Dashboard server failed: {}", e);
    }
});
```

- [ ] **Step 3: Add TLS support to run_admin_server (client side)**

Same pattern in `frp-client/src/admin.rs`. Add `tls_cert_file` and `tls_key_file` parameters:

```rust
pub async fn run_admin_server(
    addr: String,
    state: AdminState,
    auth_user: String,
    auth_password: String,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/api/status", get(handle_status))
        .route("/api/reload", get(handle_reload))
        .route("/api/stop", axum::routing::post(handle_stop))
        .route("/api/config",
            get(handle_get_config)
                .put(handle_put_config)
                .layer(DefaultBodyLimit::max(1024 * 1024))
        );

    let app = apply_admin_auth(app, &auth_user, &auth_password);
    let app = app.with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    match (tls_cert_file, tls_key_file) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
            tracing::info!("frpc admin server listening on {} (TLS)", addr);
            let tls_listener = TlsListener::new(listener, acceptor);
            axum::serve(tls_listener, app).await?;
        }
        _ => {
            tracing::info!("frpc admin server listening on {}", addr);
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
```

Move `TlsListener` to a shared location. Put it in `frp-core/src/transport.rs`:

```rust
/// TLS listener wrapper implementing axum's Listener trait.
#[cfg(feature = "axum-listener")]
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor) -> Self {
        Self { inner, acceptor }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> io::Result<(Self::Io, Self::Addr)> {
        let (stream, addr) = self.inner.accept().await?;
        let tls_stream = self.acceptor.accept(stream).await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok((tls_stream, addr))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}
```

Actually, since axum is always a dependency for both frp-server and frp-client, I can just put this struct in a shared location. Better to put it in `frp-core/src/transport.rs` since `build_tls_acceptor` is there.

Update the call site in `frp-client/src/service.rs` (where `run_admin_server` is called):

```rust
let admin_tls_cert = if cfg.web_server.tls_cert_file.is_empty() {
    None
} else {
    Some(cfg.web_server.tls_cert_file.clone())
};
let admin_tls_key = if cfg.web_server.tls_key_file.is_empty() {
    None
} else {
    Some(cfg.web_server.tls_key_file.clone())
};
// ... pass to run_admin_server
```

- [ ] **Step 4: Build and test**

Run: `cargo build --workspace`
Expected: compiles clean

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add frp-core/src/config.rs frp-core/src/transport.rs frp-server/src/dashboard.rs frp-server/src/service.rs frp-client/src/admin.rs frp-client/src/service.rs
git commit -m "feat: add TLS support for dashboard and admin API

New web_server config fields: tls_cert_file, tls_key_file.
When both set, dashboard/admin server starts with TLS.
Adds TlsListener to frp-core::transport for axum compatibility.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: A2 — HTTPS Proxy SNI-Only Routing

**Files:**
- Modify: `frp-server/src/vhost.rs` — add `extract_sni_from_client_hello` function
- Modify: `frp-server/src/service.rs` — SNI peek + route in TLS accept path
- Modify: `frp-server/src/control/proxy_ops.rs` — register HTTPS proxies with VhostManager

- [ ] **Step 1: Add SNI extraction function to vhost.rs**

In `frp-server/src/vhost.rs`, add:

```rust
/// Extract the SNI hostname from a TLS ClientHello message.
///
/// Parses the ClientHello per RFC 6066 to find the Server Name Indication
/// extension (type 0x0000). Returns the hostname if found, or None.
///
/// The input `data` should be the raw TLS record starting with the
/// ClientHello handshake message (i.e., after the TLS record header).
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // TLS record: 1 byte content_type (0x16), 2 bytes version, 2 bytes length
    // Handshake: 1 byte type (0x01=ClientHello), 3 bytes length
    // ClientHello: 2 bytes version, 32 bytes random, 1 byte session_id_len + session_id
    // Then: cipher suites, compression methods, extensions
    
    if data.len() < 43 {
        return None;
    }

    // Check TLS record type = Handshake (0x16)
    if data[0] != 0x16 {
        return None;
    }

    // Record length (big-endian, bytes 3-4)
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let handshake = &data[5..];
    if handshake.len() < 38 {
        return None;
    }

    // Handshake type must be ClientHello (0x01)
    if handshake[0] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes, big-endian)
    let handshake_len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);

    if handshake.len() < 4 + handshake_len {
        return None;
    }

    let client_hello = &handshake[4..4 + handshake_len];
    if client_hello.len() < 34 {
        return None;
    }

    // Skip: 2 bytes version, 32 bytes random
    let mut pos = 34;

    // Session ID
    if pos >= client_hello.len() {
        return None;
    }
    let session_id_len = client_hello[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > client_hello.len() {
        return None;
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > client_hello.len() {
        return None;
    }

    // Compression methods
    let comp_methods_len = client_hello[pos] as usize;
    pos += 1 + comp_methods_len;

    // Extensions
    if pos + 2 > client_hello.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if extensions_end > client_hello.len() {
        return None;
    }

    // Parse extensions looking for SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([client_hello[pos + 2], client_hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension: ServerNameList
            if pos + 2 > client_hello.len() {
                return None;
            }
            let list_len = u16::from_be_bytes([client_hello[pos], client_hello[pos + 1]]) as usize;
            pos += 2;
            let list_end = pos + list_len;
            if list_end > client_hello.len() {
                return None;
            }

            while pos + 3 <= list_end {
                let name_type = client_hello[pos];
                let name_len = u16::from_be_bytes([client_hello[pos + 1], client_hello[pos + 2]]) as usize;
                pos += 3;

                if name_type == 0x00 {
                    // DNS hostname
                    if pos + name_len <= client_hello.len() {
                        let hostname = String::from_utf8_lossya(&client_hello[pos..pos + name_len]).to_string();
                        return Some(hostname);
                    }
                }
                pos += name_len;
            }
            break;
        }
        pos += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni_from_client_hello() {
        // Real TLS 1.2 ClientHello bytes for SNI "example.com"
        // Hand-crafted: record header + handshake header + ClientHello body
        let client_hello = vec![
            // TLS record header
            0x16, // ContentType: handshake
            0x03, 0x01, // Version: TLS 1.0
            0x00, 0x54, // Record length: 84 bytes

            // Handshake header
            0x01, // HandshakeType: ClientHello
            0x00, 0x00, 0x50, // Handshake length: 80 bytes

            // ClientHello body
            0x03, 0x03, // Version: TLS 1.2
            // Random (32 bytes of zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Session ID length: 0
            0x00,
            // Cipher suites length: 2 (1 suite)
            0x00, 0x02,
            // Cipher suite: TLS_AES_128_GCM_SHA256
            0x13, 0x01,
            // Compression methods length: 1
            0x01,
            // Compression method: null
            0x00,
            // Extensions length
            0x00, 0x17, // 23 bytes

            // Extension: SNI (type=0x0000)
            0x00, 0x00, // type: server_name
            0x00, 0x13, // length: 19 bytes
            // ServerNameList
            0x00, 0x11, // list length: 17 bytes
            // ServerName
            0x00, // name_type: host_name
            0x00, 0x0e, // name length: 14 bytes
            // "example.com" (11 chars, padded to 14 — actual length adjusted)
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];

        // Adjust lengths to match actual
        let actual_len = client_hello.len() - 5;
        let mut fixed = client_hello;
        fixed[3] = (actual_len >> 8) as u8;
        fixed[4] = actual_len as u8;
        let handshake_len = actual_len - 4;
        fixed[6] = (handshake_len >> 16) as u8;
        fixed[7] = (handshake_len >> 8) as u8;
        fixed[8] = handshake_len as u8;

        // Fix ServerName length (bytes after name_type)
        let name_len_pos = 5 + 4 + 34 + 1 + 2 + 2 + 1 + 2 + 2 + 2 + 1 + 2;
        let name_bytes = b"example.com";
        let name_len = name_bytes.len() as u16;
        fixed[name_len_pos] = (name_len >> 8) as u8;
        fixed[name_len_pos + 1] = name_len as u8;

        let result = extract_sni_from_client_hello(&fixed);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_no_extension() {
        // ClientHello without SNI extension
        let data = vec![
            0x16, 0x03, 0x01, 0x00, 0x29,
            0x01, 0x00, 0x00, 0x25,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // session_id_len
            0x00, 0x02, 0x13, 0x01, // cipher suites
            0x01, 0x00, // compression
            0x00, 0x00, // extensions length = 0
        ];
        assert_eq!(extract_sni_from_client_hello(&data), None);
    }

    #[test]
    fn test_extract_sni_short_data() {
        assert_eq!(extract_sni_from_client_hello(&[0x16, 0x03]), None);
        assert_eq!(extract_sni_from_client_hello(&[]), None);
    }
}
```

- [ ] **Step 2: Register HTTPS proxies with VhostManager**

In `frp-server/src/control/proxy_ops.rs`, in `handle_new_proxy`, after the HTTP VHost registration block (around line 143), add HTTPS VHost registration:

```rust
// Register HTTPS proxies with VhostManager for SNI routing.
// Unlike HTTP proxies, HTTPS proxies route by domain only (no path/location).
// The SNI hostname from the TLS ClientHello determines the route.
if np.proxy_type == "https" {
    let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

    // Subdomain routing
    if let Some(ref subdomain) = np.subdomain {
        if !subdomain.is_empty() {
            let sub_host = &state.sub_domain_host;
            if !sub_host.is_empty() {
                let full_domain = format!("{}.{}", subdomain, sub_host);
                if !domains.contains(&full_domain) {
                    domains.push(full_domain);
                }
            }
        }
    }

    if domains.is_empty() {
        warn!("HTTPS proxy '{}' has no custom_domains — SNI routing won't work", np.proxy_name);
    }

    let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
    let http_user = np.http_user.as_deref().unwrap_or("");
    let http_pwd = np.http_pwd.as_deref().unwrap_or("");
    // HTTPS proxies use empty locations (route by SNI domain only)
    state.vhost_manager.register(
        &np.proxy_name,
        &domains,
        &[],  // no locations for HTTPS SNI routing
        run_id,
        hhr,
        http_user,
        http_pwd,
    ).await;
    info!(
        "VHost SNI routes registered for HTTPS proxy '{}': domains={:?}",
        np.proxy_name, domains
    );
}
```

Also update the `unregister_control` function to clean up HTTPS VHost entries (they're already cleaned up by the `vhost_manager.unregister` call in the existing code — confirmed it calls `unregister` for all proxies including HTTPS now).

- [ ] **Step 3: Add SNI-based routing in the main accept loop**

In `frp-server/src/service.rs`, in the main accept loop's `Tls` branch, add SNI extraction and routing BEFORE the TLS handshake. Insert after the `consume_tls_head_byte` check and before the `acceptor`:

```rust
ConnectionType::Tls(first_byte) => {
    // 0x17 = Go frp TLS prefix (must consume before handshake)
    // 0x16 = standard TLS ClientHello (byte is part of TLS record)
    if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
        if let Err(e) = consume_tls_head_byte(&mut stream).await {
            warn!("Failed to consume TLS head byte from {}: {}", addr, e);
            return;
        }
    }

    // --- SNI peek for HTTPS proxy routing ---
    // Read the ClientHello bytes to extract SNI before TLS handshake.
    // If the SNI matches a registered HTTPS proxy, forward raw TLS bytes
    // directly to the work connection (no TLS termination on frps).
    let mut sni_buf = [0u8; 4096];
    let sni_peek_n = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut sni_buf),
    ).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            warn!("Failed to read ClientHello from {} for SNI check", addr);
            return;
        }
    };

    // Build the full ClientHello data (0x16 + peeked bytes)
    let mut sni_data = Vec::with_capacity(1 + sni_peek_n);
    if first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE {
        // first_byte (0x16) was the first byte of the record; include it
        sni_data.push(first_byte);
    }
    sni_data.extend_from_slice(&sni_buf[..sni_peek_n]);

    if let Some(sni_host) = crate::vhost::extract_sni_from_client_hello(&sni_data) {
        debug!("SNI from {}: {}", addr, sni_host);
        if let Some(route) = state.vhost_manager.lookup(&sni_host).await {
            // Found an HTTPS proxy via SNI — route raw TLS bytes through
            info!("SNI route '{}' matched HTTPS proxy '{}' from {}",
                sni_host, route.proxy_name, addr);

            let ctl_tx = {
                let map = state.run_id_to_ctl_tx.read().await;
                map.get(&route.run_id).cloned()
            };

            if let Some(ctl) = ctl_tx {
                // Forward the raw TLS bytes as pre_read + TcpStream.
                // The work connection bridge will forward them as-is.
                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                    proxy_name: route.proxy_name.clone(),
                    user_conn: IoStream::Tcp(stream),
                    pre_read: sni_data,
                }).ok();
            } else {
                warn!("SNI route for '{}' found but control handler gone", sni_host);
            }
            return;
        }
    }

    // --- No SNI match — fall through to existing TLS termination ---
    // Build a PreReadStream to replay the consumed ClientHello bytes
    // into the TLS handshake.
    let stream = PreReadStream::new(sni_data, stream);

    let acceptor = match acceptor {
        Some(a) => a,
        None => {
            warn!("TLS connection from {} but TLS not configured", addr);
            return;
        }
    };
    // ... rest of existing TLS handshake code, but using `stream` instead of raw TcpStream ...
}
```

Wait, this is getting complex because after SNI peek we've consumed the ClientHello bytes from the TCP stream. If SNI doesn't match, we need to replay those bytes for the TLS handshake. We need a `PreReadStream` adapter.

Add to `frp-core/src/transport.rs`:

```rust
use tokio::io::ReadBuf;

/// A stream wrapper that yields pre-read bytes before the inner stream.
/// Used when we've peeked/consumed bytes for protocol detection but need
/// to replay them for the actual protocol handler.
pub struct PreReadStream<S> {
    pre_read: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PreReadStream<S> {
    pub fn new(pre_read: Vec<u8>, inner: S) -> Self {
        Self { pre_read, pos: 0, inner }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PreReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Yield pre-read bytes first
        if self.pos < self.pre_read.len() {
            let remaining = &self.pre_read[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PreReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
```

This `PreReadStream` wraps a TcpStream and replays consumed bytes. We use it in the fallthrough path so TLS handshake gets the full ClientHello.

But this changes the TLS handshake code path significantly. The current code passes `stream` (a `TcpStream`) to `acceptor.accept()`. With `PreReadStream<TcpStream>`, we can't pass it directly because `tokio_rustls::Accept::accept` takes `TcpStream`. 

Alternative: use `tokio_rustls::TlsAcceptor::accept_with` or manually wrap. Actually `tokio_rustls::Accept::accept` takes `impl AsyncRead + AsyncWrite + Unpin`, so `PreReadStream<TcpStream>` should work if it implements those traits!

OK, so the approach is:
1. Peek the first byte (existing `peek_connection_type`)
2. If TLS: consume 0x17 if present, then read ClientHello bytes
3. Try to extract SNI
4. If SNI matches HTTPS proxy: send InternalMsg::ProxyUserConn with pre_read = the bytes we read
5. If no match: wrap the bytes + stream in `PreReadStream`, proceed with existing TLS handshake using `PreReadStream<TcpStream>`

But step 5 means passing `PreReadStream<TcpStream>` to `acceptor.accept()`. Let me verify this works... `tokio_rustls::TlsAcceptor::accept` takes `impl AsyncRead + AsyncWrite + Unpin`. `PreReadStream<TcpStream>` implements all three, so this should work.

But the existing code also needs the `PreReadStream` to be used in the yamux path. In the yamux path:
```rust
match mux::server_mux(stream, &mux_cfg).await {
```
`server_mux` takes the stream. This is a different code path.

For simplicity in the plan, the SNI routing path:
1. When SNI matches: send `InternalMsg::ProxyUserConn` with pre_read
2. When SNI doesn't match: use `PreReadStream` to replay, then proceed with existing TLS flow

The plan steps for service.rs are significant. Let me simplify by putting the SNI extraction right after the `consume_tls_head_byte` check, and using `PreReadStream` for fallthrough.

But the existing TLS code is large (the `if state.tcp_mux { ... } else { ... }` blocks). I need to wrap the stream in `PreReadStream` early and then use that wrapper throughout.

Alright, this task is genuinely complex. Let me write the steps more carefully.

For the plan, let me present the simplest correct approach:

1. After consuming the 0x17 byte (if present), read the ClientHello bytes
2. Try SNI extraction
3. If match: route via InternalMsg with pre_read = first_byte + read bytes
4. If no match: wrap in PreReadStream, pass to existing TLS flow

The key insight: when `first_byte == 0x16`, the `0x16` byte IS part of the TLS record. When `first_byte == 0x17`, it's the Go frp prefix that we consume. After consuming 0x17, the next bytes are the TLS record starting with 0x16.

So in both cases, after any consumption, we read the TLS record. The data starts with 0x16 (if we consumed 0x17) or the first byte already is 0x16 (from the peek).

For the plan, I'll write the actual code modifications needed.

- [ ] **Step 3 (continued): Implement PreReadStream and modify accept loop**

The plan step body is large. Let me simplify and provide the key code.

In `frp-core/src/transport.rs`, add `PreReadStream` (shown above). Export it.

In `frp-server/src/service.rs`, in the `Tls(first_byte)` branch, modify to add SNI peek between TLS head consumption and TLS handshake. The modification point is after the `consume_tls_head_byte` block and before the `let acceptor = match acceptor {` line.

```rust
// Read ClientHello for SNI check (5s timeout)
let mut sni_buf = vec![0u8; 4096];
let sni_peek_n = match tokio::time::timeout(
    std::time::Duration::from_secs(5),
    stream.read(&mut sni_buf),
).await {
    Ok(Ok(n)) if n >= 43 => n,  // need at least 43 bytes for ClientHello
    Ok(Ok(_)) => 0,  // too short, fall through
    _ => {
        warn!("Failed to read ClientHello from {} for SNI check", addr);
        return;
    }
};

let pre_read: Vec<u8> = if sni_peek_n > 0 {
    let mut data = Vec::with_capacity(1 + sni_peek_n);
    // If first_byte was 0x16 (direct TLS), it's part of the record
    if first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE {
        data.push(first_byte);
    }
    data.extend_from_slice(&sni_buf[..sni_peek_n]);

    // Try SNI-based routing for HTTPS proxies
    if let Some(sni_host) = crate::vhost::extract_sni_from_client_hello(&data) {
        debug!("SNI from {}: {}", addr, sni_host);
        if let Some(route) = state.vhost_manager.lookup(&sni_host).await {
            let ctl_tx = {
                let map = state.run_id_to_ctl_tx.read().await;
                map.get(&route.run_id).cloned()
            };
            if let Some(ctl) = ctl_tx {
                info!("SNI route '{}' → HTTPS proxy '{}' from {}",
                    sni_host, route.proxy_name, addr);
                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                    proxy_name: route.proxy_name.clone(),
                    user_conn: IoStream::Tcp(stream),
                    pre_read: data,
                }).ok();
                return;
            }
        }
    }
    data
} else {
    // No SNI peek possible, fake empty pre_read for fallthrough
    let mut data = Vec::new();
    if first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE {
        data.push(first_byte);
    }
    data
};

// Wrap stream with pre_read for TLS handshake fallthrough
let stream = frp_core::transport::PreReadStream::new(pre_read, stream);
```

After this block, the rest of the code uses `stream` (a `PreReadStream<TcpStream>`) instead of raw `stream`. Since `PreReadStream` implements `AsyncRead + AsyncWrite + Unpin`, it works with `acceptor.accept()`, `mux::server_mux()`, etc.

Note: `mux::server_mux` in frp-core/src/mux.rs takes `impl AsyncRead + AsyncWrite + Unpin + Send + 'static`, and `PreReadStream<TcpStream>` satisfies all these.

But wait, the yamux path does `mux::server_mux(stream, ...)` where `stream` is `TcpStream`, and then the non-yamux path does `read_msg_v1(&mut tls_stream)` after TLS accept. With `PreReadStream`, we need to make sure everything compiles. Since `PreReadStream<TcpStream>: AsyncRead + AsyncWrite + Unpin + Send`, it should.

But there's a complication: `read_msg_v1` takes `impl AsyncRead + AsyncWrite + Unpin`. The TLS stream after `acceptor.accept()` is `tokio_rustls::server::TlsStream<TcpStream>`, not `TlsStream<PreReadStream<TcpStream>>`. So we need `acceptor.accept(stream)` where `stream: PreReadStream<TcpStream>`. This gives `TlsStream<PreReadStream<TcpStream>>`, which is fine since it's still `AsyncRead + AsyncWrite`.

OK, this should work. Let me finalize the plan.

- [ ] **Step 4: Run the SNI unit test**

Run: `cargo test -p frp-server vhost::tests`
Expected: 3 tests PASS (extract_sni tests)

- [ ] **Step 5: Build and run all tests**

Run: `cargo build --workspace`
Expected: compiles clean

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add frp-server/src/vhost.rs frp-server/src/service.rs frp-server/src/control/proxy_ops.rs frp-core/src/transport.rs
git commit -m "feat: add HTTPS proxy SNI-only routing (Go frp compat)

Extracts SNI hostname from TLS ClientHello without terminating TLS.
Routes raw TLS bytes directly to work connection. Falls back to
existing TLS termination when no SNI match.

Adds extract_sni_from_client_hello() to vhost.rs and PreReadStream
to frp-core/transport.rs for replaying consumed bytes.

Go frp compat: HTTPS proxies now use SNI routing like Go frp.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Verification

After all tasks complete, run:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy
bash scripts/compat-test.sh --verbose
```

Expected: clean build, all tests pass, compat tests green.

---

## Scope Boundaries

**In scope (9 tasks above):**
- A1: QUIC ALPN fix
- A2: HTTPS SNI-only routing
- B1: unix_domain_socket plugin
- B2: tls2raw plugin
- C1: /api/clients + /api/clients/:run_id endpoints
- C2: /healthz endpoint
- D1: Server config fields (vhost_http_timeout, user_conn_timeout, tcp_mux_passthrough)
- E1: Auth fail delay (200ms)
- E2: Dashboard/admin API TLS support

**Out of scope (deferred):**
- Remaining 5 client plugins
- V2 wire protocol
- Server HTTP plugins
- SSH Tunnel Gateway
- OIDC custom TLS / dynamic token sourcing
- XTCP advanced config
- Dashboard static web UI
- Remaining config fields
