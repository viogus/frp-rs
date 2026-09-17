# Go frp v0.69.1 Feature Alignment — v0.2.0

> Design spec. Based on compatibility audit at `docs/go-frp-compat-audit.md`.

**Goal:** Close the highest-impact gaps between frp-rs and Go frp v0.69.1 in one release cycle.

**Approach:** Top 1-2 picks from each of 5 areas (transport, plugins, dashboard, config, security).

**Target:** ~600 lines across 9 items.

---

## Area A: Transport/Protocol Compat

### A1: QUIC ALPN Fix

**File:** `frp-core/src/quic.rs`

**Current:** ALPN set to `"frp-rs"`. Go frp uses `"frp"`. Never interoperable — no regression risk.

**Change:** Replace `"frp-rs"` → `"frp"` in both server config ALPN list and client dial ALPN.

**Verification:** Run `cargo test --workspace`. No dedicated QUIC compat test exists yet.

---

### A2: HTTPS Proxy — SNI-Only Routing

**Problem:** frp-rs terminates TLS on the server for HTTPS proxies (requires `tls_cert_file`/`tls_key_file`). Go frp does NOT terminate TLS — it peeks the SNI hostname from the TLS ClientHello and forwards raw TLS bytes to the backend. The current model is incompatible with Go frpc HTTPS proxies.

**Design:**

1. **SNI extraction** (`frp-server/src/vhost.rs`): New function `extract_sni_from_clientHello(data: &[u8]) -> Option<String>`. Parses TLS ClientHello per RFC 6066, reads the SNI extension's server_name field. Returns hostname or None.

2. **Accept loop change** (`frp-server/src/service.rs`): In the main accept loop, after detecting a TLS connection (`ConnectionType::Tls(first_byte)`), extract SNI *before* the TLS handshake:
   ```
   peek TLS bytes → extract SNI → lookup vhost_manager → if HTTPS proxy found:
     forward raw bytes (pre-read + stream) to work connection via InternalMsg
     (no TLS termination)
   ```

   Fallback: if SNI lookup fails, fall through to existing TLS termination path (for the dashboard, vhost_https_port, etc.).

3. **Proxy registration** (`frp-server/src/control/proxy_ops.rs`): Register `https`-type proxies with `vhost_manager` (currently only `http`-type is registered). Use empty locations (HTTPS proxies route by domain only, not path).

4. **Data path:** `InternalMsg::ProxyUserConn` carries `pre_read` bytes (already supported). The SNI-peeked bytes + the raw TLS stream are forwarded through the work connection bridge without any TLS processing on frps.

**Config impact:** None. Existing `https` proxy types automatically use SNI routing. No server TLS cert needed for HTTPS proxy routing.

**Verification:** Unit test SNI parsing with known ClientHello bytes. Integration test: Go frpc → frp-rs frps (HTTPS proxy type).

---

## Area B: Client Plugins

### B1: unix_domain_socket Plugin

**File:** New `frp-client/src/plugin/unix_socket.rs`

**What:** Connect frpc proxy tunnel to a local Unix domain socket instead of TCP.

**Config:** Plugin type `"unix_domain_socket"`, path from `plugin_local_addr`. Example:
```toml
[[proxies]]
name = "docker_sock"
type = "tcp"
remote_port = 2375
plugin = "unix_domain_socket"
plugin_local_addr = "/var/run/docker.sock"
```

**Implementation:**
```rust
use tokio::net::UnixStream;

pub async fn connect_unix_socket(path: &str) -> Result<UnixStream, String> {
    UnixStream::connect(path).await.map_err(|e| format!("unix socket: {e}"))
}
```

Register in `plugin/mod.rs` dispatch: match `"unix_domain_socket"` → `connect_unix_socket()`.

**~80 lines.** No TLS, no auth — raw Unix socket. Go frp compat: matches `UnixDomainSocketPlugin`.

---

### B2: tls2raw Plugin

**File:** New `frp-client/src/plugin/tls2raw.rs`

**What:** frpc connects to local service via TLS, forwards decrypted plaintext through the frp tunnel. Go frp's `TLSToRawPlugin`.

**Config:**
```toml
[[proxies]]
name = "https_backend"
type = "tcp"
remote_port = 443
plugin = "tls2raw"
plugin_local_addr = "127.0.0.1:8080"
```

TLS config: use existing proxy-level `tls_server_name` for SNI. Use system root CAs for server verification (no custom CA for now).

**Flow:**
```
User TLS → frps → frp tunnel → frpc → TLS connect → local plaintext service
                        (encrypted)    ↑ frpc is TLS client
```

**Implementation:**
```rust
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;

pub async fn connect_tls2raw(addr: &str, server_name: Option<&str>) -> Result<TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| format!("tcp: {e}"))?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_certs())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let domain = server_name.unwrap_or_else(|| extract_host(addr));
    let tls = connector.connect(domain.try_into().map_err(|_| "invalid domain")?, tcp).await
        .map_err(|e| format!("tls: {e}"))?;
    Ok(tls)
}
```

**~120 lines.** Register in `plugin/mod.rs` dispatch.

---

## Area C: Dashboard/API

### C1: `/api/clients` + `/api/clients/:run_id`

**File:** `frp-server/src/dashboard.rs`

**New endpoint:** `GET /api/clients` — list all connected clients.

**Response:**
```json
[{
  "run_id": "...",
  "client_addr": "10.0.0.1:54321",
  "online": true,
  "login_time_secs": 1234,
  "proxy_count": 3,
  "proxies": ["ssh", "web", "db"]
}]
```

**New endpoint:** `GET /api/clients/:run_id` — single client detail with proxy list.

**Data source changes:**
- `ControlTx` struct (`frp-server/src/service.rs`): Add `client_addr: Option<SocketAddr>` and `login_time: Instant`.
- Populated at login (`frp-server/src/control/mod.rs`).

**Handler:**
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
```

**~80 lines handler + ~30 lines struct changes + ~30 lines proxy_manager.**

---

### C2: `/healthz`

**File:** `frp-server/src/dashboard.rs`

**What:** Standard health check endpoint for container orchestration.

```rust
async fn handle_healthz() -> &'static str { "ok" }
```

**No auth.** Merged into main router outside `apply_admin_auth` layer.

**~5 lines.**

---

## Area D: Config Parity

### D1: High-Impact Server Config Fields

**File:** `frp-core/src/config.rs`, `frp-server/src/service.rs`, `frp-server/src/vhost.rs`, `frp-server/src/control/proxy_ops.rs`

Three new fields in `ServerConfig`:

| Field | Type | Default | Go frp field | Usage |
|-------|------|---------|-------------|-------|
| `vhost_http_timeout` | `u64` | `60` | `VhostHTTPTimeout` | Timeout (seconds) for backend HTTP response in VHost handler. Pass to `tokio::time::timeout` around proxy bridging. |
| `user_conn_timeout` | `u64` | `10` | `UserConnTimeout` | Idle timeout (seconds) on user-facing proxy connections. If no data flows for this duration, close the connection. Apply in `listen_and_proxy`. |
| `tcp_mux_passthrough` | `bool` | `false` | `TCPMuxPassthrough` | When tcp_mux is enabled and yamux init fails on a new connection, forward bytes as-is to the VHost handler instead of closing. |

**Implementation pattern:**
```rust
// config.rs
#[serde(default = "default_vhost_http_timeout")]
pub vhost_http_timeout: u64,

// service.rs AppState
pub vhost_http_timeout: u64,

// vhost.rs
tokio::time::timeout(
    Duration::from_secs(state.vhost_http_timeout),
    bridge_streams(...)
).await
```

**~40 lines config + ~30 lines wiring. All three have sensible defaults, zero behavior change if not configured.**

---

## Area E: Security/Operational

### E1: Auth Fail Delay

**File:** `frp-core/src/admin_auth.rs`

**Change:** Insert 200ms delay before returning 401.

```rust
// Inside check_auth, auth failure branch:
tokio::time::sleep(std::time::Duration::from_millis(200)).await;
return (StatusCode::UNAUTHORIZED, ...).into_response();
```

**Matches Go frp's `authFailDelay` constant default (200ms).**

**~2 lines. No config — hardcoded 200ms matches Go frp behavior.**

---

### E2: Dashboard / Admin API TLS

**Files:** `frp-server/src/dashboard.rs`, `frp-client/src/admin.rs`, `frp-core/src/config.rs`

**Config:** Two new fields in `WebServer` config section:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tls_cert_file` | `String` | `""` | Path to TLS certificate PEM |
| `tls_key_file` | `String` | `""` | Path to TLS private key PEM |

When both are non-empty, the dashboard/admin server starts a TLS listener. When empty (default), plain HTTP — no behavior change.

**Implementation:**
```rust
pub async fn run_dashboard(
    addr: String,
    state: Arc<AppState>,
    auth_user: String,
    auth_password: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(state, auth_user, auth_password);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let acceptor = frp_core::transport::build_tls_acceptor(&cert, &key, None)?;
            // Poll TcpListener, accept, wrap in TLS, serve
            // ... (same pattern as service.rs accept loop TLS path)
        }
        _ => {
            axum::serve(listener, app).await?;
        }
    }
}
```

**Same pattern for `run_admin_server` in `frp-client/src/admin.rs`.**

**~50 lines config + ~50 lines server wiring + ~30 lines client wiring.**

---

## Verification

| Item | Test Strategy |
|------|--------------|
| A1 | Existing tests pass; manual QUIC compat test |
| A2 | Unit test SNI parser; compat test Go frpc → frp-rs frps (HTTPS type) |
| B1 | Unit test Unix socket connect |
| B2 | Unit test TLS connect + forward |
| C1 | `api_tests.rs` integration test |
| C2 | `api_tests.rs` integration test |
| D1 | Existing tests pass (defaults unchanged); manual timeout test |
| E1 | Unit test delay present in 401 path |
| E2 | Manual test with self-signed cert |

---

## Scope Boundaries

**In scope:** 9 items above.

**Out of scope (deferred):**
- Remaining 5 client plugins (http2https, https2http, https2https, http2http, virtual_net)
- V2 wire protocol
- Server HTTP plugins (`httpPlugins`)
- SSH Tunnel Gateway
- OIDC custom TLS / dynamic token sourcing
- XTCP advanced config (KCP/QUIC P2P transport, retry limiting)
- Dashboard static web UI, `/api/proxy/{type}` filter, client delete
- Remaining config fields (pprof, custom 404, store_config, feature_gates, etc.)
