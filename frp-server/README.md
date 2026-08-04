# frp-server

Server library for frp-rs. Handles client control connections, proxy
registration, connection dispatching, and traffic bridging.

## Architecture

The server's core is an **accept loop** + **cross-task message passing**
pattern:

```
TCP/WS/KCP/QUIC accept → read first frame → dispatch by message type
  ├── Login         → handle_control()     (new control connection)
  ├── NewWorkConn   → handle_work_conn()   (route to handler via run_id)
  ├── NewVisitorConn → handle_visitor()    (STCP, sk lookup)
  └── NatHoleVisitor → handle_nat_hole()   (XTCP hole punch)
```

Each control connection runs in its own task with a `tokio::select!` loop
(see [`control/mod.rs`](src/control/mod.rs)).

## Modules

| Module | Purpose |
|--------|---------|
| `state` | `AppState`, `InternalMsg` enum, `ControlTx`, `ReloadableState` |
| `service` | Accept loop, connection dispatch, `Service::new()`, config reload |
| `handlers` | `handle_visitor_conn_inner`, `handle_nat_hole_visitor`, `handle_work_conn_inner` |
| `control/mod` | Per-client control handler, work pool, `select!` loop |
| `control/bridge` | Encrypted/plain bridge, `ResponseHeaderInjector`, `assign_work_to_proxy` |
| `control/proxy_ops` | `NewProxy`/`CloseProxy` handler, `listen_and_proxy` |
| `proxy` | `ProxyManager`, `ProxyInfo`, port allocation, `used_ports` tracking |
| `vhost` | HTTP/HTTPS VHost routing, Host header parsing, SNI |
| `tcpmux` | TCPMux HTTP CONNECT domain routing |
| `dashboard` | Dashboard web UI + REST API (axum) |
| `nathole` | XTCP NAT hole-punch coordinator, NAT classification, behavior analysis |
| `metrics/prom` | Prometheus gauge registry + `/metrics` text rendering |
| `plugin` | Server-side HTTP plugin manager |
| `ssh_gateway` | SSH tunnel gateway (russh, feature-gated) |

## Internal Message Passing

`InternalMsg` variants drive the work connection lifecycle:

```
ProxyUserConn / VisitorConn
  → check work_pool
  → if empty: send ReqWorkConn, push to pending_requests
  → if available: bridge immediately

NewWorkConn
  → if pending_requests: pop and bridge
  → else: push to work_pool

UdpNeedsWorkConn
  → triggers work connection creation for UDP proxy
```

## Usage

```rust
use frp_server::service::Service;
use frp_server::state::AppState;

// `config_file` is optional (`None` when no config-file reload is wanted)
let service = Service::new(config, config_file).await?;
service.run().await?;
```

Add to `Cargo.toml`:
```toml
frp-server = { path = "../frp-server" }
```

## Feature Flags

All features below are enabled by default (`default = ["websocket", "kcp",
"quic", "oidc", "tls", "http-proxy", "vnet", "compression", "chacha20",
"tcp-mux", "ssh"]`) except `dashboard`, which is opt-in.

| Feature | Removes |
|---------|---------|
| `dashboard` | Prometheus metrics, axum status API (opt-in) |
| `ssh` | SSH gateway (russh) |
| `oidc` | OIDC token verification |
| `http-proxy` | HTTP proxy plugin (reqwest) |
| `websocket` | WebSocket transport listener |
| `quic` | QUIC transport listener |
| `kcp` | KCP transport listener |
| `tls` | TLS encryption (rustls, tokio-rustls) |
| `vnet` | Virtual net TUN support (frp-vnet) |
| `compression` | Snappy compression support |
| `chacha20` | ChaCha20-Poly1305 encryption |
| `tcp-mux` | yamux TCP multiplexing |
