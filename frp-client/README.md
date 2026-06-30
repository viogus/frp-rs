# frp-client

Client library for frp-rs. Manages the control connection to frps, registers
proxies, spawns work connections, bridges local services to the server, and
runs client-side plugins.

## Architecture

```
Service::run()
  ├── Login handshake (token/OIDC)
  ├── Register proxies (NewProxy)
  ├── Start plugins (http_proxy, socks5, static_file, etc.)
  ├── Spawn work connection pool
  ├── Start admin API server
  └── Main select! loop
        ├── Inbound messages from server (ReqWorkConn, StartWorkConn, Ping)
        ├── Plugin accept events
        ├── Health check ticks
        └── Admin reload requests
```

## Modules

| Module | Purpose |
|--------|---------|
| `service` | Main `Service::run()` loop, proxy registration, plugin startup |
| `control` | `ControlConnection`, login handshake, V2 negotiation, hostname resolution |
| `proxy` | `NewProxy` message builder, local TCP connect, bridge to IoStream |
| `work_conn` | `WorkConnConfig`, `spawn_work_conn`, V2 protocol write, XTCP notification |
| `plugin` | Plugin dispatch: 9 plugin types + visitor plugin |
| `admin` | Admin REST API server (status, config, reload, stop) |
| `health` | TCP/HTTP health checks for proxies |
| `visitor` | `tcp_simultaneous_open`, STCP/XTCP visitor listener |
| `reload` | `config_snapshot`, `do_reload` for hot config reload |

## Login Flow

```
Client                                    Server
  │                                         │
  │  Login { version, token, timestamp }   │
  │───────────────────────────────────────>│
  │                                         │ verify MD5(token+timestamp)
  │  LoginResp { version, run_id, error }  │
  │<───────────────────────────────────────│
  │                                         │
  │  NewProxy { proxy_name, type, ... }    │
  │───────────────────────────────────────>│
  │  NewProxyResp { proxy_name, remote_port }│
  │<───────────────────────────────────────│
```

After login, the client enters its main loop. Work connections are created on
demand (when the server sends `ReqWorkConn`) or pre-allocated via `pool_count`.

## Client Plugins

| Plugin | Description |
|--------|-------------|
| `http_proxy` | HTTP/HTTPS forward proxy |
| `socks5` | SOCKS5 proxy |
| `static_file` | Static file serving |
| `unix_domain_socket` | Unix socket proxy |
| `tls2raw` | TLS termination → raw TCP forward |
| `http2http` | HTTP → HTTP tunnel |
| `http2https` | HTTP → HTTPS tunnel |
| `https2http` | HTTPS → HTTP tunnel |
| `https2https` | HTTPS → HTTPS tunnel |
| `visitor_plugin` | STCP/XTCP visitor (NAT traversal) |

## Usage

```rust
use frp_client::service::Service;

let service = Service::new(config).await?;
service.run().await?;
```

Add to `Cargo.toml`:
```toml
frp-client = { path = "../frp-client" }
```

## Feature Flags

| Feature | Removes |
|---------|---------|
| `oidc` | OIDC token acquisition |
| `websocket` | WebSocket transport (dial) |
| `quic` | QUIC transport (dial) |
| `kcp` | KCP transport (dial) |
| `tls` | TLS transport (rustls, tokio-rustls) |
| `compression` | Snappy bridge compression |
| `chacha20` | XChaCha20-Poly1305 V2 cipher |
