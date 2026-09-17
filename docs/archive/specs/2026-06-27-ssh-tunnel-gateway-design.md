# SSH Tunnel Gateway — Design Spec

**Date:** 2026-06-27
**Status:** Draft
**Scope:** New feature — SSH reverse tunnel as frpc replacement

## Overview

Add an SSH tunnel gateway to frps, matching Go frp v0.69.1 behavior. Users connect with a standard
SSH client using `ssh -R` reverse tunnels to create frp proxies without running frpc. The SSH
server runs on a separate port alongside the main frps accept loop.

## Configuration

### New struct: `SshTunnelGatewayConfig` (`frp-core/src/config.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelGatewayConfig {
    /// SSH listen port. 0 = disabled (default).
    #[serde(default)]
    pub bind_port: u16,

    /// SSH listen address. Default: "0.0.0.0".
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Path to SSH host private key file. Auto-generated if empty and
    /// auto_gen_private_key_path does not exist.
    #[serde(default)]
    pub private_key_file: String,

    /// Path where auto-generated SSH host key is written.
    /// Default: "./.autogen_ssh_key".
    #[serde(default = "default_autogen_ssh_key_path")]
    pub auto_gen_private_key_path: String,

    /// Path to SSH authorized_keys for optional public key auth.
    /// Empty = password auth only.
    #[serde(default)]
    pub authorized_keys_file: String,
}

fn default_autogen_ssh_key_path() -> String { "./.autogen_ssh_key".into() }
```

### TOML example

```toml
[ssh_tunnel_gateway]
bind_port = 2200
bind_addr = "0.0.0.0"
private_key_file = ""
auto_gen_private_key_path = "./.autogen_ssh_key"
authorized_keys_file = ""
```

### Integration

- New field `ssh_tunnel_gateway: SshTunnelGatewayConfig` on `ServerConfig`
- `bind_port = 0` → SSH gateway disabled (default)
- `bind_port > 0` → `Service::run()` spawns SSH listener on startup
- Config normalization: Go compat aliases `sshTunnelGateway.bindPort` etc. handled by existing
  camelCase→snake_case normalization

## Authentication

### Password auth

SSH password = frp server token (`[auth].token`). Username is ignored (Go frp convention: use
`v0`). If server token is empty, password auth is disabled.

```bash
ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090
# Password: <frp server token>
```

### Public key auth (optional)

If `authorized_keys_file` is set and the file exists, SSH public key authentication is offered
alongside password auth. A key found in the file authenticates immediately. A key not found
falls through to password auth.

### Key management

- Host key type: Ed25519 (russh default)
- Auto-generation: if `private_key_file` is empty AND `auto_gen_private_key_path` doesn't
  exist on disk, generate a new Ed25519 key and write it to `auto_gen_private_key_path`
- Existing key reuse: if either path points to a valid key, load it

### No OIDC

Go frp doesn't support OIDC for SSH, and SSH keyboard-interactive would need custom plumbing.
YAGNI.

## Protocol Flow

### Connection lifecycle

```
1. SSH client connects to SSH port, TCP handshake
2. SSH key exchange (Ed25519 host key)
3. Client authenticates (password or public key)
4. Client sends remote command: "<type> --proxy_name <name> [flags...]"
5. Client sends -R reverse-forward bind request: e.g., :80:127.0.0.1:8080
6. Server parses proxy config, allocates remote_port
7. Server registers proxy via virtual control channel → handle_control()
8. Server accepts SSH reverse-forward channel (TCP-over-SSH) when opened
9. External user connects to remote_port → frps creates work connection
10. Bridge: user_conn ↔ work_conn ↔ SSH reverse channel ↔ local service
```

### SSH remote command parsing

The remote command string is parsed like frpc CLI args. Supported types: `tcp`, `http`, `https`,
`stcp`, `tcpmux`. Each type accepts the same flags as the corresponding frpc proxy type.

Example commands:

```bash
# TCP
ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcp --proxy_name "web" --remote_port 9090

# HTTP with custom domains
ssh -R :80:127.0.0.1:3000 v0@server -p 2200 http --proxy_name "blog" --custom_domains "blog.example.com"

# STCP with secret key
ssh -R :80:127.0.0.1:22 v0@server -p 2200 stcp --proxy_name "secret-ssh" --sk "mysecret"

# TCPMux
ssh -R :80:127.0.0.1:8080 v0@server -p 2200 tcpmux --proxy_name "mux" --multiplexer "httpconnect"
```

### Bridge chain

```
User ──TCP──► frps:remote_port
                │
                ▼ InternalMsg::ProxyUserConn
           Control Handler
                │
                ▼ StartWorkConn over virtual control channel
           SSH Gateway
                │
                ▼ SSH reverse-forward channel
           SSH Client ──TCP──► local:8080
```

The work connection is an SSH channel, wrapped as `IoStream::SshChannel` so the existing
bridge code handles it transparently.

### Proxy lifecycle

- **Register:** first `ssh -R` on a session → synthesize run_id → create virtual control
  connection → register proxy via existing `handle_control()` path
- **Second proxy:** same SSH session, same run_id, same virtual control connection
- **Close:** SSH session disconnects → all proxies for run_id removed via
  `ProxyManager::remove_client()`
- **Duplicate name:** registering an already-existing proxy name → rejected by existing
  ProxyManager dedup check

## Architecture

### New module: `frp-server/src/ssh_gateway.rs`

Three main components:

#### 1. `SshListener`

Accept loop. Binds TCP on `bind_addr:bind_port`. On startup, auto-generates SSH host key if
needed. Each inbound connection → russh `SshServer` handshake → authenticated session →
spawn `SshSession`.

Fields:
- `config: SshTunnelGatewayConfig`
- `server_token: String`
- `state: Arc<AppState>` — shared server state (proxy manager, auth config, etc.)
  for spawning `handle_control()` tasks directly

#### 2. `SshSession`

Per-client SSH session handler. Implements russh `server::Handler` trait.

Fields:
- `run_id: String` — synthesized on first proxy registration (random hex)
- `registered_proxies: Vec<String>` — for cleanup on disconnect
- `ssh_handle: russh::server::Handle` — to open/accept reverse-forward channels
- `internal_tx: mpsc::UnboundedSender<InternalMsg>` — sends ProxyUserConn, NewWorkConn, etc.
  to the control handler's internal channel
- `work_conn_requests: mpsc::UnboundedReceiver<WorkConnRequest>` — receives work connection
  requests from the virtual control write side

Key handlers:
- `shell_request()` / `exec_request()` — parse remote command, build proxy config
- `channel_open_forwarded_tcpip()` — reverse-forward channel opened by client (data forward to local)
- `tcpip_forward()` — reverse-forward bind request

#### 3. Virtual control channel + work connection bridge

SSH sessions don't have a TCP control connection. Two coordinated mechanisms bridge the gap:

**Virtual control channel (proxy registration path):**

```
SshSession ──mpsc tx──► VirtualCtrlRead ──read_msg_v1──► handle_control()
                        VirtualCtrlWrite ◄──write_msg_v1──
```

- `VirtualCtrlRead`: implements `AsyncRead` by polling an `mpsc::UnboundedReceiver<Vec<u8>>`.
  Each `NewProxy` message is serialized to V1 wire format and pushed through. `handle_control()`
  reads `NewProxy` → registers the proxy, exactly as with frpc.
- `VirtualCtrlWrite`: implements `AsyncWrite`. Most outbound V1 messages (heartbeats, proxy
  responses) are consumed and ignored. But `ReqWorkConn` messages are intercepted:

**Work connection creation (ReqWorkConn → SSH channel):**

When `handle_control()` needs a work connection (triggered by `InternalMsg::ProxyUserConn`),
it writes `ReqWorkConn` via V1 protocol. The `VirtualCtrlWrite` intercepts this and sends a
`WorkConnRequest` to the SSH session instead of serializing it:

```
handle_control() ──ReqWorkConn──► VirtualCtrlWrite ──WorkConnRequest──► SshSession
                                                                           │
                                                                     opens SSH reverse-
                                                                     forward channel
                                                                           │
                                                                           ▼
SshSession ──InternalMsg::NewWorkConn──► control handler internal_rx
                                                                           │
                                                                           ▼
                                                                    assign_work_to_proxy()
                                                                    bridges: user ↔ work(SSH)
```

The `WorkConnRequest` contains the proxy's `local_addr` (from `-R` bind). The SSH session
forwards this to the SSH client, which opens a TCP connection to the local service. That
TCP connection becomes an SSH channel → wrapped as `IoStream::SshChannel` → sent as
`InternalMsg::NewWorkConn` to the control handler → bridged to the user connection.

The control handler's `handle_control()` sees a normal `IoStream` on both the read side
(virtual control) and the work connection side (SSH channel via InternalMsg). Zero changes
to `handle_control()` itself.

### IoStream addition: `SshChannelStream`

In `frp-core/src/transport.rs`, add `IoStream::SshChannel` variant:

```rust
pub enum IoStream {
    Tcp(TcpStream),
    Tls(TlsStream<TcpStream>),
    Duplex(DuplexStream),
    WebSocket(WsByteStream),
    SshChannel(SshChannelStream),  // NEW
}
```

`SshChannelStream` wraps a russh `server::Channel<server::Msg>` and implements `AsyncRead` +
`AsyncWrite`. Same pattern as existing `WsByteStream` (~60 lines). `frp-core` depends on
russh only via `SshChannelStream` — the russh types are behind this wrapper; `frp-core`'s
Cargo.toml adds `russh` as optional dependency gated by a feature flag.

### Integration points

| File | Change | Impact |
|------|--------|--------|
| `frp-core/src/config.rs` | Add `SshTunnelGatewayConfig`, field on `ServerConfig` | Low |
| `frp-core/src/transport.rs` | Add `SshChannelStream`, `IoStream::SshChannel` | Low (~60 lines) |
| `frp-core/Cargo.toml` | Add `russh` optional dep | Low |
| `frp-server/src/service.rs` | Spawn `SshListener` on startup if `bind_port > 0` | Low (~15 lines) |
| `frp-server/src/ssh_gateway.rs` | **New file** — listener, session, virtual control | New (~400 lines) |
| `frp-server/Cargo.toml` | Add `russh`, `russh-keys` deps | Low |
| `frp-server/src/lib.rs` | `mod ssh_gateway;` | 1 line |

### Why reuse handle_control()

The SSH gateway needs proxy registration, work connection management, encryption/compression
bridging, bandwidth limiting, heartbeat keepalive — all of which `handle_control()` already
does. Reusing it means:
- Zero duplication of proxy lifecycle logic
- Same work connection pool (no separate implementation)
- Same encryption/compression code paths
- Same bandwidth limiting

The control handler doesn't care whether bytes came from frpc TCP or SSH virtual channel —
it processes `NewProxy` messages and bridges `IoStream`s identically.

## Error Handling

### SSH connection errors

| Error | Behavior |
|-------|----------|
| SSH banner timeout (10s) | Log warn with remote addr, close connection |
| Key exchange failure | Log error, close connection |
| Auth failure (bad token) | Log warn with remote addr, 3 attempts max, then close |
| Auth failure (key not in authorized_keys) | Fall through to password auth |
| Channel open failure | Log error, skip this proxy, session stays alive |
| SSH session EOF (client disconnect) | Clean up all proxies for run_id, remove from ProxyManager |

### Proxy registration errors

| Error | Response to SSH client stderr |
|-------|------|
| Duplicate proxy name | `proxy 'X' already exists` |
| Port already used | `port X is already in use` |
| Invalid proxy type | `unsupported proxy type 'X', supported: tcp, http, https, stcp, tcpmux` |
| Missing required arg (`--proxy_name`) | Usage hint with required flags |
| Remote port outside allow_ports | `port X is not in the allowed port range` |

### Resource cleanup

- SSH session ends → `ProxyManager::remove_client(run_id)` atomically removes all proxies
- All ports freed, group index cleaned, pending work connections drained
- Auto-allocated ports returned to pool

## Testing

### Unit tests (`frp-server/src/ssh_gateway.rs`)

- `test_parse_ssh_args_tcp` — basic TCP proxy parsing
- `test_parse_ssh_args_http` — HTTP with custom domains
- `test_parse_ssh_args_unknown_type` → error
- `test_parse_ssh_args_missing_name` → error
- `test_auto_gen_key_creates_file` — Ed25519 key generation
- `test_auto_gen_key_reuses_existing` — doesn't overwrite
- `test_parse_ssh_args_stcp` — STCP with sk
- `test_parse_ssh_args_tcpmux` — TCPMux with multiplexer
- `test_virtual_control_channel_roundtrip` — NewProxy through virtual channel → correct deserialization

### Integration test (`frp-server/tests/ssh_gateway.rs`)

Single end-to-end test:
1. Start frps with SSH gateway on random port, auto-gen key
2. Use russh client to connect, auth with token
3. Send remote command: `tcp --proxy_name "test-ssh" --remote_port 0`
4. Verify proxy registered in ProxyManager (query API)
5. Open reverse-forward channel, bridge test data through
6. Close SSH session, verify proxy removed from ProxyManager

### Manual compat verification

- Start Go frps v0.69.1 with `sshTunnelGateway.bindPort = 2200`
- Connect with standard OpenSSH client, verify behavior matches Rust frps
- Cross-compat: Rust frps + OpenSSH client (primary use case)

## Dependencies

```toml
# workspace Cargo.toml [workspace.dependencies]
russh = "0.61"
russh-keys = "0.61"

# frp-server/Cargo.toml
russh = { workspace = true }
russh-keys = { workspace = true }

# frp-core/Cargo.toml (optional, for SshChannelStream)
russh = { workspace = true, optional = true }
```

## Out of Scope

- V2 protocol support (Go frp SSH gateway is V1-only)
- SFTP subsystem
- Local port forwarding (`-L`)
- Remote port forwarding for non-frp purposes
- Shell access / PTY allocation
- X11 forwarding
- Agent forwarding
- OIDC authentication via SSH
- SSH client implementation in frpc (russh client dep not needed)

Strictly `ssh -R` reverse tunnel → frp proxy. YAGNI.

## Estimated Size

| Component | Lines (est.) |
|-----------|-------------|
| `SshTunnelGatewayConfig` | 30 |
| `SshListener` + `SshSession` + handlers | 320 |
| Virtual control channel | 80 |
| `SshChannelStream` (transport) | 60 |
| Config normalization (Go compat aliases) | 40 |
| Tests | 150 |
| Wiring (service.rs, lib.rs, Cargo.toml) | 30 |
| **Total** | **~710** |
