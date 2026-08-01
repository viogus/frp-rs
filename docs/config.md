# Configuration Reference

Complete field reference for frp-rs `frps.toml` and `frpc.toml`. Every field maps
1:1 to a Go frp v0.70.1 equivalent.

---

## Server Configuration (`frps.toml`)

### Top-Level Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bind_addr` | `string` | `"0.0.0.0"` | `bindAddr` | Address the server listens on for control connections. |
| `bind_port` | `u16` | `7000` | `bindPort` | Main port for control connections. Clients dial this port. |
| `proxy_bind_addr` | `string` | `""` | `proxyBindAddr` | Separate bind address for proxy listener ports. Empty means same as `bind_addr`. |
| `vhost_http_port` | `u16` | `0` | `vhostHTTPPort` | HTTP virtual host routing port. 0 = disabled. When set, HTTP proxies can be routed by `Host` header without consuming individual ports. |
| `vhost_https_port` | `u16` | `0` | `vhostHTTPSPort` | HTTPS virtual host routing port. 0 = disabled. Routes by TLS SNI. |
| `tcpmux_httpconnect_port` | `u16` | `0` | `tcpmuxHTTPConnectPort` | TCPMux HTTP CONNECT multiplexing port. TCPMux proxies share this port, routed by HTTP CONNECT `Host` header. 0 = disabled. |
| `kcp_bind_port` | `u16` | `0` | `kcpBindPort` | KCP transport listener port. 0 = disabled. Requires `kcp` feature. |
| `quic_bind_port` | `u16` | `0` | `quicBindPort` | QUIC transport listener port. 0 = disabled. Requires `quic` feature. |
| `websocket_port` | `u16` | `0` | `websocketPort` | WebSocket transport listener port. 0 = disabled. Requires `websocket` feature. |
| `sudp_port` | `u16` | `0` | `sudpPort` | Shared UDP port for all SUDP proxies. When > 0, SUDP proxies share this port instead of allocating individual ports. |
| `sub_domain_host` | `string` | `""` | `subDomainHost` | Base domain for sub-domain proxy routing (e.g. `"example.com"`). A proxy with `subdomain = "web"` will be reachable at `web.example.com`. |
| `tls_enable` | `bool` | `false` | `tlsEnable` | Enable TLS on the main listener. Requires `tls_cert_file` and `tls_key_file`. |
| `tls_only` | `bool` | `false` | `tlsOnly` | When true, the main `bind_port` only accepts TLS connections. Plain TCP and WebSocket upgrades are rejected. Clients must also have `tls_enable = true`. |
| `tls_cert_file` | `string` | `""` | `tlsCertFile` | Path to TLS certificate PEM file. |
| `tls_key_file` | `string` | `""` | `tlsKeyFile` | Path to TLS private key PEM file. |
| `tls_ca_file` | `string` | `""` | `tlsCaFile` | Path to CA certificate PEM file for mutual TLS client verification. Empty = no mTLS. |
| `allow_port_start` | `u16` | `1` | `allowPorts` (start) | Start of auto-assigned port range. Used when `allow_ports` is empty. |
| `allow_port_end` | `u16` | `65535` | `allowPorts` (end) | End of auto-assigned port range (inclusive). Used when `allow_ports` is empty. |
| `allow_ports` | `string` | `""` | `allowPorts` | Comma-separated port ranges, e.g. `"10000-20000,30000-40000"`. Each range is inclusive on both ends. When non-empty, takes precedence over `allow_port_start`/`allow_port_end`. |
| `max_ports_per_client` | `u64` | `0` | `maxPortsPerClient` | Maximum number of proxies a single client can register. 0 = unlimited. |
| `vhost_http_timeout` | `u64` | `60` | `vhostHTTPTimeout` | Timeout in seconds for backend HTTP response in VHost handler. |
| `user_conn_timeout` | `u64` | `10` | `userConnTimeout` | Idle timeout in seconds on user-facing proxy connections. |
| `detailed_errors_to_client` | `bool` | `false` | `detailedErrorsToClient` | When true, full Rust error details are included in client-facing error responses. When false (default), internal errors are replaced with generic messages. |
| `tcp_mux_passthrough` | `bool` | `false` | `tcpMuxPassthrough` | When `tcp_mux` is enabled and yamux init fails, forward raw bytes to the VHost handler instead of closing the connection. |
| `udp_packet_size` | `usize` | `1500` | `udpPacketSize` | UDP packet buffer size in bytes. Controls the receive buffer for UDP proxy datagrams. |
| `nat_hole_analysis_data_reserve_hours` | `u64` | `1` | `natholeAnalysisDataReserveHours` | How long historical NAT behavior records are kept (in hours). Used by XTCP NAT analysis. |
| `includes` | `string[]` | `[]` | `includes` | Glob patterns for additional TOML/INI config files to merge. Relative to the main config file directory. |

### `[auth]` Section

Authentication configuration for control connections.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `method` | `string` | `"token"` | `auth.method` | Authentication method: `"token"` or `"oidc"`. |
| `token` | `string` | `""` | `auth.token` | Shared secret token for MD5-based authentication. Must match the client's token. |
| `token_source` | `table` | `null` | `auth.tokenSource` | Dynamic token source. Mutually exclusive with `token`. |
| `oidc_issuer` | `string` | `""` | `auth.oidcIssuer` | OIDC issuer URL. Used when `method = "oidc"`. |
| `oidc_audience` | `string` | `""` | `auth.oidcAudience` | OIDC expected audience claim. |
| `oidc_token_endpoint` | `string` | `""` | `auth.oidcTokenEndpoint` | OIDC token verification endpoint URL. |
| `oidc_skip_expiry` | `bool` | `false` | `auth.oidcSkipExpiry` | Skip OIDC token expiry validation. For development only. |
| `oidc_skip_issuer` | `bool` | `false` | `auth.oidcSkipIssuer` | Skip OIDC issuer validation. For development only. |
| `oidc_proxy_url` | `string` | `""` | `auth.oidcProxyURL` | HTTP/SOCKS5 proxy URL for OIDC provider HTTP requests. |
| `additional_auth_scopes` | `string[]` | `[]` | `auth.additionalAuthScopes` | Extra auth scopes: `"HeartBeats"`, `"NewWorkConns"`. When listed, those message types require authentication in addition to `Login`. |

`auth.tokenSource` supports two source types:

- `type = "file"` reads `file.path` and trims the file contents.
- `type = "exec"` runs `exec.command` with `exec.args` and optional `exec.env` entries (`{ name, value }`), then trims stdout. Exec sources require the `TokenSourceExec` unsafe feature (`--allow-unsafe TokenSourceExec`).

Example:

```toml
[auth.tokenSource]
type = "file"
file.path = "/run/secrets/frp-token"
```

### `[log]` Section

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `level` | `string` | `"info"` | `log.level` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. Also controllable via `RUST_LOG` env var. |
| `file` | `string` | `""` | `log.file` | Log file path. Empty = stderr. Uses daily rotation. |
| `max_days` | `i32` | `3` | `log.maxDays` | Maximum days to retain rotated log files. |

### `[web_server]` Section

Dashboard and metrics HTTP server.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `addr` | `string` | `""` | `webServer.addr` | Dashboard bind address. Empty = same as `bind_addr`. |
| `port` | `u16` | `0` | `webServer.port` | Dashboard port. 0 = disabled. |
| `user` | `string` | `""` | `webServer.user` | Basic Auth username for dashboard and management API. |
| `password` | `string` | `""` | `webServer.password` | Basic Auth password for dashboard and management API. |
| `enable_prometheus` | `bool` | `false` | `webServer.enablePrometheus` | Expose `/metrics` endpoint in Prometheus text format. |
| `tls_cert_file` | `string` | `""` | `webServer.tlsCertFile` | TLS certificate for dashboard HTTPS. When both `tls_cert_file` and `tls_key_file` are non-empty, dashboard serves HTTPS. |
| `tls_key_file` | `string` | `""` | `webServer.tlsKeyFile` | TLS private key for dashboard HTTPS. |
| `custom_404_page` | `string` | `""` | `webServer.custom404Page` | Custom HTML body for 404 responses from VHost and TCPMux handlers. Content-Type is set to `text/html`. |

### `[transport]` Section

Transport-level settings for the server.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `tcp_mux` | `bool` | `true` | `transport.tcpMux` | Enable TCP multiplexing (yamux) for work connections. When enabled, all proxies share a single TCP connection. |
| `tcp_mux_keepalive_interval` | `i64` | `30` | `transport.tcpMuxKeepaliveInterval` | Keepalive interval in seconds for mux connections. |
| `heartbeat_timeout` | `i64` | `90` | `transport.heartbeatTimeout` | Heartbeat timeout in seconds. Server disconnects the client if no `Ping` received within this interval. |

### `[ssh_tunnel_gateway]` Section

SSH tunnel gateway. When `bind_port > 0`, an embedded SSH server accepts SSH
proxy-registration commands. Reverse forwarding (`ssh -R`) is disabled in
0.7.1 and rejected explicitly; only the forward proxy-registration command
path is supported.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bind_port` | `u16` | `0` | `sshTunnelGateway.bindPort` | SSH listen port. 0 = disabled. |
| `bind_addr` | `string` | `"0.0.0.0"` | `sshTunnelGateway.bindAddr` | SSH listen address. |
| `private_key_file` | `string` | `""` | `sshTunnelGateway.privateKeyFile` | Path to SSH host private key file. Auto-generated if empty and `auto_gen_private_key_path` does not exist. |
| `auto_gen_private_key_path` | `string` | `"./.autogen_ssh_key"` | `sshTunnelGateway.autoGenPrivateKeyPath` | Path where auto-generated SSH host key is written. |
| `authorized_keys_file` | `string` | `""` | `sshTunnelGateway.authorizedKeysFile` | Path to SSH `authorized_keys` for optional public key auth. Empty = password auth only. |

### `[[http_plugins]]` Section (Array)

Server-side HTTP plugins. Each entry is an external HTTP service called on lifecycle events.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `name` | `string` | `""` | `name` | Plugin name for logging. |
| `url` | `string` | **required** | `url` | URL of the plugin server (e.g. `"http://127.0.0.1:4000/handler"`). |
| `ops` | `string[]` | `[]` | `ops` | Operations this plugin handles: `"login"`, `"new_proxy"`, `"close_proxy"`. Empty = all operations. |
| `timeout` | `u64` | `5` | `timeout` | Timeout in seconds for HTTP calls to the plugin. |
| `enable_control` | `bool` | `false` | `enableControl` | When true, the plugin response determines approve/reject. When false, the plugin is notify-only. |

### `[feature]` Section

Experimental feature gates. A map of feature name to boolean. Example:

```toml
[feature]
some_experimental_feature = true
```

### Go frp Compatibility (Server)

The server config loader accepts both Rust (snake_case) and Go frp (camelCase) key names:

- `[common]` section is flattened to top level (Go frp compat).
- Flat `auth_method`, `auth_token`, `log_file`, `log_level`, `log_max_days`, `web_server_*` keys are automatically nested into the correct subsections.
- `sshTunnelGateway` (camelCase) is normalized to `ssh_tunnel_gateway`.
- `token` at top level is automatically copied into `[auth]`.

### Server Config Reload (SIGUSR1)

Send `SIGUSR1` to the frps process to hot-reload these settings from the config file:

| Setting | Effect |
|---------|--------|
| `auth.token` | Updates encryption key; new logins use new token. Existing connections are unaffected. |
| `allow_ports` / `allow_port_start` / `allow_port_end` | Adjusts port allocation range. Already-allocated ports are not released. |
| `max_ports_per_client` | Updates the per-client proxy limit. |

Settings that require a full restart: `bind_port`, `bind_addr`, TLS settings, OIDC settings, transport settings.

### Server TOML Example

```toml
# frps.toml — full server configuration example

bind_addr = "0.0.0.0"
bind_port = 7000
proxy_bind_addr = ""
vhost_http_port = 8080
vhost_https_port = 8443
tcpmux_httpconnect_port = 0
kcp_bind_port = 0
quic_bind_port = 0
websocket_port = 0
sudp_port = 0
sub_domain_host = "example.com"
tls_enable = false
tls_only = false
tls_cert_file = ""
tls_key_file = ""
tls_ca_file = ""
allow_port_start = 1
allow_port_end = 65535
max_ports_per_client = 0
vhost_http_timeout = 60
user_conn_timeout = 10
detailed_errors_to_client = false
tcp_mux_passthrough = false
udp_packet_size = 1500
nat_hole_analysis_data_reserve_hours = 1
includes = ["conf.d/*.toml"]

[auth]
method = "token"
token = "my-secret-token"
oidc_issuer = ""
oidc_audience = ""
oidc_token_endpoint = ""
oidc_skip_expiry = false
oidc_skip_issuer = false
oidc_proxy_url = ""
additional_auth_scopes = []

[log]
level = "info"
file = "/var/log/frps.log"
max_days = 3

[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "admin"
enable_prometheus = true
tls_cert_file = ""
tls_key_file = ""
custom_404_page = ""

[transport]
tcp_mux = true
tcp_mux_keepalive_interval = 30
heartbeat_timeout = 90

[ssh_tunnel_gateway]
bind_port = 0
bind_addr = "0.0.0.0"
private_key_file = ""
auto_gen_private_key_path = "./.autogen_ssh_key"
authorized_keys_file = ""

[[http_plugins]]
name = "auth-plugin"
url = "http://127.0.0.1:4000/handler"
ops = ["Login"]
timeout = 5
enable_control = true

[feature]
# experimental_feature = true
```

---

## Client Configuration (`frpc.toml`)

### Top-Level Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `server_addr` | `string` | — | `serverAddr` | **Required.** Server address (IP or hostname). |
| `server_port` | `u16` | `7000` | `serverPort` | Server control port. |
| `transport_protocol` | `string` | `"tcp"` | `protocol` | Transport protocol: `"tcp"`, `"websocket"` / `"ws"`, `"wss"`, `"quic"`, `"kcp"`. |
| `token` | `string` | `""` | `auth.token` | Authentication token. Must match the server's token. This is a convenience field; for full auth config use `[auth]` section. |
| `user` | `string` | `""` | `user` | User identity string for multi-tenant setups. Sent in the Login message. |
| `client_id` | `string` | `""` | `clientId` | Unique client identifier. Auto-generated (UUID v4) if empty. |
| `metas` | `map<string,string>` | `{}` | `metadatas` | Client-level metadata key-value pairs sent in the Login message. Available to server plugins. |
| `proxy_url` | `string` | `""` | `transport.proxyURL` | Upstream HTTP/SOCKS5 proxy for the client-to-server control connection. Supports `http://` and `socks5://` schemes. Empty = direct connection. |
| `nat_hole_stun_server` | `string` | `""` | `natHoleStunServer` | Custom STUN server address for NAT traversal. Format: `"stun:host:port"`. Empty = use default. |
| `start` | `string[]` | `[]` | `start` | Selective proxy start list. If non-empty, only proxies with names in this list are started. Empty = start all proxies. |
| `includes` | `string[]` | `[]` | `includes` | Glob patterns for additional TOML/INI config files to merge. Relative to the main config file directory. |
| `tls_enable` | `bool` | `false` | `tlsEnable` | Enable TLS for the connection to the server. |
| `tls_cert_file` | `string` | `""` | `tlsCertFile` | Client TLS certificate PEM file (for mTLS). |
| `tls_key_file` | `string` | `""` | `tlsKeyFile` | Client TLS private key PEM file (for mTLS). |
| `tls_ca_file` | `string` | `""` | `tlsCaFile` / `tlsTrustedCaFile` | CA certificate PEM file for verifying the server's TLS certificate. |
| `tls_server_name` | `string` | `""` | `tlsServerName` | Server name for TLS SNI. Empty = use `server_addr`. |
| `disable_custom_tls_first_byte` | `bool` | `false` | `disableCustomTLSFirstByte` | When true, the client skips the Go frp protocol marker byte (`0x17`) and starts TLS directly. Set this when connecting to a non-frp TLS endpoint. |
| `login_fail_exit` | `bool` | `true` | `loginFailExit` | When true, the client exits on login failure. When false, it keeps retrying. |
| `pool_count` | `i32` | `0` | `poolCount` | Number of pre-established work connections kept in the server-side pool. Higher values reduce latency for new proxy connections. |
| `heartbeat_interval` | `i64` | `30` | `transport.heartbeatInterval` | Ping interval in seconds. Client sends a heartbeat `Ping` at this interval. |
| `dns_server` | `string` | `""` | `dnsServer` | Custom DNS server address for resolving `server_addr`. Empty = system DNS. |
| `dial_server_keepalive` | `i64` | `0` | `dialServerKeepalive` | TCP keepalive interval in seconds for outbound connections to the server. 0 = disabled. |
| `connect_server_local_ip` | `string` | `""` | `connectServerLocalIP` | Local IP address to bind when dialing the frp server. Empty = system default. |
| `tcp_mux` | `bool` | `true` | `transport.tcpMux` | Enable TCP multiplexing (yamux) for work connections. |
| `v2` | `bool` | `false` | `transport.wireProtocol = "v2"` | Enable V2 wire protocol framing. Requires `tcp_mux` for yamux multiplexing. |

### `[auth]` Section (Client)

Full OIDC authentication configuration. When `method = "oidc"`, the client obtains a JWT from the OIDC provider and sends it as the login token.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `method` | `string` | `"token"` | `auth.method` | Authentication method: `"token"` or `"oidc"`. |
| `token` | `string` | `""` | `auth.token` | Shared secret token (when `method = "token"`). |
| `token_source` | `table` | `null` | `auth.tokenSource` | Dynamic token source. Mutually exclusive with `token`. |
| `oidc_client_id` | `string` | `""` | `auth.oidcClientId` | OIDC client ID for the token endpoint. |
| `oidc_client_secret` | `string` | `""` | `auth.oidcClientSecret` | OIDC client secret for the token endpoint. |
| `oidc_audience` | `string` | `""` | `auth.oidcAudience` | OIDC audience claim to request. |
| `oidc_token_endpoint` | `string` | `""` | `auth.oidcTokenEndpoint` | OIDC token endpoint URL. |
| `oidc_scope` | `string` | `""` | `auth.oidcScope` | OIDC scope string (e.g. `"openid profile"`). |
| `oidc_issuer` | `string` | `""` | `auth.oidcIssuer` | OIDC issuer URL. |
| `additional_endpoint_params` | `string` | `""` | `auth.additionalEndpointParams` | Extra parameters appended to the token endpoint request. |
| `oidc_tls_trusted_ca_file` | `string` | `""` | `auth.tlsTrustedCaFile` | Custom CA certificate PEM file for OIDC provider TLS verification. |
| `oidc_tls_insecure_skip_verify` | `bool` | `false` | `auth.insecureSkipVerify` | Skip TLS certificate verification for OIDC provider. For development only. |
| `oidc_proxy_url` | `string` | `""` | `auth.oidcProxyURL` | HTTP/SOCKS5 proxy URL for OIDC provider HTTP requests. |
| `additional_auth_scopes` | `string[]` | `[]` | `auth.additionalAuthScopes` | Client-side auth scopes. Unioned with the server's scopes. Values: `"HeartBeats"`, `"NewWorkConns"`. |

The client `auth.tokenSource` table has the same shape as the server version: `type = "file"` with `file.path`, or `type = "exec"` with `exec.command`, `exec.args`, and `exec.env`. Exec sources require `--allow-unsafe TokenSourceExec`.

### `[web_server]` Section (Client Admin API)

Admin REST API for the client. Same fields as the server `[web_server]` section.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `addr` | `string` | `""` | `webServer.addr` | Admin API bind address. |
| `port` | `u16` | `0` | `webServer.port` | Admin API port. 0 = disabled. |
| `user` | `string` | `""` | `webServer.user` | Basic Auth username for the admin API. |
| `password` | `string` | `""` | `webServer.password` | Basic Auth password for the admin API. |
| `enable_prometheus` | `bool` | `false` | `webServer.enablePrometheus` | Expose `/metrics` in Prometheus format. |
| `tls_cert_file` | `string` | `""` | — | TLS certificate for admin API HTTPS. |
| `tls_key_file` | `string` | `""` | — | TLS private key for admin API HTTPS. |
| `custom_404_page` | `string` | `""` | — | Custom 404 page HTML content. |

### `[log]` Section (Client)

Same structure as the server `[log]` section. See above.

### `[feature]` Section (Client)

Same as server `[feature]`. Experimental feature gates.

### Go frp Compatibility (Client)

The client config loader normalizes Go frp format to frp-rs format:

- `[common]` section is flattened to top level.
- `protocol` is renamed to `transport_protocol`.
- `serverAddr` / `serverPort` (camelCase) are renamed to `server_addr` / `server_port`.
- `tls_trusted_ca_file` is renamed to `tls_ca_file`.
- `auth.token` is extracted to top-level `token`.
- `[transport]` section is flattened to top level (client keeps `tcp_mux` top-level).
- `transport.wireProtocol = "v2"` is converted to top-level `v2 = true`.
- Flat `log_file`, `log_level`, `log_max_days` are nested into `[log]`.

### Client TOML Example

```toml
# frpc.toml — full client configuration example

server_addr = "127.0.0.1"
server_port = 7000
transport_protocol = "tcp"
token = "my-secret-token"
user = ""
client_id = ""
metas = { env = "production", region = "us-east" }
proxy_url = ""
nat_hole_stun_server = ""
start = []
includes = []
tls_enable = false
tls_cert_file = ""
tls_key_file = ""
tls_ca_file = ""
tls_server_name = ""
disable_custom_tls_first_byte = false
login_fail_exit = false
pool_count = 1
heartbeat_interval = 30
dns_server = ""
dial_server_keepalive = 0
connect_server_local_ip = ""
tcp_mux = true
v2 = false

[auth]
method = "token"
token = ""
oidc_client_id = ""
oidc_client_secret = ""
oidc_audience = ""
oidc_token_endpoint = ""
oidc_scope = ""
oidc_issuer = ""
additional_endpoint_params = ""
oidc_tls_trusted_ca_file = ""
oidc_tls_insecure_skip_verify = false
oidc_proxy_url = ""
additional_auth_scopes = []

[log]
level = "info"
file = ""
max_days = 3

[web_server]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "admin"
enable_prometheus = false
tls_cert_file = ""
tls_key_file = ""
custom_404_page = ""

[feature]
# experimental_feature = true

[virtualNet]
address = ""

[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
use_encryption = false
use_compression = false

[[visitors]]
name = "xtcp-visitor"
type = "xtcp"
server_name = "xtcp-proxy"
secret_key = "shared-secret"
bind_addr = "127.0.0.1"
bind_port = 6000
```

---

## Proxy Configuration (`[[proxies]]`)

Each `[[proxies]]` entry defines a proxy that the client registers with the server.

### Common Fields (All Proxy Types)

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `name` | `string` | — | **Required.** | Unique proxy name. Used as identifier in logs, admin API, and routing. |
| `type` | `string` | — | **Required.** | Proxy type: `"tcp"`, `"udp"`, `"http"`, `"https"`, `"stcp"`, `"xtcp"`, `"tcpmux"`, `"sudp"`. |
| `local_ip` | `string` | `""` | `localIp` | Local service IP address. Default = `"127.0.0.1"` in most setups. |
| `local_port` | `u16` | `0` | `localPort` | Local service port. |
| `remote_port` | `u16` | `0` | `remotePort` | Remote port to expose on the server. 0 = auto-assign from server's port range. |
| `use_encryption` | `bool` | `false` | `useEncryption` | Encrypt proxy traffic with AES-128-CFB (derived from auth token for TCP/UDP/HTTP; from `sk` for STCP/XTCP). |
| `use_compression` | `bool` | `false` | `useCompression` | Compress proxy traffic with Snappy (applied before encryption). |
| `enabled` | `bool` | `true` | `enabled` | Whether this proxy is active. `false` = skipped at startup. |

### TCP/UDP Proxy Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bandwidth_limit` | `string` | `""` | `bandwidthLimit` | Bandwidth limit string, e.g. `"1MB"`, `"500KB"`, `"100K"`. Supports suffixes: K/KB, M/MB, G/GB (case-insensitive). |
| `bandwidth_limit_mode` | `string` | `""` | `bandwidthLimitMode` | Bandwidth limit mode: `"client"` (limit client→server), `"server"` (limit server→client), or empty (both directions). |
| `group` | `string` | `""` | `group` | Proxy group name for load balancing. Proxies with the same group name are treated as a pool. |
| `group_key` | `string` | `""` | `groupKey` | Group key for authentication within a proxy group. |
| `health_check_type` | `string` | `""` | `healthCheckType` | Health check type: `"tcp"` (connect check) or `"http"` (HTTP GET check). Empty = no health checks. |
| `health_check_url` | `string` | `"/"` | `healthCheckURL` | URL path for HTTP health checks. Only used when `health_check_type = "http"`. |
| `health_check_http_headers` | `map<string,string>` | `{}` | `healthCheckHTTPHeaders` | Custom HTTP headers sent with health check requests. |
| `health_check_interval_seconds` | `u64` | `0` | `healthCheckIntervalS` | Seconds between health checks. Minimum 10. |
| `health_check_timeout_seconds` | `u64` | `0` | `healthCheckTimeoutS` | Health check connect/read timeout in seconds. Minimum 3. |
| `health_check_max_failed` | `u32` | `0` | `healthCheckMaxFailed` | Consecutive failures before marking the proxy unhealthy. Minimum 1. |
| `multiplexer` | `string` | `""` | `multiplexer` | Multiplexer type for the proxy connection (e.g. `"yamux"`). |

### HTTP/HTTPS Proxy Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `custom_domains` | `string[]` | `[]` | `customDomains` | Custom domain names for VHost routing (e.g. `["web.example.com"]`). |
| `subdomain` | `string` | `""` | `subdomain` | Sub-domain name. Combined with the server's `sub_domain_host` to form the full domain (e.g. `web` + `example.com` = `web.example.com`). |
| `http_user` | `string` | `""` | `httpUser` | HTTP Basic Auth username required to access the proxy. |
| `http_password` | `string` | `""` | `httpPassword` | HTTP Basic Auth password. Alias: `http_pwd`. |
| `http_pwd` | `string` | `""` | `httpPwd` | Alias for `http_password`. Both are accepted; `http_password` takes precedence. |
| `host_header_rewrite` | `string` | `""` | `hostHeaderRewrite` | Rewrite the `Host` header to this value before forwarding to the local service. |
| `headers` | `map<string,string>` | `{}` | `headers` | Custom HTTP request headers injected into proxied requests. |
| `response_headers` | `map<string,string>` | `{}` | `responseHeaders` | Custom HTTP response headers injected into proxied responses. |
| `locations` | `string[]` | `[]` | `locations` | URL path prefixes for HTTP routing. Only requests matching these paths are routed to this proxy. |
| `route_by_http_user` | `string` | `""` | `routeByHTTPUser` | Route requests to this proxy based on HTTP Basic Auth username. |
| `allow_users` | `string[]` | `[]` | `allowUsers` | List of HTTP Basic Auth usernames allowed to access this proxy. |

### STCP/XTCP Proxy Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `sk` | `string` | `""` | `sk` | **Secret key.** Required for STCP/XTCP. The visitor must present the same key to connect. Also used as the encryption key when `use_encryption = true`. |
| `virtual_net` | `string` | `""` | `virtualNet` | Virtual network name for proxy isolation. Proxies in different virtual nets cannot reach each other. Empty = default (global) network. |

### Proxy Metadata and Misc Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `annotations` | `map<string,string>` | `{}` | `annotations` | Arbitrary key-value annotations (e.g. `{ owner = "team-a" }`). |
| `metas` | `map<string,string>` | `{}` | `metas` | Key-value metadata sent to server plugins for this proxy. |
| `proxy_protocol_version` | `string` | `""` | `proxyProtocolVersion` | HAProxy PROXY protocol version: `"v1"`, `"v2"`, or `""` (disabled). When set, the server prepends a PROXY protocol header to each connection. |

### `[proxies.plugin]` Section

Per-proxy client plugin configuration. The plugin runs on the client side and handles the actual service logic.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `type` | `string` | — | `type` | Plugin type: `"http_proxy"`, `"socks5"`, `"static_file"`, `"unix_domain_socket"`, `"http2https"`, `"https2http"`, `"https2https"`, `"http2http"`, `"tls2raw"`, `"virtual_net"`. |
| `http_user` | `string` | `""` | `httpUser` | HTTP basic auth username for the plugin. |
| `http_password` | `string` | `""` | `httpPassword` | HTTP basic auth password for the plugin. |
| `local_addr` | `string` | `""` | `localAddr` | Local address for the plugin listener (e.g. `"127.0.0.1:3128"`). |
| `local_path` | `string` | `""` | `localPath` | Local filesystem path for `static_file` plugin. |
| `strip_prefix` | `string` | `""` | `stripPrefix` | URL path prefix to strip before forwarding to the local service. |
| `host_header_rewrite` | `string` | `""` | `hostHeaderRewrite` | Rewrite the `Host` header for the plugin (http_proxy, static_file). |
| `username` | `string` | `""` | `username` | Username for upstream proxy auth (http_proxy, socks5 plugins). |
| `password` | `string` | `""` | `password` | Password for upstream proxy auth (http_proxy, socks5 plugins). |
| `crt_file` | `string` | `""` | `pluginCrtPath` | TLS certificate file for plugin listener (https2http, https2https). |
| `key_file` | `string` | `""` | `pluginKeyPath` | TLS key file for plugin listener (https2http, https2https). |
| `server_name` | `string` | `""` | `serverName` | Server name for STCP/XTCP visitor plugin. |
| `secret_key` | `string` | `""` | `sk` | Secret key for STCP/XTCP visitor plugin auth. |
| `bind_addr` | `string` | `""` | `bindAddr` | Local address for the visitor plugin listener. |
| `bind_port` | `i32` | `0` | `bindPort` | Local port for the visitor plugin listener. `-1` disables binding. |

`type = "virtual_net"` does not bind a listener; work connections are handed
to the vnet controller and require a non-empty IPv4 `[virtualNet] address`.

### Proxy TOML Examples

**TCP proxy:**

```toml
[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
use_encryption = false
use_compression = false
bandwidth_limit = "10MB"
bandwidth_limit_mode = "client"
health_check_type = "tcp"
health_check_interval_seconds = 30
health_check_timeout_seconds = 3
health_check_max_failed = 3
group = "ssh-pool"
group_key = "pool-key"
```

**HTTP proxy with custom domain:**

```toml
[[proxies]]
name = "web-app"
type = "http"
local_ip = "127.0.0.1"
local_port = 3000
custom_domains = ["app.example.com"]
http_user = "user"
http_password = "pass"
host_header_rewrite = "app.internal"
headers = { "X-Forwarded-Proto" = "https" }
locations = ["/api", "/static"]
proxy_protocol_version = "v2"
```

**STCP proxy:**

```toml
[[proxies]]
name = "secret-service"
type = "stcp"
sk = "my-secret-key"
local_ip = "127.0.0.1"
local_port = 5432
use_encryption = true
use_compression = false
```

**XTCP proxy (NAT hole punch):**

```toml
[[proxies]]
name = "p2p-service"
type = "xtcp"
sk = "p2p-secret-key"
local_ip = "127.0.0.1"
local_port = 8080
use_encryption = true
use_compression = true
```

**TCP proxy with plugin:**

```toml
[[proxies]]
name = "http-proxy-plugin"
type = "tcp"
remote_port = 10081
[proxies.plugin]
type = "http_proxy"
http_user = "proxy-user"
http_password = "proxy-pass"
```

**Disabled proxy:**

```toml
[[proxies]]
name = "draft-proxy"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 9999
remote_port = 9999
enabled = false
```

---

## Visitor Configuration (`[[visitors]]`)

Visitors are STCP/XTCP client-side listeners that accept local connections and tunnel them
through the frps server to a remote STCP/XTCP proxy.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `name` | `string` | `""` | `name` | Visitor name for logging. |
| `type` | `string` | `""` | `type` | Visitor type: `"stcp"` or `"xtcp"`. |
| `server_name` | `string` | `""` | `serverName` | **Required.** The STCP/XTCP proxy name to connect to (must match the proxy's `name`). |
| `secret_key` | `string` | `""` | `sk` / `secretKey` | **Required.** Shared secret key. Must match the STCP proxy's `sk`. |
| `server_user` | `string` | `""` | `serverUser` | Optional server-side user for auth matching. |
| `bind_addr` | `string` | `"0.0.0.0"` | `bindAddr` | Local address to bind for accepting visitor connections. |
| `bind_port` | `u16` | `0` | `bindPort` | Local port for the visitor listener. 0 = disabled. |
| `plugin` | `[visitors.plugin]` | — | `plugin` | Optional visitor plugin. `type = "virtual_net"` with `destinationIP` advertises the IP as a vnet host route instead of binding a local listener. |
| `fallback_timeout_ms` | `u64` | `5000` | `fallbackTimeoutMs` | XTCP fallback timeout in milliseconds. After this time without a successful hole punch, fall back to the `fallback_to` visitor (usually STCP). |
| `fallback_to` | `string` | `""` | `fallbackTo` | Fallback visitor name if XTCP hole punch fails. Typically points to an STCP visitor. |
| `disable_assisted_addrs` | `bool` | `false` | `disableAssistedAddrs` | Disable NAT traversal assisted address reporting (STUN-discovered mapped addresses shared between peers during XTCP hole punching). |
| `use_encryption` | `bool` | `false` | `useEncryption` | Encrypt tunnel traffic with AES-128-CFB (key derived from `secret_key`). |
| `use_compression` | `bool` | `false` | `useCompression` | Compress tunnel traffic with Snappy. |
| `protocol` | `string` | `"kcp"` | `protocol` | XTCP P2P data-plane protocol. frp-rs implements KCP only, so the default is `"kcp"` even though Go frp v0.70.1 defaults visitors to `"quic"`. |
| `keep_tunnel_open` | `bool` | `false` | `keepTunnelOpen` | When true, the XTCP visitor retries NAT hole punching instead of falling back to STCP after a connection ends. |
| `max_retries_an_hour` | `i32` | `8` | `maxRetriesAnHour` | Maximum XTCP NAT hole punch retries per hour. |
| `min_retry_interval` | `i64` | `30` | `minRetryInterval` | Minimum interval in seconds between XTCP retry attempts. |

### Visitor TOML Examples

**STCP visitor:**

```toml
[[visitors]]
name = "stcp-visitor"
type = "stcp"
server_name = "secret-service"
secret_key = "my-secret-key"
bind_addr = "127.0.0.1"
bind_port = 6000
use_encryption = true
```

**XTCP visitor with STCP fallback:**

```toml
[[visitors]]
name = "xtcp-visitor"
type = "xtcp"
server_name = "p2p-service"
secret_key = "p2p-secret-key"
bind_addr = "127.0.0.1"
bind_port = 6000
fallback_timeout_ms = 5000
fallback_to = "stcp-visitor"
keep_tunnel_open = true
max_retries_an_hour = 8
min_retry_interval = 30
use_encryption = true
use_compression = false
```

**Virtual net visitor:**

```toml
[[visitors]]
name = "vnet-visitor"
type = "stcp"
server_name = "vnet-server"
secret_key = "shared-secret"
bind_port = -1

[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
```

The `virtual_net` visitor plugin requires `[feature] VirtualNet = true`.
It registers a host route for `destinationIP` (IPv4 `/32` or IPv6 `/128`)
through the vnet routing path; the local TCP listener is not started for this
visitor. Instead, a no-bind STCP/XTCP tunnel is opened to the server, the
visitor's `use_encryption`/`use_compression` settings are applied to the
tunnel byte stream, and inbound `VnetPacket`s for the visitor are written into
that tunnel.

---

## Bandwidth Limit Format

The `bandwidth_limit` field accepts human-readable strings with these suffixes:

| Suffix | Multiplier | Example | Bytes/sec |
|--------|-----------|---------|-----------|
| (none) | 1 | `"500"` | 500 |
| `K` / `KB` | 1,000 | `"500KB"` | 500,000 |
| `M` / `MB` | 1,000,000 | `"10MB"` | 10,000,000 |
| `G` / `GB` | 1,000,000,000 | `"1GB"` | 1,000,000,000 |

Suffixes are case-insensitive. An empty string or `"0"` means no limit.

---

## Port Range Format

The `allow_ports` field accepts a comma-separated list of ranges and single ports:

```
"10000-20000"                  # single range
"10000-20000,30000-40000"      # multiple ranges
"1000-2000,8080,30000-40000"   # mixed ranges and single ports
```

Each range is inclusive on both ends. Inverted ranges (e.g. `"20000-10000"`) are automatically swapped. Invalid port numbers (> 65535) are silently ignored. When `allow_ports` is empty, `allow_port_start` and `allow_port_end` define a single contiguous range.

---

## Config File Includes

Both server and client support merging additional config files via `includes`:

```toml
includes = ["conf.d/*.toml", "secrets.toml"]
```

- Patterns are relative to the directory containing the main config file.
- Supports a single `*` wildcard per path component.
- `.toml` and `.ini` extensions are supported.
- Included files are deep-merged: tables merge recursively, arrays concatenate.
- The main config file's explicit values take precedence over included files.

For directory-based config, use `--config-dir`:

```bash
frps --config-dir /etc/frp/conf.d
```

All `.toml` and `.ini` files in the directory (recursive) are loaded and merged in sorted order.

---

## Feature Flags (Build-Time)

Configuration fields and behavior gated behind Cargo features.

### Compile-Time Gated Fields

Only three config fields have `#[cfg(feature)]` on the struct definition. When the feature is off, the field does not exist on the config struct and is rejected at deserialization time.

| Feature | Field | Description |
|---------|-------|-------------|
| `kcp` | `kcp_bind_port` | KCP listener port (server) |
| `quic` | `quic_bind_port` | QUIC listener port (server) |
| `websocket` | `websocket_port` | WebSocket listener port (server) |

### Runtime-Gated Features

All other features gate only the runtime behavior. Their config fields are always present on the struct and always deserialized, but the corresponding protocol handler, plugin, or code path is not compiled and the field value is ignored at runtime.

| Feature | Config Fields Always Present | Runtime Effect When Disabled |
|---------|------------------------------|------------------------------|
| `tls` | `tls_enable`, `tls_cert_file`, `tls_key_file`, `tls_ca_file`, `tls_server_name`, `tls_only`, `disable_custom_tls_first_byte` | TLS accept/dial not compiled |
| `oidc` | `oidc_issuer`, `oidc_audience`, `oidc_token_endpoint`, `oidc_skip_expiry`, `oidc_skip_issuer`, `oidc_proxy_url` | OIDC token verification not compiled |
| `compression` | `use_compression` (proxy/visitor) | Snappy bridge compression not compiled |
| `chacha20` | V2 cipher fields | XChaCha20-Poly1305 V2 cipher not compiled |
| `ssh` | `[ssh_tunnel_gateway]` section | SSH gateway not compiled |
| `dashboard` | `[web_server]` section | Dashboard HTTP endpoints not compiled |
| `http-proxy` | `type = "http_proxy"` plugin config | HTTP proxy plugin not compiled |

---

### Parse-Only Compatibility Fields

Some Go frp v0.70.1 fields are parsed and validated for source-level
compatibility but are not yet consumed by the frp-rs runtime. They are
accepted so Go frp configs load unchanged; setting them currently has no
runtime effect: `log.disablePrintColor`, `webServer.assetsDir`,
`webServer.pprofEnable`, and plugin `enableHTTP2`.

---

## Environment Variables

Log level can be overridden at runtime:

```bash
RUST_LOG=debug ./frps -c frps.toml
RUST_LOG=frp_core=trace,frp_server=debug ./frps -c frps.toml
```

Both the config file `log.level` and the `RUST_LOG` environment variable control log verbosity. See the `tracing-subscriber` documentation for precedence rules.
