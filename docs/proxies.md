# Proxy Type Guide

frp-rs supports 8 proxy types. Each type defines how external traffic reaching the
frps server is forwarded through a frpc client to a local service.

---

## TCP Proxy (`type = "tcp"`)

Plain TCP port forwarding. The most common proxy type.

**Use for:** SSH, databases, MySQL, Redis, any TCP-based service.

### Configuration

```toml
[[proxies]]
name = "ssh"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 22
remote_port = 6000
use_encryption = true
use_compression = true
```

### Data Flow

```
User → frps:6000 → [encrypted bridge] → frpc → 127.0.0.1:22
```

frps listens on `remote_port`. Each incoming TCP connection triggers a work
connection request from frpc. The server bridges the user connection to the
work connection, which frpc forwards to `local_ip:local_port`.

### Encryption & Compression

Both `use_encryption` (AES-128-CFB) and `use_compression` (Snappy) are supported.
When both enabled, compression is applied first, then encryption.

### Health Checks

TCP and HTTP health checks are supported. frpc periodically connects to
`local_ip:local_port` (for TCP checks) or sends an HTTP request (for HTTP checks):

```toml
health_check_type = "tcp"
health_check_interval_seconds = 30
health_check_timeout_seconds = 3
health_check_max_failed = 3
```

For HTTP health checks, configure the URL and optional custom headers:

```toml
health_check_type = "http"
health_check_url = "/health"
```

### Type-Specific Fields

| Field | Description |
|-------|-------------|
| `bandwidth_limit` | Bandwidth limit, e.g. `"1MB"` or `"500KB"`. Only `KB`/`MB` suffixes are supported (1024 base). Empty = unlimited. |
| `bandwidth_limit_mode` | `"client"` or `"server"`. Which side applies the limit. |
| `group` / `group_key` | Load balancing group. Proxies with the same group share connections. `group_key` enables sticky sessions (hash-based affinity). |
| `proxy_protocol_version` | HAProxy PROXY protocol: `"v1"`, `"v2"`, or `""` (disabled). |

---

## UDP Proxy (`type = "udp"`)

UDP port forwarding. Encapsulates UDP datagrams inside the frp wire protocol.

**Use for:** DNS, game servers, VoIP, any UDP-based service.

### Configuration

```toml
[[proxies]]
name = "dns"
type = "udp"
local_ip = "127.0.0.1"
local_port = 53
remote_port = 6001
```

### Data Flow

```
User → frps:6001/UDP → [UDPPacket on work conn] → frpc → 127.0.0.1:53/UDP
```

Unlike TCP proxies, UDP traffic uses a dedicated work connection. frps listens on
a UDP socket at `remote_port`, encapsulates each datagram as a `UDPPacket` wire
message, and sends it over the work connection. frpc unwraps and forwards to the
local UDP service. The server-level `udp_packet_size` setting (default 1500)
controls the datagram receive buffer.

### Encryption & Compression

Since the SUDP/three-stage encryption work, UDP proxies support
`use_encryption`/`use_compression` on the data plane: the provider segment
(frps ↔ provider) is encrypted with `derive_key(auth token)` and the
visitor segment (frps ↔ visitor) with `derive_key(sk)` — the same
Go-frp three-segment model used by SUDP (see the SUDP Visitor section
below). Datagrams are compressed (Snappy) then encrypted before hitting
the wire.

### Health Checks

TCP and HTTP health checks: the client starts a TCP health check for any proxy type (including UDP) that sets a non-empty `health_check_type`.

### Type-Specific Fields

UDP proxies share the common proxy fields. No type-specific fields beyond the
standard set.

---

## SUDP Proxy (`type = "sudp"`)

Shared UDP. Multiple SUDP proxies share a single server port, differentiated by
the destination local address.

**Use for:** Hosting multiple UDP services behind the same port, e.g. multiple
game servers on different internal hosts.

### Configuration

On the server, set a shared port:

```toml
# frps.toml
sudp_port = 6002
```

Then define SUDP proxies on one or more clients:

```toml
# frpc.toml (client A)
[[proxies]]
name = "game-server-1"
type = "sudp"
local_ip = "10.0.0.1"
local_port = 27015
remote_port = 6002
```

```toml
# frpc.toml (client B)
[[proxies]]
name = "game-server-2"
type = "sudp"
local_ip = "10.0.0.2"
local_port = 27016
remote_port = 6002
```

### Data Flow

```
User → frps:6002/UDP → [UDPPacket, routed by local_addr] → frpc-A → 10.0.0.1:27015/UDP
                      → [UDPPacket, routed by local_addr] → frpc-B → 10.0.0.2:27016/UDP
```

All SUDP proxies share the server-side UDP socket. The server routes incoming
datagrams to the correct client by matching the proxy's `local_ip:local_port`
as the destination address identifier. This avoids consuming a separate port
for each UDP proxy.

### Encryption & Compression

Encryption is supported with the Go-frp three-segment model (see the SUDP
Visitor section below): the visitor segment is encrypted with `derive_key(sk)`,
the provider segment with `derive_key(auth token)`. Compression is not
supported on the SUDP data plane.

### Health Checks

Not applicable (same as UDP).

### Type-Specific Fields

| Field | Description |
|-------|-------------|
| `local_ip` | **Required for routing.** The server uses `local_ip:local_port` as a key to identify which SUDP proxy should receive an incoming datagram. |

Server-level fields (`frps.toml`):

| Field | Description |
|-------|-------------|
| `sudp_port` | Port all SUDP proxies share. When set, `remote_port` on each SUDP proxy is overridden to this value. |

### SUDP Visitor (frpc)

A SUDP visitor (`[[visitors]]` with `type = "sudp"`) binds a local UDP port on the client and tunnels datagrams to a remote SUDP provider through the frps server. It mirrors Go frp's `client/visitor/sudp.go`:

```toml
# frpc.toml
[[visitors]]
name = "game-visitor"
type = "sudp"
server_name = "game-server-1"   # the SUDP proxy name registered by the provider
secret_key = "shared-sk"        # must match the provider's sk
bind_addr = "127.0.0.1"
bind_port = 27015               # local UDP port to listen on
```

### Data Flow

```
Local client → visitor frpc:27015/UDP → [NewVisitorConn + UDPPacket on work conn] → frps → provider frpc → 10.0.0.1:27015/UDP
```

- **Lazy tunnel:** no server connection is held until the first datagram arrives; the first datagram triggers a fresh `NewVisitorConn` handshake over a dedicated connection to the server. After the tunnel closes (disconnect or 60s idle timeout) the visitor returns to the wait state and the next datagram reconnects.
- The shared UDP socket is multiplexed by datagram source address: replies are sent back to the `UdpAddr` source, and outbound datagrams carry their own source address in `UDPPacket.remote_addr`.

### Encryption & Compression

The SUDP data plane is encrypted end-to-end with Go-frp's three-segment
model: the **visitor segment** (visitor frpc ↔ frps) is AES-128-CFB stream
encryption keyed by `derive_key(sk)`, the **provider segment** (frps ↔ provider
frpc) by `derive_key(auth token)`, and frps joins the two decrypted streams in
the middle. `use_encryption` is honored on both the visitor and the provider;
`use_compression` is accepted but ignored on SUDP (Go's streaming-compression
model for the per-packet plane is not unified here yet).

Cross-compat: a Go frpc `sudp` visitor (with `transport.useEncryption = true`)
works against a Rust frps + Rust provider, and a Rust visitor works against a
Rust stack. The reverse direction (any visitor → Go frps) is **not supported by
Go itself**: Go v0.70.1's server-side `UDPProxy` never registers the
visitor-manager listener its own `sudp` visitor type requires
("custom listener … doesn't exist"), so Go's sudp is a client-side half
implementation — frp-rs is a superset.

### Visitor Fields

| Field | Description |
|-------|-------------|
| `type` | `"sudp"` |
| `server_name` | **Required.** Name of the SUDP proxy to connect to (must match the provider's `name`). |
| `secret_key` | **Required.** Must match the provider's `sk` (validated by the server against the registered proxy). |
| `bind_addr` / `bind_port` | Local UDP address and port for the visitor socket. |
| `use_encryption` | Encrypts the visitor segment with `derive_key(sk)` (matches the provider's `transport.useEncryption`). |
| `use_compression` | Accepted for config compatibility but ignored on SUDP (see above). |

---

## HTTP Proxy (`type = "http"`)

HTTP reverse proxy with virtual host routing by domain name and URL path.

**Use for:** Web applications, REST APIs, any HTTP service that needs
domain-based or path-based routing.

### Configuration

```toml
[[proxies]]
name = "web-app"
type = "http"
local_ip = "127.0.0.1"
local_port = 8080
custom_domains = ["app.example.com", "www.example.com"]
locations = ["/api", "/"]
host_header_rewrite = "backend.local"
http_user = "admin"
http_password = "secret123"
```

### Data Flow

```
Browser → frps:vhost_http_port (Host: app.example.com) → [VHost routing] → frpc → 127.0.0.1:8080

Browser → frps:vhost_http_port (Host: other.com) → 404 Not Found
```

The HTTP VHost listener (`vhost_http_port` in `frps.toml`) reads the `Host`
header from incoming HTTP requests, matches it against registered `custom_domains`,
and forwards to the correct client's frpc. Sub-domain routing is also supported
via `subdomain` + server-level `sub_domain_host`.

### Encryption & Compression

Both `use_encryption` (AES-128-CFB) and `use_compression` (Snappy) are supported
on the work connection bridge.

### Health Checks

TCP and HTTP health checks are supported:

```toml
health_check_type = "http"
health_check_url = "/health"
health_check_interval_seconds = 10
health_check_timeout_seconds = 3
health_check_max_failed = 3
```

### Type-Specific Fields

| Field | Description |
|-------|-------------|
| `custom_domains` | Domains this proxy handles (e.g. `["app.example.com"]`). VHost routing matches the request's Host header against these. |
| `subdomain` | Sub-domain prefix (e.g. `"app"` + `sub_domain_host="example.com"` = `app.example.com`). Alternative to `custom_domains`. |
| `locations` | URL path prefixes for routing (e.g. `["/api", "/admin"]`). Supports longest-prefix matching. |
| `host_header_rewrite` | Rewrite the Host header before forwarding to the local service. Useful when the backend expects a specific hostname. |
| `http_user` / `http_password` | HTTP Basic Auth credentials. Requests without matching credentials receive 401. |
| `route_by_http_user` | Route requests by the Basic Auth username (overrides domain/path routing). |
| `allow_users` | Not implemented on the HTTP vhost path — use `http_user`/`http_password` or `route_by_http_user` for access control. |
| `headers` | Custom HTTP request headers to add to proxied requests. |
| `response_headers` | Custom HTTP response headers to inject into responses. |

Server-level fields for HTTP VHost (`frps.toml`):

| Field | Description |
|-------|-------------|
| `vhost_http_port` | Port for the HTTP VHost listener (0 = disabled). Set this to enable HTTP proxying. |
| `sub_domain_host` | Base domain for sub-domain routing (e.g. `"example.com"`). |

---

## HTTPS Proxy (`type = "https"`)

HTTPS reverse proxy with SNI-based routing. Routes TLS connections by the
Server Name Indication (SNI) hostname in the TLS ClientHello.

**Use for:** Secure web applications, any HTTPS/TLS service where you want
frps to terminate or route by domain without inspecting HTTP headers.

### Configuration

```toml
[[proxies]]
name = "secure-app"
type = "https"
local_ip = "127.0.0.1"
local_port = 8443
custom_domains = ["secure.example.com"]
```

On the server, TLS certificate and key are optional — when not configured,
a self-signed certificate is generated automatically:

```toml
# frps.toml
vhost_https_port = 443
tls_cert_file = "/etc/frp/server.crt"
tls_key_file = "/etc/frp/server.key"
```

### Data Flow

```
Browser → frps:443/TLS (SNI: secure.example.com) → [SNI routing] → frpc → 127.0.0.1:8443

Browser → frps:443/TLS (SNI: unknown.com) → connection silently closed
```

frps does not terminate TLS. It parses the SNI hostname from the ClientHello,
routes to the matching proxy, and tunnels the original encrypted bytes through
unchanged.

### Encryption & Compression

The frps-to-frpc bridge supports `use_encryption` and `use_compression`,
independent of the TLS layer between the user and frps.

### Health Checks

TCP and HTTP health checks are supported (health check connects to the local
service, not through TLS).

### Type-Specific Fields

Same HTTP proxy fields apply, except `locations` (SNI routing works by
hostname only, no path-based routing):

| Field | Description |
|-------|-------------|
| `custom_domains` | **Required.** Domains matched against the TLS SNI hostname. |
| `subdomain` | Sub-domain routing (works with server-level `sub_domain_host`). |
| `host_header_rewrite` | Not applied on the HTTPS path — bytes are tunneled as-is. |
| `http_user` / `http_password` | Not checked on the HTTPS path (no Basic Auth after SNI routing). |
| `headers` | Not injected on the HTTPS path. |
| `response_headers` | Not injected on the HTTPS path. |

Server-level fields for HTTPS VHost (`frps.toml`):

| Field | Description |
|-------|-------------|
| `vhost_https_port` | Port for the HTTPS VHost listener (0 = disabled). |
| `tls_cert_file` | Path to TLS certificate PEM file. |
| `tls_key_file` | Path to TLS private key PEM file. |

---

## STCP Proxy (`type = "stcp"`)

Secret TCP. A secure, secret-key-based proxy where visitors authenticate with
a shared secret before the server bridges the connection.

**Use for:** Internal services that should not be exposed on a public port.
Visitors connect through frps with a secret key, and frps routes using the key,
not a port number. No public port is opened for the proxy.

### Configuration

Provider (exposes the service):

```toml
[[proxies]]
name = "internal-db"
type = "stcp"
local_ip = "127.0.0.1"
local_port = 5432
sk = "my-shared-secret"
use_encryption = true
use_compression = true
```

Visitor (connects to the service):

```toml
[[visitors]]
name = "db-visitor"
type = "stcp"
server_name = "internal-db"
secret_key = "my-shared-secret"
bind_addr = "127.0.0.1"
bind_port = 5432
use_encryption = true
use_compression = true
```

The visitor runs its own frpc that binds a local port. Connections to that
local port are forwarded through frps to the provider's frpc, matched by the
secret key.

### Data Flow

```
App → visitor frpc:5432 → frps (sk_index lookup) → provider frpc → 127.0.0.1:5432
```

1. Provider registers the proxy with `sk = "my-shared-secret"`.
2. Server stores the mapping `sk → proxy_name` in the `sk_index`.
3. Visitor sends `NewVisitorConn` with the secret key and `server_name`.
4. Server looks up the key in `sk_index`, finds the provider's proxy.
5. Server bridges the visitor connection to the provider.

No public listener port is opened -- the visitor punches through frps using
only the secret key for routing.

### Encryption & Compression

Both `use_encryption` and `use_compression` are supported on the bridge.
Must match between provider and visitor.

### Health Checks

TCP and HTTP health checks are supported on the provider side.

### Type-Specific Fields

Provider fields:

| Field | Description |
|-------|-------------|
| `sk` | **Required.** Secret key for visitor authentication. Must match the visitor's `secret_key`. |
| `virtual_net` | Virtual network namespace. Proxies in different virtual nets cannot see each other even with the same `sk`. |
| `allow_users` | List of allowed visitor run_ids. Empty = only the owner (provider's user) can access; `["*"]` = all visitors allowed. |

Visitor fields (`[[visitors]]` in frpc.toml):

| Field | Description |
|-------|-------------|
| `type` | `"stcp"` |
| `server_name` | Name of the STCP proxy to connect to (must match provider's `name`). |
| `secret_key` | Secret key matching the provider's `sk`. |
| `bind_addr` / `bind_port` | Local address and port to listen on for incoming connections. |
| `use_encryption` | Must match provider setting. |
| `use_compression` | Must match provider setting. |

---

## XTCP Proxy (`type = "xtcp"`)

NAT traversal proxy. Uses STUN (Session Traversal Utilities for NAT) and TCP
simultaneous open to establish a direct peer-to-peer connection between visitor
and provider, bypassing the frps relay entirely for data transfer.

**Use for:** High-bandwidth streams, large file transfers, or any scenario
where you want to avoid relaying all traffic through the server. Requires both
ends to be on NAT'd networks with compatible NAT types (EasyNAT).

### Configuration

Provider:

```toml
[[proxies]]
name = "video-stream"
type = "xtcp"
local_ip = "127.0.0.1"
local_port = 8554
sk = "xtcp-secret"
use_encryption = true
use_compression = true
```

Visitor:

```toml
[[visitors]]
name = "video-viewer"
type = "xtcp"
server_name = "video-stream"
secret_key = "xtcp-secret"
bind_addr = "127.0.0.1"
bind_port = 8554
use_encryption = true
use_compression = true
fallback_to = "video-stream-stcp"
fallback_timeout_ms = 5000
keep_tunnel_open = false
```

### Data Flow

```
Phase 1: Signaling (via frps)
  Visitor → frps: NatHoleVisitor
  frps → Provider: StartWorkConn + NatHoleSid (on work connection)
  Provider → STUN server: discover public address
  Provider → frps: NatHoleClient (reports STUN results on control connection)
  frps: runs NAT analysis (classify + behavior scoring)

Phase 2: Hole Punch
  frps → Visitor: NatHoleResp (provider's public addresses)
  frps → Provider: NatHoleResp (visitor's public addresses)
  Both sides: TCP simultaneous open to each other's public addresses

Phase 3: Direct P2P (frps out of data path)
  App → visitor frpc:8554 → [P2P encrypted bridge] → provider frpc → 127.0.0.1:8554
```

**Step by step:**

1. Visitor sends `NatHoleVisitor` message to frps (either on a fresh TCP
   connection or on the existing control connection -- Go frp compat path).
2. frps creates a NAT hole-punch session and sends `NatHoleSid` to the
   provider's control handler via internal messaging.
3. Provider receives `StartWorkConn` + `NatHoleSid` on its work connection,
   performs STUN to discover its public address, and reports back to frps
   via `NatHoleClient` on the control connection.
4. frps (`NatHoleCoordinator`) classifies the NAT types and runs the analyzer
   to score hole-punch feasibility.
5. frps sends `NatHoleResp` to both sides with the peer's public addresses.
6. Both sides perform **TCP simultaneous open** -- they dial each other's
   public addresses at the same time. If the NAT is EasyNAT (endpoint-independent
   mapping), the packets punch holes through both NATs and a direct TCP
   connection is established.
7. Once the P2P connection is up, data flows directly between visitor and
   provider. frps is no longer in the data path.
8. Provider sends `NatHoleReport` to frps to confirm the session completed.

### NAT Classification

frps classifies NAT behavior using a 5-mode behavior table. Each STUN probe
result is scored through an `Analyzer` with success/failure feedback. The
following NAT types are supported:

- **EasyNAT**: endpoint-independent mapping -- hole punching usually succeeds.
- **HardNAT**: address-and-port-dependent mapping -- hole punching usually fails.

### STCP Fallback

XTCP includes automatic fallback to STCP if hole punching fails:

```toml
fallback_to = "video-stream-stcp"   # STCP proxy name to fall back to
fallback_timeout_ms = 5000           # Wait up to 5 seconds before falling back
```

The visitor starts a timer when it begins the XTCP hole punch. If the P2P
connection is not established within `fallback_timeout_ms`, it connects to
the STCP proxy specified by `fallback_to` instead. This should point to a
separate STCP proxy on the same provider that serves as a relay backup.

### Retry Behavior

```toml
keep_tunnel_open = true         # Retry hole punch after connection ends
max_retries_an_hour = 8         # Max retry attempts per hour (default: 8)
min_retry_interval = 30          # Min seconds between retries (default: 30)
```

When `keep_tunnel_open = true`, the visitor retries NAT hole punching instead
of permanently falling back to STCP. This is useful for transient NAT changes.

### Encryption & Compression

Both `use_encryption` and `use_compression` are supported on the P2P bridge.
The encryption key is derived from the `sk` (SecretKey), not the auth token.
Both provider and visitor MUST use the same `sk`.

### Health Checks

TCP and HTTP health checks are supported on the provider side.

### Type-Specific Fields

Provider fields:

| Field | Description |
|-------|-------------|
| `sk` | **Required.** Secret key for encryption and visitor matching. |
| `virtual_net` | Virtual network namespace for isolation. |
| `allow_users` | Allowed visitor run_ids. Empty = only the owner (provider's user) can access; `["*"]` = all visitors allowed. |

Visitor fields (`[[visitors]]`):

| Field | Description |
|-------|-------------|
| `type` | `"xtcp"` |
| `server_name` | Name of the XTCP proxy to connect to. |
| `secret_key` | Secret key matching the provider's `sk`. |
| `bind_addr` / `bind_port` | Local address and port for the visitor listener. |
| `fallback_to` | STCP proxy name for fallback if hole punch fails. |
| `fallback_timeout_ms` | Fallback timeout in milliseconds (default: 1000). |
| `keep_tunnel_open` | Retry hole punch after connection ends instead of falling back. |
| `max_retries_an_hour` | Max XTCP retries per hour (default: 8). |
| `min_retry_interval` | Min seconds between retry attempts (default: 90). |
| `disable_assisted_addrs` | Disable NAT traversal assisted address reporting. |
| `use_encryption` / `use_compression` | Must match provider settings. |

Server-level fields (`frps.toml`):

| Field | Description |
|-------|-------------|
| `nat_hole_analysis_data_reserve_hours` | How long NAT behavior history is kept (default: 168). |

---

## TCPMux Proxy (`type = "tcpmux"`)

TCP multiplexing proxy. Routes connections through a shared server port using
HTTP CONNECT tunneling with Host header routing, eliminating the need for
a separate port per proxy.

**Use for:** Hosting many TCP services behind a single port. The external
client sends an HTTP CONNECT request with a Host header that identifies the
target service.

### Configuration

Server:

```toml
# frps.toml
tcpmux_httpconnect_port = 8080
```

Client:

```toml
[[proxies]]
name = "db-tcpmux"
type = "tcpmux"
local_ip = "127.0.0.1"
local_port = 5432
custom_domains = ["db.example.com"]
multiplexer = "yamux"
use_encryption = true
use_compression = true
```

### Data Flow

```
Client → frps:8080  (CONNECT db.example.com HTTP/1.1)
                          ↓
frps: TCPMuxManager lookup by Host header → finds proxy "db-tcpmux"
                          ↓
frps → 200 Connection Established → [bridge] → frpc → 127.0.0.1:5432
```

**Step by step:**

1. External client connects to `tcpmux_httpconnect_port` and sends an HTTP
   `CONNECT` request: `CONNECT db.example.com:443 HTTP/1.1\r\nHost: db.example.com\r\n\r\n`.
2. frps parses the `Host` header, strips the port, and looks up the hostname
   in `TcpMuxManager` (a routing table of domain → proxy).
3. If a matching tcpmux proxy is found, frps responds with
   `HTTP/1.1 200 Connection Established`.
4. From that point, the connection becomes a raw TCP tunnel. frps bridges it
   through a work connection to frpc, which connects to the local service.
5. If no matching route is found, frps returns 404.

The `multiplexer` field is stored/forwarded only and does not drive behavior —
yamux multiplexing is controlled by the global `tcp_mux` setting.

### Proxy Authentication

TCPMux supports HTTP Proxy-Authorization:

```toml
http_user = "proxy-user"
http_password = "proxy-pass"
```

The client must include a `Proxy-Authorization: Basic ...` header in the
CONNECT request.

### Encryption & Compression

Both `use_encryption` (AES-128-CFB) and `use_compression` (Snappy) are supported
on the work connection bridge.

### Health Checks

TCP and HTTP health checks are supported.

### Type-Specific Fields

| Field | Description |
|-------|-------------|
| `custom_domains` | **Required.** Domains used for CONNECT hostname routing. At least one domain must be provided. |
| `multiplexer` | Multiplexer type. Currently `"yamux"` is supported. Enables stream multiplexing over the work connection. |
| `http_user` / `http_password` | Proxy-Authorization credentials. Enables 407 Proxy Authentication Required challenge. |
| `group` / `group_key` | Load balancing group (same as TCP). |

Server-level fields (`frps.toml`):

| Field | Description |
|-------|-------------|
| `tcpmux_httpconnect_port` | Port for the TCPMux HTTP CONNECT listener (0 = disabled). |
| `tcp_mux_passthrough` | When true, CONNECT passthrough mode sends no 200 response — the full CONNECT request bytes are forwarded as pre-read data to the matched backend proxy. |

---

## Quick Reference

| Proxy Type | Transport | Public Port? | VHost/SNI Routing? | Enc/Comp? | Health Checks? |
|------------|-----------|--------------|---------------------|-----------|----------------|
| `tcp` | TCP | Yes (remote_port) | No | Yes | Yes (tcp/http) |
| `udp` | UDP | Yes (remote_port) | No | No | No |
| `sudp` | UDP | Yes (shared port) | No | No | No |
| `http` | TCP | No (vhost_http_port) | Yes (Host header) | Yes | Yes (tcp/http) |
| `https` | TCP | No (vhost_https_port) | Yes (SNI) | Yes | Yes (tcp/http) |
| `stcp` | TCP | No | No (sk routing) | Yes | Yes (tcp/http) |
| `xtcp` | TCP (P2P) | No | No (sk routing + STUN) | Yes | Yes (tcp/http) |
| `tcpmux` | TCP | No (tcpmux port) | Yes (CONNECT host) | Yes | Yes (tcp/http) |

### Common Fields (all proxy types)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Unique proxy name (required) |
| `type` | string | — | Proxy type (required) |
| `local_ip` | string | `"127.0.0.1"` | Local service IP |
| `local_port` | u16 | `0` | Local service port |
| `remote_port` | u16 | `0` | Remote port (0 = auto-assign). Not used by STCP/XTCP/TCPMux/HTTP/HTTPS. |
| `use_encryption` | bool | `false` | Encrypt proxy traffic (AES-128-CFB) |
| `use_compression` | bool | `false` | Compress proxy traffic (Snappy) |
| `bandwidth_limit` | string | `""` | Bandwidth limit, e.g. `"1MB"` |
| `bandwidth_limit_mode` | string | `"client"` | `"client"`, `"server"`, or `"both"` |
| `group` | string | `""` | Proxy group for load balancing |
| `group_key` | string | `""` | Group key for sticky sessions |
| `annotations` | map | `{}` | Key-value annotations |
| `metas` | map | `{}` | Key-value metadata |
| `enabled` | bool | `true` | Whether the proxy is started |
| `proxy_protocol_version` | string | `""` | HAProxy PROXY protocol: `"v1"`, `"v2"`, or `""` |

### Common Health Check Fields

| Field | Default | Description |
|-------|---------|-------------|
| `health_check_type` | `""` | `"tcp"` or `"http"`. Empty = disabled. |
| `health_check_url` | `""` | URL path for HTTP health checks. |
| `health_check_interval_seconds` | `10` | Seconds between checks (min 10). |
| `health_check_timeout_seconds` | `3` | Connect timeout per check (min 3). |
| `health_check_max_failed` | `1` | Consecutive failures before marking unhealthy (min 1). |
| `health_check_http_headers` | `{}` | Custom HTTP headers for health check requests. |

### Encryption & Compression Details

When `use_encryption = true`, data between frps and frpc is encrypted with
**AES-128-CFB**. The encryption key (16 bytes) is derived from the auth token
via PBKDF2-SHA1:

```
encryption_key = PBKDF2(token, "frp", iterations=64, key_len=16, hash=SHA1)
```

For XTCP P2P connections, the key is instead derived from the proxy's `sk`
(SecretKey), allowing peers to encrypt without sharing the auth token.

When `use_compression = true`, data is compressed with **Snappy** before
encryption. The order is:

```
plaintext → Snappy compress → AES-128-CFB encrypt → wire
```

### Load Balancing

TCP, HTTP, HTTPS, and TCPMux proxies support load balancing across multiple
frpc instances. Proxies with the same `group` value share incoming connections
via round-robin selection. When `group_key` is set, the server uses
hash-based sticky sessions to route the same client to the same backend.
