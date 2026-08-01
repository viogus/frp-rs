# Client Plugin Reference

frpc supports 10 client-side plugin types. Most plugins run as local servers
on the frpc host, handling application-level protocols before forwarding
traffic through the frp tunnel. When a proxy config includes a
`[proxies.plugin]` section, frpc starts the plugin server instead of
connecting to an existing local TCP port. The `virtual_net` plugin is the
exception: it has no local listener and instead hands work connections to the
vnet controller.

Local-listener plugins use `type = "tcp"` for the proxy. Each plugin binds its
own local listener on `127.0.0.1:0` (OS-assigned port) and the frp tunnel
forwards traffic to it.

Plugin configuration fields are documented in the TOML `[proxies.plugin]`
section. All fields are optional unless noted.

------------------------------------------------------------------------------

## 1. HTTP Proxy (`plugin.type = "http_proxy"`)

An HTTP forward proxy with CONNECT tunneling. Traffic from the frp tunnel is
handled by this proxy, which makes the upstream request. Supports plain HTTP
forwarding and CONNECT-based HTTPS tunneling.

### Configuration

```toml
[[proxies]]
name = "web_proxy"
type = "tcp"
remote_port = 6000

[proxies.plugin]
type = "http_proxy"
http_user = "optional-user"
http_password = "optional-password"
```

### Behavior

| HTTP method | Action                                            |
|-------------|---------------------------------------------------|
| CONNECT     | Tunnel to target host:port (HTTPS pass-through)   |
| GET, POST, ... | Proxy the request to the upstream HTTP server |

### Authentication

Optional. When `http_user` and `http_password` are both non-empty, the proxy
requires `Proxy-Authorization: Basic ...` header from clients. Uses the
standard HTTP 407 Proxy Authentication Required challenge.

### Fields

| Field         | Type   | Required | Description                              |
|---------------|--------|----------|------------------------------------------|
| `http_user`   | string | no       | Username for Basic proxy auth            |
| `http_password` | string | no       | Password for Basic proxy auth            |

------------------------------------------------------------------------------

## 2. SOCKS5 (`plugin.type = "socks5"`)

A SOCKS5 proxy server (RFC 1928). Supports CONNECT command only (TCP tunnel).
Optional username/password authentication.

### Configuration

```toml
[[proxies]]
name = "socks5_proxy"
type = "tcp"
remote_port = 7000

[proxies.plugin]
type = "socks5"
username = "alice"
password = "s3cret"
```

### Authentication

If `username` and `password` are both non-empty, the server advertises
USERNAME/PASSWORD auth (method 0x02) in addition to NO_AUTH (0x00). Clients
that support user/pass will be challenged; clients without credentials can
still use NO_AUTH. If credentials are set and the client sends incorrect
credentials, the connection is rejected.

Omit both `username` and `password` for an open SOCKS5 proxy (no auth).

### Supported Address Types

IPv4, domain name, and IPv6 targets are all supported.

### Fields

| Field      | Type   | Required | Description                        |
|------------|--------|----------|------------------------------------|
| `username` | string | no       | SOCKS5 username (method 0x02)      |
| `password` | string | no       | SOCKS5 password                    |

------------------------------------------------------------------------------

## 3. Static File (`plugin.type = "static_file"`)

Serves static files from a local directory over HTTP. Handles MIME type
detection from file extensions. Optional basic auth and URL prefix stripping.

### Configuration

```toml
[[proxies]]
name = "static_site"
type = "tcp"
remote_port = 8000

[proxies.plugin]
type = "static_file"
local_path = "/var/www/html"
strip_prefix = "assets"
http_user = "admin"
http_password = "secret123"
```

### URL Resolution

1. Request path is URL-decoded (`%20` → space, etc.)
2. If `strip_prefix` is set, it is stripped from the beginning of the decoded
   path (e.g., `/assets/style.css` → `/style.css`)
3. The path is joined with `local_path` on the filesystem
4. If the path is a directory, `index.html` is appended
5. Path traversal (`..`) is rejected with 403 Forbidden

### Authentication

When `http_user` and `http_password` are set, the server requires HTTP Basic
Authentication (`Authorization: Basic ...` header). Returns 401 Unauthorized
with `WWW-Authenticate: Basic realm="frp"` on failure.

### Supported MIME Types

html, htm, css, js, json, png, jpg, jpeg, gif, svg, ico, txt, xml, pdf, zip,
wasm, woff, woff2, ttf, mp3, mp4, webm. All others fall back to
`application/octet-stream`.

### Fields

| Field          | Type   | Required | Description                                      |
|----------------|--------|----------|--------------------------------------------------|
| `local_path`   | string | **yes**  | Filesystem path to serve files from              |
| `strip_prefix` | string | no       | URL path prefix to strip before filesystem lookup |
| `http_user`    | string | no       | Username for HTTP Basic auth                     |
| `http_password`| string | no       | Password for HTTP Basic auth                     |

------------------------------------------------------------------------------

## 4. Unix Domain Socket (`plugin.type = "unix_domain_socket"`)

Bridges frp tunnel connections to a local Unix domain socket instead of TCP.
Each inbound tunnel connection causes frpc to connect to the Unix socket and
bidirectionally relay data.

### Configuration

```toml
[[proxies]]
name = "docker_api"
type = "tcp"
remote_port = 9000

[proxies.plugin]
type = "unix_domain_socket"
local_addr = "/var/run/docker.sock"
```

Go frp's flat plugin format is also supported and is the recommended form for
configs shared with Go frp:

```toml
[[proxies]]
name = "docker_api"
type = "tcp"
remote_port = 9000
plugin = "unix_domain_socket"
plugin_local_addr = "/var/run/docker.sock"
```

### Platform Support

Unix only (Linux, macOS, BSD). Returns an error on Windows.

### Fields

| Field       | Type   | Required | Description                          |
|-------------|--------|----------|--------------------------------------|
| `local_addr`| string | **yes**  | Path to the Unix domain socket       |

### Notes

- No authentication — the plugin simply relays bytes between the tunnel and
  the socket.
- The socket must already exist and be writable by the frpc process.
- No TLS, no protocol handling — pure byte relay.

------------------------------------------------------------------------------

## 5. HTTP to HTTP (`plugin.type = "http2http"`)

Reverse proxy: frpc accepts plain HTTP and forwards to a plain HTTP backend.
Headers are passed through with optional Host header rewriting.

### Configuration

```toml
[[proxies]]
name = "web_backend"
type = "tcp"
remote_port = 8080

[proxies.plugin]
type = "http2http"
local_addr = "127.0.0.1:3000"
host_header_rewrite = "myapp.internal"
```

### Behavior

- Reads the HTTP request from the tunnel connection
- Parses request line and headers
- Optionally rewrites the `Host` header if `host_header_rewrite` is set
- Forwards the request to `local_addr` using HTTP/1.0 with `Connection: close`
- Copies the backend response back to the client

### Fields

| Field                 | Type   | Required | Description                               |
|-----------------------|--------|----------|-------------------------------------------|
| `local_addr`          | string | **yes**  | Backend `host:port` (plain HTTP)          |
| `host_header_rewrite` | string | no       | Override the Host header sent to backend  |

### TLS Required

No.

------------------------------------------------------------------------------

## 6. HTTP to HTTPS (`plugin.type = "http2https"`)

Reverse proxy: frpc accepts plain HTTP and forwards to an HTTPS backend. The
plugin connects to the backend via TLS, verifying its certificate with system
root CAs.

### Configuration

```toml
[[proxies]]
name = "secure_backend"
type = "tcp"
remote_port = 8443

[proxies.plugin]
type = "http2https"
local_addr = "backend.example.com:443"
host_header_rewrite = "backend.example.com"
```

### Behavior

- Same HTTP request parsing and forwarding as `http2http`
- Connects to the backend via TCP + TLS (rustls)
- Server Name Indication (SNI) is set from the `local_addr` hostname
- Backend TLS certificate is verified against system root CAs
- The forwarded request is sent over the encrypted TLS connection

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default). Fails at startup if
  TLS is not compiled in.
- No `crt_file`/`key_file` needed for the listener side — this plugin does not
  terminate TLS for incoming traffic.

### Fields

| Field                 | Type   | Required | Description                                 |
|-----------------------|--------|----------|---------------------------------------------|
| `local_addr`          | string | **yes**  | Backend `host:port` (TLS-enabled HTTPS)     |
| `host_header_rewrite` | string | no       | Override the Host header sent to backend    |

------------------------------------------------------------------------------

## 7. HTTPS to HTTP (`plugin.type = "https2http"`)

Reverse proxy: frpc accepts HTTPS (terminates TLS) and forwards decrypted
traffic to a plain HTTP backend. Requires a TLS certificate and private key.

### Configuration

```toml
[[proxies]]
name = "tls_terminated"
type = "tcp"
remote_port = 443

[proxies.plugin]
type = "https2http"
local_addr = "127.0.0.1:8080"
crt_file = "/etc/frp/server.crt"
key_file = "/etc/frp/server.key"
host_header_rewrite = "app.local"
```

### Behavior

- Accepts TLS on the incoming connection using the provided `crt_file`/`key_file`
- After TLS decryption, reads and parses the HTTP request
- Forwards the request to `local_addr` over plain HTTP/1.0
- Copies the backend response back over the encrypted TLS channel

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default)
- **`crt_file` and `key_file` are required** — PEM-format TLS certificate and
  private key for the plugin listener

### Fields

| Field                 | Type   | Required | Description                               |
|-----------------------|--------|----------|-------------------------------------------|
| `local_addr`          | string | **yes**  | Backend `host:port` (plain HTTP)          |
| `crt_file`            | string | **yes**  | Path to TLS certificate PEM file          |
| `key_file`            | string | **yes**  | Path to TLS private key PEM file          |
| `host_header_rewrite` | string | no       | Override the Host header sent to backend  |

------------------------------------------------------------------------------

## 8. HTTPS to HTTPS (`plugin.type = "https2https"`)

Reverse proxy: frpc accepts HTTPS (terminates TLS), then re-encrypts and
forwards to an HTTPS backend. TLS on both sides — the plugin acts as a
man-in-the-middle for TLS, decrypting incoming traffic and re-encrypting it
for the backend.

### Configuration

```toml
[[proxies]]
name = "double_tls"
type = "tcp"
remote_port = 443

[proxies.plugin]
type = "https2https"
local_addr = "internal-api.example.com:443"
crt_file = "/etc/frp/edge.crt"
key_file = "/etc/frp/edge.key"
host_header_rewrite = "internal-api.example.com"
```

### Behavior

- Accepts TLS on the incoming connection using `crt_file`/`key_file`
- Decrypts the HTTP request
- Establishes a new TLS connection to the backend (SNI from `local_addr`
  hostname, verified against system root CAs)
- Forwards the request over the backend TLS connection
- Copies the response back through both TLS layers

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default)
- **`crt_file` and `key_file` are required** — for the plugin listener
- Backend TLS is verified with system root CAs (no custom CA support)

### Fields

| Field                 | Type   | Required | Description                               |
|-----------------------|--------|----------|-------------------------------------------|
| `local_addr`          | string | **yes**  | Backend `host:port` (TLS-enabled HTTPS)   |
| `crt_file`            | string | **yes**  | Path to TLS certificate PEM file          |
| `key_file`            | string | **yes**  | Path to TLS private key PEM file          |
| `host_header_rewrite` | string | no       | Override the Host header sent to backend  |

------------------------------------------------------------------------------

## 9. TLS to Raw (`plugin.type = "tls2raw"`)

TLS termination to raw TCP. The plugin connects to a local TLS service
(frpc acts as TLS client), decrypts the stream, and forwards the raw bytes
through the frp tunnel.

### Configuration

```toml
[[proxies]]
name = "tls_service"
type = "tcp"
remote_port = 9000

[proxies.plugin]
type = "tls2raw"
local_addr = "127.0.0.1:5432"
```

### Behavior

- Each tunnel connection triggers a TCP connection to `local_addr`
- The TCP connection is upgraded to TLS (frpc is the TLS client)
- SNI is set from the `local_addr` hostname
- Backend TLS certificate is verified against system root CAs
- After TLS handshake, raw bytes are relayed bidirectionally between the
  tunnel and the TLS stream

### Use Case

Expose a local TLS-only service (e.g., a PostgreSQL server requiring TLS)
through frp while handling the TLS layer on frpc. The public-facing frp
connection is handled by the proxy `type = "tcp"` — it is not TLS-aware.
TLS is stripped at the plugin, and raw TCP flows through the tunnel.

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default)
- No `crt_file`/`key_file` needed — frpc is a TLS client, not server
- Backend TLS certificate is verified with system root CAs

### Fields

| Field       | Type   | Required | Description                                    |
|-------------|--------|----------|------------------------------------------------|
| `local_addr`| string | **yes**  | Local TLS service `host:port`                  |

------------------------------------------------------------------------------

## Common Plugin Fields Reference

All fields available in the `[proxies.plugin]` section:

| Field                 | Used by                                    | Description                                    |
|-----------------------|--------------------------------------------|------------------------------------------------|
| `type`                | **all**                                    | Plugin type identifier                         |
| `http_user`           | http_proxy, static_file                    | HTTP Basic auth username                       |
| `http_password`       | http_proxy, static_file                    | HTTP Basic auth password                       |
| `username`            | socks5                                     | SOCKS5 username                                |
| `password`            | socks5                                     | SOCKS5 password                                |
| `local_addr`          | unix_domain_socket, http2http, http2https, https2http, https2https, tls2raw | Backend address (host:port or socket path) |
| `local_path`          | static_file                                | Filesystem directory to serve                  |
| `strip_prefix`        | static_file                                | URL prefix to strip before filesystem lookup   |
| `host_header_rewrite` | http2http, http2https, https2http, https2https | Override Host header sent to backend        |
| `crt_file`            | https2http, https2https                    | TLS certificate PEM for plugin listener        |
| `key_file`            | https2http, https2https                    | TLS private key PEM for plugin listener        |

------------------------------------------------------------------------------

## Feature Gate Summary

| Plugin           | Requires TLS feature | Requires Unix | Required config fields        |
|------------------|----------------------|---------------|-------------------------------|
| http_proxy       | no                   | no            | —                             |
| socks5           | no                   | no            | —                             |
| static_file      | no                   | no            | `local_path`                  |
| unix_domain_socket | no                 | **yes**       | `local_addr`                  |
| http2http        | no                   | no            | `local_addr`                  |
| http2https       | **yes**              | no            | `local_addr`                  |
| https2http       | **yes**              | no            | `local_addr`, `crt_file`, `key_file` |
| https2https      | **yes**              | no            | `local_addr`, `crt_file`, `key_file` |
| tls2raw          | **yes**              | no            | `local_addr`                  |
| virtual_net      | no                   | no            | `[virtualNet] address`        |

Plugins compiled without the required feature will return a descriptive error
at startup rather than silently failing.

------------------------------------------------------------------------------

## Proxy Virtual Net Plugin (`[proxies.plugin] type = "virtual_net"`)

The Go frp v0.70.1 `virtual_net` proxy plugin exposes the client's TUN device
to remote `virtual_net` visitors. It does not bind a local listener. When the
server assigns a work connection to this proxy, frpc hands the connection to
the vnet controller: bytes from the remote tunnel are written into the local
TUN, and the remote source IP is registered so TUN return packets go back over
the same work connection.

```toml
[virtualNet]
address = "10.0.0.2"

[[proxies]]
name = "vnet-provider"
type = "tcp"

[proxies.plugin]
type = "virtual_net"
```

The Go-style flat form `plugin = "virtual_net"` is also accepted. Requires
`[feature] VirtualNet = true`, the `vnet` build feature, and a valid IPv4
`[virtualNet] address`.

------------------------------------------------------------------------------

## Visitor Virtual Net Plugin (`[visitors.plugin] type = "virtual_net"`)

Go frp v0.70.1 also supports a visitor-side `virtual_net` plugin. It does not
bind a local TCP listener; instead it advertises `destinationIP` as a host
route through the virtual network routing path.

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

Requires `[feature] VirtualNet = true` and the `vnet` build feature (on by
default). frp-rs parses, validates, advertises/removes the `destinationIP`
route over the control connection, and forwards inbound `VnetPacket`s into
the STCP/XTCP visitor tunnel. The visitor tunnel is a no-bind tunnel: raw IP
packets are written into it, and return traffic arriving on the tunnel is
delivered through the same TUN channels used by control-connection
`VnetPacket`s to local TUN-backed vnet proxies.
