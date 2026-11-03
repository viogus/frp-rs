# Client Plugin Reference

frpc supports the 10 Go-parity client-side plugin types plus the frp-rs
`http2connect` extension. Most plugins run as local servers on the frpc host,
handling application-level protocols before forwarding traffic through the frp
tunnel. When a proxy config includes a
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

### UDP

None. An HTTP forward proxy's CONNECT method is TCP-only (RFC 9110 §9.3.6), so
there is no UDP ASSOCIATE equivalent here. UDP relaying is available in the
`socks5` plugin (UDP ASSOCIATE) and the `http2connect` plugin (HTTP/2
CONNECT-UDP); HTTP/1.1 CONNECT-UDP is not a thing.

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

A SOCKS5 proxy server (RFC 1928). Supports CONNECT (TCP tunnel) and,
when `udp_enable = true`, UDP ASSOCIATE (RFC 1928 §7; frp-rs extension —
Go frp's `socks5` plugin is CONNECT-only). Optional username/password
authentication.

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

If `username` and `password` are both non-empty, the proxy accepts **only**
USERNAME/PASSWORD auth (method 0x02). Clients that offer only NO_AUTH (0x00)
are rejected with `0xFF` (no acceptable method). If credentials are set and
the client sends incorrect credentials, the connection is rejected.

Omit both `username` and `password` for an open SOCKS5 proxy (no auth).

### Supported Address Types

IPv4, domain name, and IPv6 targets are all supported.

### UDP ASSOCIATE

UDP is off by default. Enabling it binds a shared SOCKS5 UDP relay on the
frpc side **on the first `UDP ASSOCIATE`** (so a reload of a fixed
`udp_bind_addr` does not collide with the previous instance) and answers with
the configured `BND.ADDR`/`BND.PORT`. The relay forwards unfragmented datagrams
(`FRAG = 0`) to IPv4/IPv6/domain targets and frames replies with the concrete
host that sent them (a domain request is answered with its resolved IP, per
RFC 1928 §7). Fragmented datagrams are dropped. The receive buffer is 16 KiB,
so larger datagrams are truncated; keep application datagrams below that.

UDP datagrams cannot travel over the frp **TCP** tunnel that carries the SOCKS5
handshake, so the relay address must be reachable by the client. There are two
deployments:

**Through frps (default, automatic companion)** — frpc is behind NAT. Write
only the SOCKS5 proxy; frpc automatically registers a companion
`type = "udp"` proxy named `<name>__udp` on the **same remote port** and points
it at the relay's loopback socket:

```toml
[[proxies]]
name = "socks5_proxy"
type = "tcp"
remote_port = 7000

[proxies.plugin]
type = "socks5"
udp_enable = true
```

With no explicit addresses, frpc picks an ephemeral loopback port (for
example `127.0.0.1:34567`), fills `udp_bind_addr` with it and
`udp_advertise_addr = "<serverAddr>:7000"`, then registers
`socks5_proxy__udp` (`type = "udp"`, `remote_port = 7000`,
`local_ip = "127.0.0.1"`, `local_port = 34567`). The client receives the frps
public address and one port for both TCP and UDP. frps tracks TCP and UDP
remote ports separately (Go frp parity), so this is valid.

The companion is a normal UDP proxy on the wire, so it works against a Go frps
as well. It is **not** added to a `group`: UDP has a single owner per port, so
a grouped/HA SOCKS5 fleet can only have one member serving the UDP side at a
time; the TCP group is unaffected. The companion is visible in proxy/status
listings as `<name>__udp`; set
`udp_auto_companion = false` in `[proxies.plugin]` to disable the automatic
proxy. Automatic registration needs an explicit non-zero `remote_port`;
`remote_port = 0` cannot give TCP and UDP the same port, so frpc logs a warning
and skips the companion (the plugin still runs in direct mode). A user-written
UDP proxy already targeting the same `remote_port` wins; frpc does not add a
duplicate and warns if its `local_port` does not match `udp_bind_addr`. The
companion's address can still be overridden with explicit
`udp_bind_addr` / `udp_advertise_addr`; with the automatic companion an explicit
advertise port must equal `remote_port` (a bare IP gets `remote_port`); if it
does not, frpc logs a warning and skips the companion rather than refusing to
start. A deployment that sets **both** addresses and advertises a different
port is recognised as the direct shape below and left alone rather than
refused.

**Direct** — frpc is reachable from the client (public host or same LAN).
Disable the automatic companion and advertise the frpc host:

```toml
[proxies.plugin]
type = "socks5"
udp_enable = true
udp_auto_companion = false
udp_bind_addr = "0.0.0.0:17000"
udp_advertise_addr = "203.0.113.10:17000"   # the frpc host as the client sees it
```

**Manual companion** — a user-written proxy is still accepted for custom
topologies (for example, a UDP proxy on a different remote port). It is a
regular UDP proxy: it forwards each client datagram to the plugin's relay
socket, and the relay's replies go back through it. A manual companion
**requires a fixed `udp_bind_addr` and an explicit `udp_advertise_addr`**
(frps' public address:UDP remote port); an empty `udp_bind_addr` binds an
OS-assigned port that the companion's fixed `local_port` cannot reach, and the
connection answers `REP_SUCCEEDED` while every datagram is black-holed. frpc
warns when it detects this combination. The
loopback bind keeps a *second* raw relay off the network, but it does not make
the companion's public frps UDP port private.

The automatic companion leaves the same exposure: the frps UDP port is an open
relay while an association is alive. Firewall it exactly as you would the
manual proxy.

Association lifetime and scale:
- The association ends when its TCP control connection closes (a TCP
  half-close also ends it). An absolute 1-hour cap bounds an association whose
  peer vanished without FIN/RST; the plugin closes the control connection with
  no SOCKS-level signal, so a client holding an association longer than an hour
  must treat EOF as normal expiry and re-associate.
- A reply is only forwarded to a client if the source address is one the client
  requested. A protocol whose replies come from a different address/port than
  the request (some anycast/load-balanced UDP services) will not work.
- The relay forwards a target's reply to the datagram's source. A spoofed
  source address therefore makes the frpc host send the reply to the victim —
  a classic UDP reflector with the target's amplification factor. A source-IP
  ACL on the relay port does not mitigate spoofed sources; firewall the
  advertised UDP port.
- The relay admits at most 128 client sources (256 sockets) and remembers at
  most 256 targets per client per address family (up to 512 across both). Both
  caps evict the oldest entry; the client cap is by last activity, so a spray
  of more than 128 sources evicts legitimate clients too.
- At most 64 associations per plugin; the 65th gets `REP_GENERAL_FAILURE`.
- The forwarding gate is **per plugin, not per association**: while at least
  one association is live, datagrams from any source are accepted. A closed
  association's UDP source can therefore keep relaying until the last
  association closes (the 10-minute idle TTL only reaps its per-client state
  once traffic stops).

> **Security note:** RFC 1928 UDP framing carries no session token, so the
> relay cannot prove that a datagram was sent by the same client that completed
> the TCP association. SOCKS5 authentication gates *who may hold the association
> open*, not who may send datagrams through it, and it is not a substitute for
> network ACLs. The relay sends target traffic with the **frpc host's** source
> address, so the advertised public UDP port is an open UDP reflector: anyone
> who can reach it while an association is alive can make that host send UDP to
> arbitrary destinations. In either companion deployment (automatic or manual),
> loopback binding does not reduce this exposure — frps forwards the whole
> internet to that loopback socket. Enable UDP only on a trusted network, or
> front the port with a firewall/ACL that restricts who may send to it.

### Fields

| Field      | Type   | Required | Description                        |
|------------|--------|----------|------------------------------------|
| `username` | string | no       | SOCKS5 username (method 0x02)      |
| `password` | string | no       | SOCKS5 password                    |
| `udp_enable` | bool | no     | Enable `UDP ASSOCIATE` (frp-rs extension) |
| `udp_auto_companion` | bool | no | Automatically register the same-port `type = "udp"` proxy for the relay. Default: `true`. Needs an explicit non-zero `remote_port`; `remote_port = 0` logs a warning and skips the companion. Set `false` for direct or manually managed deployments. |
| `udp_bind_addr` | string | no | UDP relay bind address. Empty with auto companion = an ephemeral `127.0.0.1:<port>` chosen by frpc (the companion targets it); empty with auto disabled = `127.0.0.1:0` (OS-assigned). The socket binds on first association. |
| `udp_advertise_addr` | string | no | `BND.ADDR`/`BND.PORT` returned to clients. Empty with auto companion = `<serverAddr>:<remote_port>`; an explicit port must equal `remote_port`, and a bare IP gets `remote_port`. Empty with auto disabled = the bound address, with an unspecified bind (`0.0.0.0`/`[::]`) rewritten to loopback. A bare IP (no port) uses the bound port. |

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
plugin connects to the backend via TLS but does **not** verify the backend
certificate (`InsecureSkipVerify`).

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
- Backend TLS certificate is **not** verified (`InsecureSkipVerify`, matching
  Go frp behavior)
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
- Advertises ALPN `h2` + `http/1.1` by default (`enable_http2 = true`,
  matching Go frp `Complete()` backfilling nil → true; `http2http` Cargo
  feature, frpc default ON — tiny builds advertise `http/1.1` only)
- After TLS decryption, reads and parses the HTTP request — HTTP/2 inbound
  frames are decoded (`frp-client/src/plugin/h2.rs`) and forwarded to the
  backend as HTTP/1.1
- Forwards the request to `local_addr` over plain HTTP
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
| `enable_http2`        | bool   | no       | Advertise ALPN `h2` (default `true`)      |

> **Header-size note:** the plugin's h2 listener keeps Go frp's 16 MiB
> `max_header_list_size` (`defaultMaxHeaderListSize`) deliberately — it binds
> the operator's own 127.0.0.1 port and serves the local user's browser, so
> large Cookie jars/JWTs must not be rejected. The 4096-byte cap exists only
> on the server-side vhost h2c surface (untrusted public traffic).

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
- Advertises ALPN `h2` + `http/1.1` by default (`enable_http2 = true`;
  HTTP/2 inbound decoded via `plugin/h2.rs` and forwarded as HTTP/1.1)
- Decrypts the HTTP request
- Establishes a new TLS connection to the backend (SNI from `local_addr`
  hostname, without backend certificate verification)
- Forwards the request over the backend TLS connection
- Copies the response back through both TLS layers

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default)
- **`crt_file` and `key_file` are required** — for the plugin listener
- Backend TLS certificate is **not** verified (`InsecureSkipVerify`, matching
  Go frp behavior)

### Fields

| Field                 | Type   | Required | Description                               |
|-----------------------|--------|----------|-------------------------------------------|
| `local_addr`          | string | **yes**  | Backend `host:port` (TLS-enabled HTTPS)   |
| `crt_file`            | string | **yes**  | Path to TLS certificate PEM file          |
| `key_file`            | string | **yes**  | Path to TLS private key PEM file          |
| `host_header_rewrite` | string | no       | Override the Host header sent to backend  |
| `enable_http2`        | bool   | no       | Advertise ALPN `h2` (default `true`)      |

------------------------------------------------------------------------------

## 9. TLS to Raw (`plugin.type = "tls2raw"`)

TLS termination to raw TCP. frpc terminates TLS **on the tunnel side** (acting
as the TLS server), then connects to a local plain TCP service and relays the
decrypted bytes.

### Configuration

```toml
[[proxies]]
name = "tls_service"
type = "tcp"
remote_port = 9000

[proxies.plugin]
type = "tls2raw"
local_addr = "127.0.0.1:5432"
crt_file = "/etc/frp/edge.crt"
key_file = "/etc/frp/edge.key"
```

### Behavior

- Each tunnel connection is terminated by frpc with a TLS handshake (frpc is
  the TLS **server**, using `crt_file`/`key_file`)
- After TLS termination, frpc connects to the local plain TCP service at
  `local_addr`
- If `proxy_protocol_version` is set to `v1`/`v2`, a PROXY protocol header is
  written to the local connection so the service sees the real client IP/port
- Decrypted bytes are relayed bidirectionally between the TLS stream and the
  raw TCP connection

### Use Case

Expose a public TLS endpoint that forwards to a local plain-TCP service (e.g.,
a PostgreSQL or Redis server that is not TLS-aware). The public-facing frp
connection is handled by the proxy `type = "tcp"` — it is not TLS-aware. The
plugin terminates TLS on frpc and passes plaintext to the local service.

### TLS Requirements

- Requires **TLS feature** (`tls` — enabled by default)
- **`crt_file` and `key_file` are required** — PEM-format TLS certificate and
  private key used by frpc to terminate TLS on the tunnel side
- The local backend is plain TCP — no certificate verification

### Fields

| Field       | Type   | Required | Description                                    |
|-------------|--------|----------|------------------------------------------------|
| `local_addr`| string | **yes**  | Local plain TCP service `host:port`            |
| `crt_file`  | string | **yes**  | Path to TLS certificate PEM file               |
| `key_file`  | string | **yes**  | Path to TLS private key PEM file               |

------------------------------------------------------------------------------

## 10. HTTP/2 CONNECT (`plugin.type = "http2connect"`, frp-rs extension)

An HTTP/2 forward proxy that supports RFC 9113 `CONNECT` (TCP) and RFC 9298
extended CONNECT with `:protocol = connect-udp` (UDP over RFC 9297 capsules).
The listener is h2c (prior knowledge) by default; set `crt_file` and `key_file`
to terminate TLS with ALPN `h2` instead. Requires the `http2http` Cargo feature
(default on). This plugin type is not in Go frp.

### Configuration

```toml
[[proxies]]
name = "h2_proxy"
type = "tcp"
remote_port = 7100

[proxies.plugin]
type = "http2connect"
http_user = "optional-user"          # optional Proxy-Authorization
http_password = "optional-password"
# crt_file = "/etc/frp/h2.crt"       # optional: TLS + ALPN h2
# key_file = "/etc/frp/h2.key"
```

### TCP CONNECT

The client sends `CONNECT` with `:authority = host:port` (the port is required).
The plugin connects to that TCP target and bridges the h2 stream. Non-CONNECT
methods are rejected with `405`; a failed target connect is `502`/`504`.

### CONNECT-UDP

The client sends an extended `CONNECT` with `:protocol = connect-udp` and a
path whose last two segments are `{target_host}/{target_port}` (the RFC 9298
URI-template form). Any prefix — including `/.well-known/masque/udp/` — is
ignored; the last two segments are the target. RFC 9297 makes the request
header `Capsule-Protocol: ?1` a SHOULD; this plugin accepts a request without it
because `:protocol = connect-udp` makes the capsule dialect unambiguous, and
the successful response always carries `capsule-protocol: ?1`. Each subsequent
h2 DATA byte stream is a sequence of RFC 9297 capsules. A `DATAGRAM` capsule
(type `0x00`) value is `Context ID (varint) + UDP payload`; context `0` carries
the UDP datagram, and datagrams with an unregistered context ID are dropped.
Unknown capsule types are skipped. A malformed or oversized DATAGRAM capsule
(64 KiB cap) closes the stream. After a client half-close the target→client tail
is closed after 30 s of target silence or 1 h total; a single target write is
bounded at 30 s so a non-reading target cannot pin the fd indefinitely.

### Authentication

When `http_user`/`http_password` are set, every request must carry a matching
`Proxy-Authorization: Basic ...` header; otherwise the response is `407` with
`Proxy-Authenticate: Basic realm="frp"`.

### Security

Like the `http_proxy` plugin this is an open forward proxy once an operator can
reach it: TCP CONNECT can reach any target, and CONNECT-UDP can send to any
target the frpc host can route to — including `127.0.0.1` (local backends and,
with the `admin` feature, frpc's admin API). Put credentials on it and/or
restrict who can reach the frp remote port. The advertised listener is the frp
TCP proxy's `remote_port`; TLS only protects the client-to-frpc hop, not the
target side.

### Fields

| Field           | Type   | Required | Description |
|-----------------|--------|----------|-------------|
| `http_user`     | string | no       | Proxy Basic auth username |
| `http_password` | string | no       | Proxy Basic auth password |
| `crt_file`      | string | no       | TLS certificate PEM; must be paired with `key_file` |
| `key_file`      | string | no       | TLS private key PEM; must be paired with `crt_file` |

------------------------------------------------------------------------------

## Common Plugin Fields Reference

All fields available in the `[proxies.plugin]` section:

| Field                 | Used by                                    | Description                                    |
|-----------------------|--------------------------------------------|------------------------------------------------|
| `type`                | **all**                                    | Plugin type identifier                         |
| `http_user`           | http_proxy, http2connect, static_file      | HTTP Basic auth username                       |
| `http_password`       | http_proxy, http2connect, static_file      | HTTP Basic auth password                       |
| `username`            | socks5                                     | SOCKS5 username                                |
| `password`            | socks5                                     | SOCKS5 password                                |
| `local_addr`          | unix_domain_socket, http2http, http2https, https2http, https2https, tls2raw | Backend address (host:port or socket path) |
| `local_path`          | static_file                                | Filesystem directory to serve                  |
| `strip_prefix`        | static_file                                | URL prefix to strip before filesystem lookup   |
| `host_header_rewrite` | http2http, http2https, https2http, https2https | Override Host header sent to backend        |
| `crt_file`            | https2http, https2https, tls2raw, http2connect | TLS certificate PEM for plugin listener     |
| `key_file`            | https2http, https2https, tls2raw, http2connect | TLS private key PEM for plugin listener     |

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
| tls2raw          | **yes**              | no            | `local_addr`, `crt_file`, `key_file` |
| http2connect     | no (gated by `http2http`; TLS optional) | no | — (optional `crt_file`/`key_file`) |
| virtual_net      | no                   | no            | `[virtualNet] address`        |

Plugins compiled without the required feature will return a descriptive error
at startup rather than silently failing.

------------------------------------------------------------------------------

## Proxy Virtual Net Plugin (`[proxies.plugin] type = "virtual_net"`)

The Go frp v0.71.1 `virtual_net` proxy plugin exposes the client's TUN device
to remote `virtual_net` visitors. It does not bind a local listener. When the
server assigns a work connection to this proxy, frpc hands the connection to
the vnet controller: bytes from the remote tunnel are written into the local
TUN, and the remote source IP is registered so TUN return packets go back over
the same work connection. The proxy's `use_encryption`/`use_compression`
transport settings are applied to the work-connection byte stream, and config
reload re-creates the TUN device for added or changed `virtual_net` proxies.

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
`[feature] VirtualNet = true`, the `vnet` build feature (opt-in, not in
default binaries), and a valid IPv4 `[virtualNet] address`.

------------------------------------------------------------------------------

## Visitor Virtual Net Plugin (`[visitors.plugin] type = "virtual_net"`)

Go frp v0.71.1 also supports a visitor-side `virtual_net` plugin. It does not
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

Requires `[feature] VirtualNet = true` and the `vnet` build feature
(opt-in: `--features vnet` on frps/frpc — not in default binaries).
frp-rs parses, validates, advertises/removes the `destinationIP`
route (IPv4 `/32` or IPv6 `/128`) over the control connection, and forwards
inbound `VnetPacket`s into the STCP/XTCP visitor tunnel. The visitor tunnel is
a no-bind tunnel: raw IP packets are written into it with the visitor's
`use_encryption`/`use_compression` settings applied, and return traffic
arriving on the tunnel is delivered to the local TUN whose subnet contains the
packet destination instead of being broadcast to every TUN.
