# Production Deployment Guide

This guide covers deploying frp-rs in production environments: systemd services,
Docker, TLS, monitoring, and performance tuning.

---

## 1. Systemd Service

### Server Unit (`/etc/systemd/system/frps.service`)

```ini
[Unit]
Description=frp-rs server (frps)
Documentation=https://github.com/viogus/frp-rs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=frp
Group=frp
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/frp
WorkingDirectory=/var/lib/frp
StandardOutput=journal
StandardError=journal
SyslogIdentifier=frps

# Signal handling
# SIGUSR1: reload auth token + port range from config
KillSignal=SIGINT
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

**Note on `ProtectSystem=strict`:** If you use TLS certificates, add `ReadOnlyPaths=/etc/frp` (frps only needs to read certs, not write them). If you write logs to a file, add `ReadWritePaths=/var/log/frp`.

### Client Unit (`/etc/systemd/system/frpc.service`)

```ini
[Unit]
Description=frp-rs client (frpc)
Documentation=https://github.com/viogus/frp-rs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=frp
Group=frp
ExecStart=/usr/local/bin/frpc -c /etc/frp/frpc.toml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/frp
WorkingDirectory=/var/lib/frp
StandardOutput=journal
StandardError=journal
SyslogIdentifier=frpc

# For login_fail_exit = false, the client retries indefinitely.
# Restart=on-failure catches crashes; set RestartSec higher for
# retry-backoff (e.g. 15s) to avoid fast spin loops on misconfiguration.
RestartSec=15s

KillSignal=SIGINT
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
```

### Setup Commands

```bash
# Create the frp system user (no login, no home)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin frp

# Create config and working directories
sudo mkdir -p /etc/frp /var/lib/frp /var/log/frp
sudo chown -R frp:frp /etc/frp /var/lib/frp /var/log/frp

# Copy configs and binaries into place
sudo cp frps.toml /etc/frp/
sudo cp target/release/frps /usr/local/bin/

# Install and start
sudo cp frps.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable frps --now
sudo systemctl status frps
```

### Log Viewing

```bash
# Follow live logs
journalctl -u frps -f

# Last 100 lines
journalctl -u frps -n 100

# Since last boot
journalctl -u frps -b

# Filter by severity
journalctl -u frps -p err

# Time range
journalctl -u frps --since "2024-01-01" --until "2024-01-02"

# Export for analysis
journalctl -u frps -o json > frps-logs.json
```

### Adding `logrotate` (if using file logging)

```conf
# /etc/logrotate.d/frp
/var/log/frp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        # frps supports SIGUSR1 reload; no reopen needed if logging to stderr/journal
        /bin/kill -SIGUSR1 $(cat /run/frps.pid) 2>/dev/null || true
    endscript
}
```

---

## 2. Docker Deployment

### Pre-Built Images from GitHub Container Registry

```bash
# Server
docker pull ghcr.io/viogus/frps-rs:latest

# Client
docker pull ghcr.io/viogus/frpc-rs:latest
```

Available tags:
- `latest` — latest release, multi-arch (linux/amd64, linux/arm64)
- `vX.Y.Z` — pinned release version
- `test` — bleeding edge from `main` branch

Images are built from **scratch** (no base image). The Rust binary is linked
statically against musl, and the C entrypoint is compiled with `-static`.
Image size tracks the default-features binary: ~8.5 MB frps / ~6.8 MB frpc
(declared release profile, glibc build measured 2026-09-01 Linux x86_64;
musl link is the same order of magnitude) plus a few hundred KB of
busybox-free C entrypoint — a default frps image is roughly 8.8–9.3 MB. The
`tiny` tier (~5.2 MB frps / ~4.6 MB frpc) is the right choice for small
images.

### Optional UPX Compression

Not recommended by default — see the trade-offs below — but available for
storage-constrained deployments (embedded, air-gapped transfers):

```bash
upx -9 -o frps-upx frps && upx -9 -o frpc-upx frpc
```

Measured 2026-09-01 Linux x86_64, UPX 4.2.4, `-9` on the declared release
profile: frps 8,454,704 → 2,993,996 bytes, frpc 6,805,576 → 2,640,192
(~35–39% of original across all four tiers; `upx --test` verified, 1 MiB
byte-exact data-plane smoke-tested). Costs: **+30% idle RSS** (8.3 → 10.8 MB
frps, decompressed image lives in anonymous memory — raw binaries keep
demand-paged, evictable text), ~60 ms one-time startup decompression, and
classic antivirus false-positive risk (Go frp ships uncompressed for the
same reason). Docker layer compression already shrinks the raw binary in
transit, so the main win is raw artifact download, not image size.

### Docker Compose Example

```yaml
# docker-compose.yml
services:
  frps:
    image: ghcr.io/viogus/frps-rs:latest
    container_name: frps
    restart: unless-stopped
    network_mode: host               # required for correct proxy port binding
    volumes:
      - ./frps.toml:/app/frp.toml:ro   # mounted config skips env generation
    environment:
      # Optional overrides (only applied when /app/frp.toml is missing/empty)
      - FRP_BIND_PORT=7000
      - FRP_AUTH_TOKEN=${FRP_TOKEN}
      # NOTE: the published images build with default features only — the
      # dashboard is opt-in and NOT compiled in, so FRP_DASHBOARD_* vars are
      # ignored by ghcr.io/viogus/frps-rs:latest. To use the dashboard, build
      # your own image with `FRP_FEATURES="dashboard"` (see Dockerfile.source).

  frpc:
    image: ghcr.io/viogus/frpc-rs:latest
    container_name: frpc
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./frpc.toml:/app/frp.toml:ro
    environment:
      - FRP_SERVER_ADDR=${SERVER_IP}
      - FRP_SERVER_PORT=7000
      - FRP_AUTH_TOKEN=${FRP_TOKEN}
```

**Why `network_mode: host`?** The server binds proxy ports dynamically (one per
`remote_port`). Using host networking avoids publishing hundreds of individual
ports. In production, you can restrict port ranges with `allow_ports` or
`allow_port_start`/`allow_port_end` in the server config.

### Building from Source

```bash
# Build the Docker image from Rust source
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg FRP_COMPONENT=frps \
  -f docker/Dockerfile.source \
  -t frps-rs:local \
  .

# With feature flags (e.g., tiny build without QUIC/KCP/SSH)
docker buildx build \
  --platform linux/amd64 \
  --build-arg FRP_COMPONENT=frps \
  --build-arg FRP_FEATURES='--no-default-features --features tiny' \
  -f docker/Dockerfile.source \
  -t frps-rs:tiny \
  .
```

The `Dockerfile.source` uses `cargo-zigbuild` for cross-compilation with musl,
producing a fully static binary. The runtime stage is `FROM scratch`, so the
image contains only the Rust binary and the C entrypoint.

### Environment Variable Configuration

When no config file is mounted (or it is empty), the entrypoint auto-generates
a TOML config from environment variables before launching the binary.

**frps environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `FRP_BIND_ADDR` | `0.0.0.0` | Bind address |
| `FRP_BIND_PORT` | `7000` | Control port |
| `FRP_AUTH_TOKEN` | (none) | Authentication token |
| `FRP_SUBDOMAIN_HOST` | (none) | Sub-domain suffix |
| `FRP_TLS_CERT_FILE` | (none) | TLS certificate path |
| `FRP_TLS_KEY_FILE` | (none) | TLS private key path |
| `FRP_DASHBOARD_PORT` | (none) | Dashboard port (enables dashboard) |
| `FRP_DASHBOARD_ADDR` | `0.0.0.0` | Dashboard bind address |
| `FRP_DASHBOARD_USER` | (none) | Dashboard basic auth username |
| `FRP_DASHBOARD_PWD` | (none) | Dashboard basic auth password |

**frpc environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `FRP_SERVER_ADDR` | `127.0.0.1` | Server address |
| `FRP_SERVER_PORT` | `7000` | Server port |
| `FRP_AUTH_TOKEN` | (none) | Authentication token |
| `FRP_TUNNEL_NAME` | (none) | Proxy name |
| `FRP_TUNNEL_TYPE` | `tcp` | Proxy type |
| `FRP_TUNNEL_LOCAL_IP` | `127.0.0.1` | Local IP to forward |
| `FRP_TUNNEL_LOCAL_PORT` | (none) | Local port to forward |
| `FRP_TUNNEL_REMOTE_PORT` | (none) | Remote port to expose |

The env-only mode is convenient for simple single-proxy setups. For multiple
proxies or advanced configuration, mount a config file instead.

---

## 3. TLS Setup

### Self-Signed Certificates (Internal / Testing)

```bash
# Generate a self-signed certificate valid for 365 days
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/frp/server.key \
  -out /etc/frp/server.crt \
  -days 365 \
  -subj "/CN=frps.example.com"

# Set permissions
chmod 600 /etc/frp/server.key
chmod 644 /etc/frp/server.crt
```

### Server TLS Configuration (`frps.toml`)

```toml
bind_port = 7000

# Enable TLS on the control port
tls_enable = true
tls_cert_file = "/etc/frp/server.crt"
tls_key_file = "/etc/frp/server.key"
tls_only = false         # false: accept both TLS and plain TCP
                          # true:  reject non-TLS connections
                          # NOTE: setting tls_ca_file below auto-forces
                          # tls_only = true (Go TrustedCaFile parity)

# Mutual TLS (require client certificates)
tls_ca_file = "/etc/frp/ca.crt"    # CA that signed client certs
```

**`tls_only = true`**: The server will only accept TLS connections on
`bind_port`. Plain TCP and WebSocket-upgrade connections are rejected. All
clients must have `tls_enable = true`.

### Client TLS Configuration (`frpc.toml`)

```toml
server_addr = "frps.example.com"
server_port = 7000
transport_protocol = "tcp"

# Connect with TLS
tls_enable = true
tls_server_name = "frps.example.com"   # SNI hostname
tls_ca_file = "/etc/frp/ca.crt"        # CA to verify server cert

# Mutual TLS (client certificate)
tls_cert_file = "/etc/frp/client.crt"
tls_key_file = "/etc/frp/client.key"
```

### Let's Encrypt with Nginx Reverse Proxy

TLS can also be terminated at a reverse proxy in front of frps. This is the
recommended approach for public deployments: nginx handles certificate renewal
and modern TLS, while frps operates behind it.

```nginx
# /etc/nginx/sites-available/frps
upstream frps_backend {
    server 127.0.0.1:7000;   # frps bind_port (plain TCP)
}

server {
    listen 443 ssl http2;
    server_name frps.example.com;

    ssl_certificate     /etc/letsencrypt/live/frps.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/frps.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # frp control traffic is TCP, not HTTP. Stream it.
    location / {
        # N/A — frp is a TCP stream, not HTTP
    }
}
```

For frp's control connection, use nginx's **stream module** (`stream {}` block):

```nginx
# /etc/nginx/nginx.conf — add a stream block
stream {
    upstream frps_control {
        server 127.0.0.1:7000;
    }

    server {
        listen 7000 ssl;
        proxy_pass frps_control;

        ssl_certificate     /etc/letsencrypt/live/frps.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/frps.example.com/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
    }
}
```

With this setup, clients connect to `nginx:7000` (TLS-terminated), and nginx
proxies the decrypted stream to frps on `127.0.0.1:7000` (plain). Frps does not
need `tls_enable` in this configuration.

Certificate renewal with certbot:

```bash
sudo certbot --nginx -d frps.example.com
# certbot automatically updates the nginx config and sets up auto-renewal
```

### Mutual TLS (mTLS) Setup

Mutual TLS requires both server and client to present certificates signed by a
shared CA.

```bash
# 1. Create a CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=frp-internal-ca"

# 2. Create server certificate (signed by CA)
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/CN=frps.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

# 3. Create client certificate (signed by CA)
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr \
  -subj "/CN=frpc-client-01"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# 4. Distribute:
#    Server: server.crt, server.key, ca.crt
#    Client: client.crt, client.key, ca.crt
```

Server config with mTLS:

```toml
tls_enable = true
tls_cert_file = "/etc/frp/server.crt"
tls_key_file = "/etc/frp/server.key"
tls_ca_file = "/etc/frp/ca.crt"     # client certs must be signed by this CA
```

Client config with mTLS:

```toml
tls_enable = true
tls_cert_file = "/etc/frp/client.crt"
tls_key_file = "/etc/frp/client.key"
tls_ca_file = "/etc/frp/ca.crt"     # verify server cert against this CA
tls_server_name = "frps.example.com"
```

---

## 4. Monitoring

### Prometheus Metrics

The dashboard (and its `/metrics` endpoint) is **opt-in**: build frps with
the `dashboard` feature — `cargo build --release -p frps --features
"ssh,quic,dashboard"` (or set `FRP_FEATURES="dashboard"` when building the
Docker image). With a default-features binary the `[web_server]` section is
parsed but inert — no dashboard, no `/metrics`.

Enable Prometheus scraping on the dashboard port:

```toml
# frps.toml
[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "${DASHBOARD_PASSWORD}"
enable_prometheus = true
```

The `/metrics` endpoint exposes proxy-level counters in Prometheus text format:

- `frp_server_traffic_in` — bytes received from clients (per proxy)
- `frp_server_traffic_out` — bytes sent to clients (per proxy)
- `frp_server_connection_counts` — current active connections (per proxy)

Scrape configuration in Prometheus:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: frps
    scrape_interval: 15s
    basic_auth:
      username: admin
      password: ${DASHBOARD_PASSWORD}
    static_configs:
      - targets: ['frps-host:7500']
```

### Dashboard Web UI

```toml
# frps.toml — plain HTTP (put nginx in front for HTTPS)
[web_server]
addr = "127.0.0.1"        # bind to localhost; put a reverse proxy in front
port = 7500
user = "admin"
password = "secure-password"
```

For direct HTTPS without a reverse proxy, add TLS fields:

```toml
# frps.toml — direct HTTPS
[web_server]
addr = "0.0.0.0"
port = 7500
user = "admin"
password = "secure-password"
tls_cert_file = "/etc/frp/dashboard.crt"
tls_key_file = "/etc/frp/dashboard.key"
```

Both cert and key must be non-empty for TLS to activate (implicit detection, matching Go frp behavior). CLI flags `--dashboard-tls-cert-file` and `--dashboard-tls-key-file` also work.

The dashboard provides:

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard (version, uptime, client/proxy counts) — auth-protected |
| `GET /api/status` | JSON status |
| `GET /api/serverinfo` | Server info (Go frp dashboard parity) |
| `GET /api/proxies` | List all proxies with traffic stats |
| `DELETE /api/proxies` | Bulk delete; JSON body `{"proxies": ["name", …]}` |
| `GET /api/proxies/{name}` | Single proxy detail |
| `GET /api/proxy/{type}` | List proxies of one type |
| `GET /api/proxy/{type}/{name}` | Single proxy, scoped by type |
| `GET /api/traffic/{name}` | Proxy traffic counters (the Go v1 route, `api_router.go:46`) |
| `GET /api/proxy/{name}/traffic` | Same body as `/api/traffic/{name}` — frp-rs alias; Go's v1 route table has no such path |
| `GET /api/clients` / `GET /api/clients/{run_id}` | Connected clients |
| `GET /api/events` | WebSocket stream of live dashboard events |
| `GET /api/store/proxies` / `POST /api/store/proxies` | List / create dashboard-managed (stored) proxies |
| `DELETE /api/store/proxy/{name}` | Delete a stored proxy |
| `GET /api/v2/config` | Sanitized server config (the `auth` section carries only the method name; dashboard `user`/`password` are omitted) |
| `PUT /api/v2/proxy/{name}/update` | Hot-update a live proxy's server-side bandwidth settings |
| `GET /api/v2/system/info` | Version, config summary and status (Go `V2SystemInfoResp` parity) |
| `POST /api/v2/system/prune` | Clear offline-proxy statistics; requires `?type=offline_proxies`, the only accepted value (Go `V2SystemPruneResp` parity) |
| `GET /api/v2/users` | User list (Go `APIV2UserList` parity) |
| `GET /api/v2/clients` / `GET /api/v2/clients/{key}` | Connected clients, v2 shape |
| `GET /api/v2/proxies` / `GET /api/v2/proxies/{name}` / `GET /api/v2/proxies/{name}/traffic` | Proxies and per-proxy traffic, v2 shape |
| `GET /metrics` | Prometheus text format (only if `enable_prometheus = true`; still requires Basic auth) |

Outside auth, matching Go frp (`server.go:125-129`): `GET /healthz`,
`GET /debug/pprof` and `GET /debug/pprof/{*path}` — the pprof handlers are
placeholders that serve no Go-style CPU profiles.

`PUT /api/v2/proxy/{name}/update` accepts a JSON body such as
`{"bandwidthLimit": "2MB", "bandwidthLimitMode": "server"}`. Only
`bandwidthLimit` / `bandwidthLimitMode` are hot-applied (enforced on
subsequently established bridges). Provider-dependent fields
(`localIP`, `localPort`, `remotePort`, `customDomains`, `useEncryption`,
`useCompression`) are rejected with 400 — update the frpc config and reload
instead. Unknown proxy names return 404.

For production, put nginx in front of the dashboard with TLS and IP allowlisting:

```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.frps.example.com;
    ssl_certificate     /etc/letsencrypt/live/dashboard.frps.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dashboard.frps.example.com/privkey.pem;

    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:7500;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Client admin API** (`frpc`):

> The frpc admin API is behind the **opt-in `admin` feature** (it was a default
> until the 2026-08-09 audit round). A default `frpc` build ignores
> `web_server.port` entirely — build with `--features admin` to get it:
> `cargo build --release -p frpc --features admin`.

```toml
# frpc.toml
[web_server]
addr = "127.0.0.1"
port = 7400
user = "admin"
password = "secure-password"
```

Client endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Proxy status grouped by type |
| `GET /api/metrics` | Prometheus text format |
| `GET /api/config` | Current config (sensitive values redacted) |
| `PUT /api/config` | Update config + trigger reload (body limit 1 MiB) |
| `GET /api/proxy/{name}/config` | Effective config of one proxy |
| `GET /api/visitor/{name}/config` | Effective config of one visitor |
| `GET /api/reload` / `POST /api/reload` | Reload proxies from config file. Go-compatible strict mode via `?strictConfig=true`; the JSON body form is a frp-rs extension |
| `POST /api/stop` | Gracefully stop the client |
| `GET` / `POST /api/store/proxies`, `GET` / `PUT` / `DELETE /api/store/proxies/{name}` | Runtime proxy store CRUD — only when `store.path` is set; the same paths as Go frp (GET 200 / HEAD 405 / OPTIONS 405), but the body/payload shape is **frp-rs-specific** (Go frp's admin API uses a different nested body shape), so it is not wire-compatible with a Go admin client |
| `GET` / `POST /api/store/visitors`, `GET` / `PUT` / `DELETE /api/store/visitors/{name}` | Runtime visitor store CRUD — same conditions and the same frp-rs-specific payload shape |

`frpc reload`, `frpc status` and `frpc stop` load the config named by `-c` — the
same file a daemon started with `-c` uses; with no `-c` frp-rs keeps its
`127.0.0.1:7400` default, where Go defaults `-c` to ./frpc.ini — strictly unless
`--strict-config=false`, which all three accept (Go frp v0.71.0 inherits it as a
persistent root flag). The `=` spelling is the Go-faithful one; frp-rs **also**
accepts a space-separated `--strict-config <bool>` and consumes the token as the
value, which Go's pflag does not — an frp-rs extension, measured and tabulated
in `docs/developing.md` § `--strict-config`: the space-separated value form.
Using it prints one warning line on stderr (`warning: --strict-config <bool> is
an frp-rs extension; …`), because the outcome differs from Go silently
otherwise. Use the `=` spelling for any argv that must behave identically under
both binaries.
A config that fails to load is
reported on stdout and the command exits 1 **without contacting anything**,
rather than falling back to `127.0.0.1:7400`. When the address comes from the
config, `web_server.port` must be set — otherwise all three print Go's
`web server port should be set if you want to use this feature` and exit 1; the
two exceptions are no `-c` at all (frp-rs keeps its `127.0.0.1:7400` default and
checks no port) and a portless config given **both** `--admin-addr` and
`--admin-port` (the flags win, so the config port is never consulted). The
`--admin-addr` / `--admin-port` / `--admin-user` / `--admin-pwd` flags are an
frp-rs extension (Go frp v0.71.0's `reload`/`status`/`stop` register no such
flags) and override the address **after** a successful load, so they can no
longer mask a broken config; both `--admin-addr` and `--admin-port` must be given
for the override to apply. `stop` is Go's third admin command
(`cmd/frpc/sub/admin.go:42`): it POSTs `/api/stop` with an empty body
(`Content-Length: 0`, measured on the Go v0.71.0 binary) and prints
`stop success` on 200. Connection failures, non-200 responses and timeouts use
frp-rs's message shapes on **stderr** (`reload failed: …` /
`status query failed: …` / `stop failed: …`) — a pre-existing divergence from
Go's `fmt.Println(err)` on stdout, measured for `stop` against a 500: Go prints
`api status code [500]`.

`--api-timeout DURATION` is Go parity with Go's 30 s default
(`adminAPITimeout`). Go registers it *per subcommand*
(`cmd/frpc/sub/admin.go:47`), so `reload`, `status` and `stop` accept it and no
other subcommand does — measured on v0.71.0, `frpc verify --api-timeout=1s` is
`Error: unknown flag: --api-timeout`, exit 1. The value follows Go's
`time.ParseDuration` grammar — compound values, decimal fractions, an optional
sign, units `ns us µs μs ms s m h` — parsed in-tree because `Duration: FromStr`
is not implemented by the pinned toolchain (1.98.1: the trait bound
`Duration: FromStr` is not satisfied). As in Go, a zero or negative value is
accepted and means the deadline has already passed. One exception to that grammar
is recorded rather than copied: when the group sum passes `2^64`, Go's `uint64`
running total wraps and can still survive its own range checks — measured, two
2^63 ns groups wrap to 0 and Go reports `context deadline exceeded` — while
frp-rs rejects the input with `time: invalid duration`. frp-rs is stricter on
that class, never looser, and never panics; `TODO.md` carries the measurements
and `frp-core/src/cli.rs` the unit pin. The deadline covers the whole
admin call (connect, write, read); when it runs out — or had already passed
before dialing — the command prints `reload failed:` / `status query failed:` /
`stop failed:` followed by `admin request timed out after <duration>` on stderr
and exits 1, where Go prints `context deadline exceeded` on stdout (measured with
`--api-timeout=0`, `=0s` and `=-1s`). Both `--api-timeout` and `--api_timeout`
are accepted, and here that is Go parity rather than an frp-rs extension: Go's
`Execute()` installs `config.WordSepNormalizeFunc` globally
(`rootCmd.SetGlobalNormalizationFunc`, `cmd/frpc/sub/root.go`), so its flags
accept the underscore spelling too (measured for `--api_timeout` and
`--strict_config`; `--admin_addr` is `unknown flag` because no such flag exists
there). One placement difference remains: Go's cobra also accepts the flag before
the subcommand (`frpc --api-timeout 1s stop …`, measured), while frp-rs requires
the subcommand word first — the pre-existing rule for every subcommand flag,
unchanged here.

Four further differences remain in this flag's surface — none of them in the
accepted-value grammar or in the call itself. (1) A rejected value
is reported as bpaf's `Error: couldn't parse <value>: time: …`, where Go wraps
the same inner text in `invalid argument "<value>" for "--api-timeout" flag` —
for ASCII inputs the inner `time: …` wording matches Go verbatim, and the outer
shape is bpaf's, pre-existing across this CLI. (2) For a non-ASCII unit the inner
text does not match: `--api-timeout=1µ` gives Go
`time: unknown unit "\xc2\xb5" in duration "1\xc2\xb5"` and frp-rs
`time: unknown unit "µ" in duration "1µ"` — Go hex-escapes the unit and the
original, frp-rs prints them raw (measured on both binaries; `1d` matches
verbatim, so the inner identity is ASCII-only). (3) `frpc stop --help` renders
the flag as `--api-timeout=DURATION` and omits Go's `(default 30s)`, because bpaf
prints no fallback default. (4) A negative value collapses to `Duration::ZERO`,
so `--api-timeout=-1s` reports `admin request timed out after 0ns` where Go
reports `context deadline exceeded`.

`GET /api/reload` needs no body and no `Content-Type` — the Go-compatible call
`curl -u user:pass http://127.0.0.1:7400/api/reload` reloads in non-strict mode.
Strict mode is selected with Go's query parameter: `?strictConfig=true` (the
full `strconv.ParseBool` true set is `1 t T TRUE true True`; `0 f F FALSE false
False` are non-strict). With no parameter the reload is non-strict. Any other
value — including an empty `?strictConfig=` — is `ParseBool`'s error case, which
Go frp **discards**, so it is a 200 non-strict reload, never a 400. A repeated
parameter (`?strictConfig=true&strictConfig=false`) takes the **first** value,
matching Go's `url.Values.Get`, and a pair whose percent-escape is malformed
(`?strictConfig=%zz`) is dropped — again like `url.ParseQuery` — which leaves
the parameter absent and the reload non-strict. The remaining 400 sources are a
body that cannot be buffered or does not deserialize into the expected
`{"strict_config": bool}` shape, and a reload the loader itself rejects (a
strict-mode unknown key).

Strict mode does not recurse into `[[proxies]]` / `[[visitors]]` array elements,
and the server-side `[[httpPlugins]]` array behaves the same way. The gap is
wider than the reload answer: with strict mode on (Go's default, `strictConfig =
true`), Go frp v0.71.0 **refuses to start** on such a
config — `decode proxy at index 0: unmarshal ProxyConfig error: json: unknown
field "bogus_key_in_tcp_proxy"` — whereas frp-rs starts with the key dropped.
Arrays and nested tables are not walked generally: nothing inside an array
element is visited (including arrays nested there, such as a proxy's
`healthCheckHttpHeaders`), and a nested table in a section that *is* checked is
skipped too (`auth.tokenSource.exec.env` has no key set at `tokenSource`). The
sections most likely to be typo'd — `[auth]`, `[log]`, `[webServer]`,
`[transport]` — are still checked, so an unknown key there is still 400.

Keeping the loose direction is a choice between two affordable fixes, not a
missing capability. The key sets are mechanically derivable: `ProxyConfig`,
`VisitorConfig` and `HttpPluginConfig` are each a single union struct that
already carries Go's camelCase spellings as serde aliases, so one set per
*struct* — not per proxy type — covers every element.
`#[serde(deny_unknown_fields)]` on those structs implements it in a few lines
with no list to maintain, but it is unconditional: it cannot be keyed on
`strictConfig`, so it would also reject unknown fields in *non*-strict loads
(`--strict-config=false`), where Go ignores them — under strict mode, which is
Go's default and what the paragraph above measures, it would match Go instead. A
strict-only scan list instead has to track
every field and alias of those structs, exempt their open maps (`headers`,
`response_headers`, `annotations`, `metas`) and nested arrays, and has no
reflection to prove completeness (hand-maintained lists are already the pattern
for the walked sections — the risk here is completeness, not novelty): a false
400 blocks a valid config, while a missed typo only drops a key. frp-rs keeps the
loose direction on that basis; the Go-faithful strict-only fix is tracked as its
own `TODO.md` item.

The consequence is not uniform. An unknown or optional key is dropped silently —
`remote_portt = 7001` loads as `remote_port: 0`, the same silent-config-loss
class as the camelCase wire-field gotcha — but a *required* key left unset is
rejected with a message naming it (`visitor 'v': bind port is required`). For a
proxy block, check its keys against the type's reference rather than relying on
strict mode to catch a typo.

`POST /api/reload` additionally accepts the frp-rs extension body
`{"strict_config": true}` (also accepted as `"strictConfig"`, the spelling
frpc's own CLI sends); when both channels are present the query parameter wins.
A body that is present but malformed JSON is rejected with 400.

Three request-target rules follow from Go and are worth knowing. Go's admin
router matches methods exactly, so every `GET` route *Go registers* answers
`HEAD` with `405 Method Not Allowed` (`/api/metrics` is frp-rs-only — Go has no
such route and answers 404 for every method), and `HEAD /api/reload` never
reloads, whatever the query says.

The authenticated cells match Go; two *unauthenticated* cells do not, and the
two differ in kind. Because the auth middleware is applied to the whole admin
router before method and path routing, an unauthenticated `HEAD` on a registered
route is `401` here where Go answers `405`, and an unauthenticated request to an
unknown path (GET or HEAD) is `401` here where Go answers `404`. The unknown-path
cell is **permanent by decision**: `401` hides which paths exist, and a
construction that authenticates only matched routes (a blanket `route_layer`)
would answer `404` there and disclose configuration state too — measured on that
construction, `GET /api/store/proxies` answers `401` with `[store]` configured
and `404` without it. frp-rs prefers hiding existence to Go's `404`.

The `HEAD` cell is not an impossibility; it is a known alternative, rejected for
the fail-closed default. The Go-matching construction is per-handler auth on the
registered GET/POST routes, the existing unauthenticated
`handle_head_not_allowed` left on each route's `.head(...)`, and an auth-wrapped
`Router::fallback`: the adversarial review measured that construction with an
axum 0.8.9 probe to answer `405` there while keeping unmatched paths at `401`,
and measured Go frp v0.71.0's cells over the wire (unauthenticated `GET` `401`,
unauthenticated `HEAD` on a registered route `405`, unauthenticated unknown path
`404`); the construction needs no route introspection and no path
list. It is not adopted because authentication then becomes opt-in per route — a
route added later without the wrapper is unauthenticated by default, whereas the
single outer layer authenticates every route, present and future, by default.
Any future fix must first close that fail-open foot-gun (a wrapping helper plus a
test that every registered route answers `401` unauthenticated). Only a *blanket*
switch of `apply_admin_auth` to `route_layer` is out of scope here, because that
helper is the frps dashboard's too; the per-handler construction is admin-local.

More than 10000 query parameters disable `strictConfig`:
Go's `net/url.parseQuery` opens with a parameter-count guard (`defaultMaxParams =
10000`, inclusive, counting `&`s + 1) and its error leaves the query empty, so
`?strictConfig=true` plus 9999 `&` is a strict 400 and plus 10000 `&` is a
non-strict 200; frp-rs mirrors the guard, and because an over-limit query means
"parameter absent" the JSON body form can still select strict mode (a frp-rs
extension). Finally, do not put `#` in an admin request target: Go never splits
a fragment, so `/api/reload?strictConfig=true#strictConfig=false` is non-strict
for Go (its value is `true#strictConfig=false`) but strict here, and
`/api/reload#x?strictConfig=true` is Go's 404 but a reload here. The fragment
is dropped inside hyper's request-line parsing before any frp-rs code runs, so
that divergence cannot be fixed without replacing the HTTP stack.

### Health Checks

Client-side health checks for individual proxies:

```toml
[[proxies]]
name = "web-app"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 80
health_check_type = "tcp"
health_check_interval_seconds = 10
health_check_timeout_seconds = 3
health_check_max_failed = 3
```

For HTTP health checks:

```toml
[[proxies]]
name = "api"
type = "http"
local_ip = "127.0.0.1"
local_port = 3000
custom_domains = ["api.example.com"]
health_check_type = "http"
health_check_url = "/health"
health_check_interval_seconds = 30
health_check_timeout_seconds = 5
health_check_max_failed = 2
```

When a health check fails `health_check_max_failed` consecutive times, the proxy
is marked unhealthy and traffic stops being forwarded to it.

### Log Aggregation

frp-rs uses `tracing` for structured logging. Key recommendations:

**1. Journald (systemd, recommended):**

The systemd units above log to journald by default. Use `journald` forwarding
to aggregate:

```bash
# Forward to a central syslog server (add to frps.service)
StandardOutput=journal
StandardError=journal

# On the central host, use systemd-journal-remote or journalbeat
```

**2. File logging with rotation:**

```toml
[log]
level = "info"
file = "/var/log/frp/frps.log"
max_days = 3
```

The `max_days` setting auto-rotates log files. Combined with logrotate
(see Section 1), you get both rotation and compression.

**3. JSON / structured logging (for ELK / Loki):**

frp-rs emits JSON logs natively via `log.format`:

```toml
[log]
level = "info"
file = "/var/log/frp/frps.log"
max_days = 3
format = "json"
```

or from the CLI: `frps -c frps.toml --log-format json` (CLI wins over the
config file; `frpc` supports the same `--log-format`). JSON output combines
with `RUST_LOG` for per-module verbosity:

```bash
# Per-module log levels, JSON output
RUST_LOG=info,frp_server=debug,frp_core::bridge=trace frps -c frps.toml --log-format json
```

---

## 5. Performance Tuning

### File Descriptor Limits

Each proxy connection uses file descriptors. With many concurrent connections,
the default limit (often 1024) is insufficient.

```bash
# Check current limits
ulimit -n

# Set in the systemd unit (recommended):
# /etc/systemd/system/frps.service
[Service]
LimitNOFILE=65536

# Or set system-wide:
# /etc/security/limits.conf
frp  soft  nofile  65536
frp  hard  nofile  1048576
```

A good starting estimate: `max_concurrent_connections * 2` + 100 overhead.
For a server handling 10,000 concurrent proxy connections, plan for ~20,000
file descriptors.

### TCP Tuning

**`tcp_mux` (default: true):**

TCP multiplexing uses yamux to tunnel multiple logical streams over a single
TCP connection. This dramatically reduces connection establishment overhead.

```toml
# frps.toml
[transport]
tcp_mux = true
tcp_mux_keepalive_interval = 30    # seconds between keepalive pings
```

Keep `tcp_mux = true` unless you have a specific reason to disable it. Benefits:
- Fewer TCP handshakes (amortized across proxy connections)
- Reduced TIME_WAIT socket accumulation
- Lower per-connection memory overhead on the server

**`pool_count` (client-side):**

Caps the number of pre-established (idle) work connections. After login
the server issues `pool_count` `ReqWorkConn` requests immediately, so the
pool is **pre-warmed** right after login (Go frp semantics); further
connections are created on-demand when the server requests them, and
surplus connections are kept in the pool up to `pool_count`.

```toml
# frpc.toml
pool_count = 5    # keep up to 5 idle work connections ready
```

Start with `pool_count = 1` and increase if you observe latency spikes on
first connections to infrequently-used proxies. Each pooled connection
consumes negligible resources when idle.

Measured connection-setup latency (64 B probe, 2000 samples, loopback):

| `pool_count` | setup p50 | setup p99 |
|--------------|-----------|-----------|
| `0` (cold)   | 251 µs    | 633 µs    |
| `4` (warm)   | 191 µs    | 372 µs    |

Warming the pool cut setup p50 by ~24% and p99 by ~41% on loopback.
Latency-sensitive deployments can raise `pool_count` further.

`TCP_NODELAY` is enabled on every data-path TCP connection automatically
(matching Go frp), so small request/response and interactive traffic is not
delayed by Nagle's algorithm — no configuration needed.

For memory-constrained or high-fan-out servers, the per-connection bridge buffer
defaults to 32 KiB (matching Go frp) and can be tuned via the `FRP_BRIDGE_BUF_KB`
environment variable (range 4–1024).

**Heartbeat intervals:**

```toml
# frps.toml
[transport]
heartbeat_timeout = 90   # server disconnects if no ping within this window

# frpc.toml
heartbeat_interval = -1   # -1 = disabled under tcp_mux (Go v0.71.0 default)
```

With tcp_mux enabled (the default), app-layer heartbeats are **disabled
by default on the client** (`heartbeat_interval`/`heartbeat_timeout` default
to `-1`, Go v0.71.0 parity): yamux keepalive (30s) plus the server's 90s
control idle watchdog (active when `heartbeat_timeout <= 0`) cover
liveness. The server's `heartbeat_timeout` should be at least 2x the
client's `heartbeat_interval` when you re-enable client pings. For
high-latency or lossy links, increase `heartbeat_timeout` to 180s.

### Connection Pooling

**Server-side work pool:**

The server maintains a per-client work connection pool. When a user connects
to a proxy port, the server first checks the pool; if empty, it sends
`ReqWorkConn` and queues the user's connection. Increasing `pool_count` on the
client reduces this latency.

**Client-side dial keepalive:**

```toml
# frpc.toml
dial_server_keepalive = 60    # TCP keepalive on server connection (seconds)
```

In NAT-heavy environments, long-idle pooled connections may be silently
dropped. `dial_server_keepalive` sends TCP keepalive probes to detect and
re-establish dead connections before they are needed.

### Bandwidth Limiting

Per-proxy bandwidth limits on the client:

```toml
[[proxies]]
name = "file-server"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 8080
remote_port = 80
bandwidth_limit = "10MB"          # 10 MB/s max
bandwidth_limit_mode = "client"   # "client" or "server"
```

| Suffix | Value |
|--------|-------|
| `KB` | kibibytes (1024 bytes) |
| `MB` | mebibytes (1024 × 1024 bytes) |
| Any other suffix (e.g. `K`, `G`, `GB`), a lowercase suffix (`kb`/`mb`), or no suffix | **config-load error** — "invalid bandwidth_limit", proxy rejected at registration |

An empty string or a non-positive value (e.g. `0`, `0KB`) means unlimited
(`Some(0)`), matching Go frp's `BuildBandwidthLimit` semantics.

`bandwidth_limit_mode`:
- `"client"` — limit bandwidth on the frpc side (download from local service)
- `"server"` — limit bandwidth on the frps side (upload to remote user)

### Kernel Tuning (Linux)

```bash
# /etc/sysctl.d/99-frp.conf

# Increase the number of available ephemeral ports
net.ipv4.ip_local_port_range = 1024 65535

# Enable fast recycling of TIME_WAIT sockets
net.ipv4.tcp_tw_reuse = 1

# Increase TCP buffer sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Increase backlog
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 5000

# Apply
sudo sysctl -p /etc/sysctl.d/99-frp.conf
```

### Resource Limits (Docker)

When running frps in Docker with host networking, apply limits at the Docker
or orchestrator level:

```yaml
# docker-compose.yml
services:
  frps:
    image: ghcr.io/viogus/frps-rs:latest
    network_mode: host
    ulimits:
      nofile:
        soft: 65536
        hard: 1048576
    # Optional: CPU/memory limits
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
```

### Performance Checklist

- [ ] `LimitNOFILE=65536` (or higher) in systemd unit
- [ ] `tcp_mux = true` (unless you have a reason to disable it)
- [ ] `pool_count >= 1` for latency-sensitive workloads
- [ ] `heartbeat_timeout > 2 * heartbeat_interval`
- [ ] `dial_server_keepalive > 0` in NAT environments
- [ ] Kernel TCP buffers tuned for expected throughput
- [ ] `allow_ports` restricted to the ports you actually need
- [ ] Log level `info` (not `debug` or `trace`) in production
- [ ] Log to journald or file with rotation (not stderr to tty)
