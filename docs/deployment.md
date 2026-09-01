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
| `GET /` | HTML dashboard (version, uptime, client/proxy counts) |
| `GET /api/status` | JSON status |
| `GET /api/proxies` | List all proxies with traffic stats |
| `GET /api/proxies/{name}` | Single proxy detail (also `GET /api/proxy/{type}/{name}`) |
| `GET /api/proxy/:name/traffic` | Traffic counters for a proxy |
| `GET /api/v2/config` | Sanitized server config (the `auth` section carries only the method name; dashboard `user`/`password` are omitted) |
| `PUT /api/v2/proxy/{name}/update` | Hot-update a live proxy's server-side bandwidth settings |
| `GET /metrics` | Prometheus text format (if enabled) |

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
| `GET /api/config` | Current config (sensitive values redacted) |
| `PUT /api/config` | Update config + trigger reload |
| `GET /api/reload` | Reload proxies from config file |
| `POST /api/stop` | Gracefully stop the client |

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
