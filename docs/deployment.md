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

**Note on `ProtectSystem=strict`:** If you use TLS certificates, add `ReadWritePaths=/etc/frp` (or wherever your certs live). If you write logs to a file, add `ReadWritePaths=/var/log/frp`.

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
Total image size is approximately 3 MB.

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
      - FRP_DASHBOARD_PORT=7500
      - FRP_DASHBOARD_USER=admin
      - FRP_DASHBOARD_PWD=${DASHBOARD_PASS}

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

- `frp_proxy_traffic_in` — bytes received from clients (per proxy)
- `frp_proxy_traffic_out` — bytes sent to clients (per proxy)
- `frp_proxy_connections` — current active connections (per proxy)

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
# frps.toml
[web_server]
addr = "127.0.0.1"        # bind to localhost; put a reverse proxy in front
port = 7500
user = "admin"
password = "secure-password"
```

The dashboard provides:

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard (version, uptime, client/proxy counts) |
| `GET /api/status` | JSON status |
| `GET /api/proxies` | List all proxies with traffic stats |
| `GET /api/proxy/:name` | Single proxy detail |
| `GET /api/proxy/:name/traffic` | Traffic counters for a proxy |
| `GET /metrics` | Prometheus text format (if enabled) |

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

**3. Structured logging (for ELK / Loki):**

Set `RUST_LOG` for more granular control:

```bash
# Per-module log levels
RUST_LOG=info,frp_server=debug,frp_core::bridge=trace frps -c frps.toml
```

For JSON-formatted logs (suitable for ELK/Loki), pipe through a transformer
or use `tracing-subscriber`'s JSON layer (requires custom build).

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

Pre-establishes work connections so the server can assign them immediately
when a user connects, without waiting for `ReqWorkConn` + `NewWorkConn`:

```toml
# frpc.toml
pool_count = 5    # keep 5 idle work connections ready
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
heartbeat_interval = 30   # client sends a ping every 30s
```

The server's `heartbeat_timeout` should be at least 2x the client's
`heartbeat_interval`. Defaults (90s / 30s) work well for most deployments.
For high-latency or lossy links, increase `heartbeat_timeout` to 180s.

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
| `K` / `KB` | kilobytes (1,000 bytes) |
| `M` / `MB` | megabytes (1,000,000 bytes) |
| `G` / `GB` | gigabytes (1,000,000,000 bytes) |
| No suffix | bytes |

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
