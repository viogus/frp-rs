# Configuration Reference

Complete field reference for frp-rs `frps.toml` and `frpc.toml`. Every field maps
1:1 to a Go frp v0.71.0 equivalent.

---

## Server Configuration (`frps.toml`)

### Top-Level Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bind_addr` | `string` | `"0.0.0.0"` | `bindAddr` | Address the server listens on for control connections. An explicit empty string is completed to `0.0.0.0` too (Go's `ServerConfig.Complete()`, `server.go:110`), so only an absent key and `""` share the default. |
| `bind_port` | `u16` | `7000` | `bindPort` | Main port for control connections. Clients dial this port. An explicit `0` — in the file or via `--bind-port 0` — is also completed to `7000`. |
| `proxy_bind_addr` | `string` | `""` | `proxyBindAddr` | Separate bind address for proxy listener ports. Empty means same as the **effective** `bind_addr`: the inheritance runs inside the completion, i.e. after the CLI flags are applied, so `--bind-addr 0.0.0.0` also moves the proxy ports to every interface (and a narrower `--bind-addr` narrows them); an empty `bind_addr` yields `0.0.0.0`, not `""`. Set this key explicitly to pin the proxy plane independently — an explicit value is used verbatim. |
| `vhost_http_port` | `u16` | `0` | `vhostHTTPPort` | HTTP virtual host routing port. 0 = disabled. When set, HTTP proxies can be routed by `Host` header without consuming individual ports. |
| `vhost_https_port` | `u16` | `0` | `vhostHTTPSPort` | HTTPS virtual host routing port. 0 = disabled. Routes by TLS SNI. |
| `tcpmux_httpconnect_port` | `u16` | `0` | `tcpmuxHTTPConnectPort` | TCPMux HTTP CONNECT multiplexing port. TCPMux proxies share this port, routed by HTTP CONNECT `Host` header. 0 = disabled. |
| `kcp_bind_port` | `u16` | `0` | `kcpBindPort` | KCP transport listener port. 0 = disabled. Requires `kcp` feature. |
| `quic_bind_port` | `u16` | `0` | `quicBindPort` | QUIC transport listener port. 0 = disabled. Requires `quic` feature. |
| `websocket_port` | `u16` | `0` | `websocketPort` | WebSocket transport listener port. 0 = disabled. Requires `websocket` feature. |
| `sudp_port` | `u16` | `0` | `sudpPort` | Shared UDP port for all SUDP proxies. When > 0, SUDP proxies share this port instead of allocating individual ports. |
| `sub_domain_host` | `string` | `""` | `subDomainHost` | Base domain for sub-domain proxy routing (e.g. `"example.com"`). A proxy with `subdomain = "web"` will be reachable at `web.example.com`. |
| `tls_enable` | `bool` | `false` | `—` (no Go server field; Go's `TLS.Enable` is client-only, `transport.tls.enable`) | Declared by frp-rs's own `ServerConfig` for historical reasons: it has no counterpart in Go v0.71.0's server config at all, and the one place frp-rs's own code sets it from a Go-shaped input is the `[transport.tls]` flatten, which inserts it as `true` when that section carries `force = true`, `certFile` or `keyFile` (`frp-core/src/config/normalize.rs:798-816`) — but **read by nothing** on the server: the field is inert, so the reload neither applies it nor names it as restart-required, and a restart cannot make it take effect. The real server switch is `tls_only` below (Go's server-side `TLS.Force`); the acceptor uses `tls_cert_file` / `tls_key_file`, and with neither set the server auto-generates a self-signed pair. A load that **writes** it (flat, under `[common]`, or as a literal `tls_enable` inside `[transport.tls]`) is no longer silent: it emits one warning per load at each server load site that has a log sink (`tls_enable has no effect on the server: …`) — see the inert-fields note below. |
| `tls_only` | `bool` | `false` | `transport.tls.force` | When true, the main `bind_port` only accepts TLS connections. Plain TCP and WebSocket upgrades are rejected. Clients must also have `tls_enable = true`. |
| `tls_cert_file` | `string` | `""` | `transport.tls.certFile` | Path to TLS certificate PEM file. |
| `tls_key_file` | `string` | `""` | `transport.tls.keyFile` | Path to TLS private key PEM file. |
| `tls_ca_file` | `string` | `""` | `transport.tls.trustedCaFile` | Path to CA certificate PEM file for mutual TLS client verification. Empty = no mTLS. Also accepted flat as `tls_trusted_ca_file` (the Go legacy spelling frp-rs renames at load). |
| `allow_port_start` | `u16` | `1` | `allowPorts` (start) | Start of auto-assigned port range. Used when `allow_ports` is empty. |
| `allow_port_end` | `u16` | `65535` | `allowPorts` (end) | End of auto-assigned port range (inclusive). Used when `allow_ports` is empty. |
| `allow_ports` | `string` | `""` | `allowPorts` | Comma-separated port ranges, e.g. `"10000-20000,30000-40000"`. Each range is inclusive on both ends. When non-empty, takes precedence over `allow_port_start`/`allow_port_end`. |
| `max_ports_per_client` | `u64` | `0` | `maxPortsPerClient` | Maximum number of proxies a single client can register. 0 = unlimited. **Restart-only** (not reloadable). |
| `max_conns_per_proxy` | `u64` | `0` | `maxConnsPerProxy` | Maximum concurrent connections per proxy. 0 = unlimited. **Restart-only**. |
| `max_proxies_per_client` | `u64` | `0` | `maxProxiesPerClient` | Maximum number of proxy registrations per client (distinct from `max_ports_per_client`). 0 = unlimited. **Restart-only**. |
| `vhost_http_timeout` | `u64` | `60` | `vhostHTTPTimeout` | Timeout in seconds for backend HTTP response in VHost handler. |
| `user_conn_timeout` | `u64` | `10` | `userConnTimeout` | Idle timeout in seconds on user-facing proxy connections. |
| `detailed_errors_to_client` | `bool` | `true` | `detailedErrorsToClient` | When true (default), full Rust error details are included in client-facing error responses. When false, internal errors are replaced with generic messages. |
| `tcp_mux_passthrough` | `bool` | `false` | `tcpMuxPassthrough` | When `tcp_mux` is enabled and yamux init fails, forward raw bytes to the VHost handler instead of closing the connection. |
| `udp_packet_size` | `usize` | `1500` | `udpPacketSize` | UDP packet buffer size in bytes. Controls the receive buffer for UDP proxy datagrams. Clamped to **[0, 65507]** at load (hostile values rejected — a 2^31 value would otherwise allocate multi-GiB UDP buffers). |
| `nat_hole_analysis_data_reserve_hours` | `u64` | `168` | `natholeAnalysisDataReserveHours` | How long historical NAT behavior records are kept (in hours). Used by XTCP NAT analysis. |
| `includes` | `string[]` | `[]` | `includes` | Glob patterns for additional config files to merge (`.toml`, `.ini`, `.json`, `.yaml`, `.yml`). Relative to the main config file directory. |

### `[auth]` Section

Authentication configuration for control connections.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `method` | `string` | `"token"` | `auth.method` | Authentication method: exactly `"token"` or `"oidc"`. An empty value completes to `"token"` (Go's `Auth.Complete()`); any other spelling is a **config-load error** with Go's text (`invalid auth method, optional values are [token oidc]`) on stdout and exit 1 — no lower-casing, no trimming. |
| `token` | `string` | `""` | `auth.token` | Shared secret token for MD5-based authentication. Must match the client's token. |
| `token_source` | `table` | `null` | `auth.tokenSource` | Dynamic token source. Mutually exclusive with `token`. |
| `oidc_issuer` | `string` | `""` | `auth.oidcIssuer` | OIDC issuer URL. Used when `method = "oidc"`. |
| `oidc_audience` | `string` | `""` | `auth.oidcAudience` | OIDC expected audience claim. |
| `oidc_token_endpoint` | `string` | `""` | `auth.oidcTokenEndpoint` | OIDC token verification endpoint URL. |
| `oidc_skip_expiry` | `bool` | `false` | `auth.oidcSkipExpiry` | Skip OIDC token expiry validation. For development only. |
| `oidc_skip_issuer` | `bool` | `false` | `auth.oidcSkipIssuer` | Skip OIDC issuer validation. For development only. |
| `oidc_skip_audience` | `bool` | `false` | `auth.oidcSkipAudience` | Skip OIDC audience (`"aud"` claim) validation entirely. When true, any validly-signed JWT is accepted regardless of audience. For development only. |
| `oidc_additional_audience` | `string[]` | `[]` | `auth.oidcAdditionalAudience` | Additional accepted audiences. A token is accepted when its `"aud"` claim matches `oidc_audience` OR any entry of this list (union). |
| `oidc_tls_trusted_ca_file` | `string` | `""` | `auth.oidcTLSTrustedCAFile` | Path to a custom CA certificate PEM file used to verify the OIDC provider's TLS certificate (openid-configuration / JWKS fetches). Extends the default root store with the file's certificates. |
| `oidc_proxy_url` | `string` | `""` | `auth.oidcProxyURL` | HTTP/SOCKS5 proxy URL for OIDC provider HTTP requests. |
| `oidc_skip_nbf` | `bool` | `false` | `auth.oidcSkipNbf` | Skip the `"nbf"` (not-before) claim validation. For development only. |
| `authentication_timeout` | `i64` | `90` | `auth.authenticationTimeout` | Login timestamp freshness window in seconds (replay protection; `0` = disabled, Go frp default). |
| `token_auth_timeout` | `bool` | `true` | `auth.tokenAuthTimeout` | Apply the freshness window to token (MD5) auth logins. |
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
| `level` | `string` | `"info"` | `log.level` | Log level: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. Also controllable via `RUST_LOG` env var, which outranks both this value and `--log-level`. An **empty `level` in the file** is completed to `"info"` after parsing, as Go's `LogConfig.Complete()` does (`pkg/config/v1/common.go:121`) — empty is Go's `util.EmptyOr` zero value, not "silence". An **empty `--log-level ""` flag** is treated as "not supplied" and falls through to the effective config level; when the file sets a non-default level the two binaries differ there, because only `frps` overlays its CLI flags onto the loaded config (the empty flag is written into `[log] level` and then completed to `"info"`), while `frpc` keeps the file's value. Measured with `[log] level = "warn"` plus `--log-level ""`: `frps` logs at `info` (1498 raw bytes / 7 `INFO` records, listener up); `frpc` honours `warn` — **0 `INFO` records in every shape measured**, with the record composition depending on the client's `login_fail_exit` (default `true`) and on whether a server is live: live server 478 B / 1 `WARN`; no server with `login_fail_exit = false` 624 B / 2 `WARN`; no server with the default `login_fail_exit = true` 569 B / 1 `WARN` + 1 `ERROR` (raw-stream bytes; each identical with and without `--log-level ""`). With no `[log] level` in the file both resolve to `"info"`. Note that on Go this flag **does not exist on the client's run path at all** — `--log_level` is registered only for the `frpc <type>` subcommands (`pkg/config/flags.go:161-163`, reached from `cmd/frpc/sub/proxy.go:56`) and in SSH mode (`pkg/ssh/server.go:285`), so Go's `frpc` rejects it: measured `Error: unknown flag: --log_level`, rc 1, 1343 B stderr, with and without `-c`. Recorded as a known divergence in `TODO.md`, not changed here. |
| `file` | `string` | `"console"` | `log.to` | Log output target: `"console"` (default, stdout) or a file path. Uses daily rotation for file output. An **empty** `file`/`to` (in the file, or `--log-file ""`) is completed to `"console"` after parsing (Go's `LogConfig.Complete()`, `pkg/config/v1/common.go:120`), so an empty path means stdout rather than a rotation file named after the empty path. |
| `max_days` | `i32` | `3` | `log.maxDays` | Maximum days to retain rotated log files. Rotated files whose mtime is strictly older than `max_days` days are deleted. frp-rs cleans up at startup and then once a day; **Go cleans up only at the midnight rotation** (`golib@v0.8.2/log/output_rotatefile.go:103` — `clearFiles()` is called only from `rotate()`, which `dailyRotate` reaches only at the 0:00 boundary, `:193-194`), so on Go a retention change is not observable at startup at all. `max_days <= 0` disables cleanup entirely on both (`:242-244`). An **explicit `0`** is Go's zero value and is completed to `3` (`pkg/config/v1/common.go:122`); negative values pass through and keep cleanup disabled. |
| `format` | `string` | `"text"` | — | Log output format: `"text"` or `"json"`. Any other value falls back to `"text"` with a warning. Also controllable via the `--log-format` CLI flag (CLI wins over the config file). This field is an **frp-rs extension**: Go v0.71.0 has no `log.format` key and rejects `--log-format` with `unknown flag`, so there is no Go completion to mirror — an empty `format` is resolved to `"text"` by `resolve_log_format`, not completed in the config. |

### `[web_server]` Section

Dashboard and metrics HTTP server. `[webServer]` is the same section as
`[web_server]`; a file may write both, and they are merged **per key** with
`[web_server]` winning every key both define (the camelCase section is no longer
discarded whole).

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `addr` | `string` | `"127.0.0.1"` | `webServer.addr` | Dashboard bind address. An empty string is completed to `127.0.0.1` (Go's `WebServer.Complete()`); write `"0.0.0.0"` to bind every interface. |
| `port` | `u16` | `0` | `webServer.port` | Dashboard port. 0 = disabled. |
| `user` | `string` | `""` | `webServer.user` | Basic Auth username for dashboard and management API. |
| `password` | `string` | `""` | `webServer.password` | Basic Auth password for dashboard and management API. |
| `enable_prometheus` | `bool` | `false` | `webServer.enablePrometheus` | Expose `/metrics` endpoint in Prometheus text format. |
| `tls_cert_file` | `string` | `""` | `webServer.tlsCertFile` | TLS certificate for dashboard HTTPS. When both `tls_cert_file` and `tls_key_file` are non-empty, dashboard serves HTTPS. Four spellings reach this one field, and the first **non-empty** one wins: nested `[web_server.tls] cert_file`, nested `certFile` (`[webServer.tls]` is the same table), the parent-level `tls_cert_file`, then the parent-level alias `certFile`. An explicitly **empty** nested value means *unset* and falls through to the flat value — it does not clear it. `.ini` supports the nested section too (`[webServer.tls]`, `[web_server.tls]`), and the whole file may write both `[webServer]` and `[web_server]` (merged per key, `[web_server]` winning each shared key). |
| `tls_key_file` | `string` | `""` | `webServer.tlsKeyFile` | TLS private key for dashboard HTTPS. Same nested spellings, precedence and empty-value rule as `tls_cert_file`. |
| `custom_404_page` | `string` | `""` | `webServer.custom404Page` | Custom HTML body for 404 responses from VHost and TCPMux handlers. Content-Type is set to `text/html`. |
| `assets_dir` | `string` | `""` | `webServer.assetsDir` | Directory containing a custom dashboard `index.html`; read once at startup (empty = built-in page). |
| `pprof_enable` | `bool` | `false` | `webServer.pprofEnable` | Serve `/debug/pprof/*` placeholder routes (frp-rs does not expose Go-style pprof profiles). |

### `[transport]` Section

Transport-level settings for the server.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `tcp_mux` | `bool` | `true` | `transport.tcpMux` | Enable TCP multiplexing (yamux) for work connections. When enabled, all proxies share a single TCP connection. |
| `tcp_mux_keepalive_interval` | `i64` | `30` | `transport.tcpMuxKeepaliveInterval` | Keepalive interval in seconds for mux connections. Serde default is `0`; a zero value is normalized to the 30s default at load time. |
| `tcp_mux_keepalive_timeout` | `i64` | `0` | — (frp-rs extension) | Dead-session reaper silence bound in seconds. `0` = auto (`3 × keepalive`, floored 30s); `>0` = explicit bound (floored 30s); `<0` = disable the reaper (never close on idle). Not reloadable. |
| `heartbeat_timeout` | `i64` | `90` | `transport.heartbeatTimeout` | Heartbeat timeout in seconds. Server disconnects the client if no `Ping` received within this interval. When `tcp_mux` is enabled (the default), this is normalized to `-1` (disabled — yamux keepalive covers liveness). |
| `tcp_keepalive` | `i64` | `7200` | `transport.tcpKeepalive` | TCP keepalive idle time in seconds for server-side accepted connections. 0 = disabled. Probe interval and retries are also set so dead peers are reclaimed quickly. |

### `[ssh_tunnel_gateway]` Section

SSH tunnel gateway. When `bind_port > 0`, an embedded SSH server accepts SSH
proxy-registration commands. Reverse forwarding (`ssh -R`, `tcpip-forward` /
`forwarded-tcpip`) is supported since the 0.70.1-era parity pass (PR #221,
2026-08-02; Go semantics: the
port is recorded, not bound; a `forwarded-tcpip` channel is opened when a work
connection is requested).

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bind_port` | `u16` | `0` | `sshTunnelGateway.bindPort` | SSH listen port. 0 = disabled. |
| `bind_addr` | `string` | `"0.0.0.0"` | `sshTunnelGateway.bindAddr` | SSH listen address. |
| `private_key_file` | `string` | `""` | `sshTunnelGateway.privateKeyFile` | Path to SSH host private key file. Auto-generated if empty and `auto_gen_private_key_path` does not exist. |
| `auto_gen_private_key_path` | `string` | `"./.autogen_ssh_key"` | `sshTunnelGateway.autoGenPrivateKeyPath` | Path where auto-generated SSH host key is written. |
| `authorized_keys_file` | `string` | `""` | `sshTunnelGateway.authorizedKeysFile` | Path to SSH `authorized_keys` for optional public key auth. Empty = password auth only. |
| `ssh_session_idle_timeout` | `u64` | `0` | — (frp-rs extension) | Authenticated-session idle timeout in seconds. 0 = disabled (Go frp parity). When enabled, an idle authenticated session is disconnected so it cannot hold a connection slot forever. |

> **About `.autogen_ssh_key`:** the default `auto_gen_private_key_path` is
> **relative to the working directory**, so running `frps` from the repository
> root creates a real Ed25519 host private key at `./.autogen_ssh_key`. It is a
> throwaway key for that local run — it authenticates nothing outside your
> machine — but it must never be committed. The repo's `.gitignore` already
> covers it. Point `auto_gen_private_key_path` at a path outside the repo if you
> would rather it never appear here.

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
- Exception: `tls_enable`, `tls_only`, `tls_cert_file`, `tls_key_file` and `tls_ca_file` have no camelCase aliases — use the snake_case names. The four Go-shaped TLS fields (`tls_only`, `tls_cert_file`, `tls_key_file`, `tls_ca_file`) are carried by the nested `[transport.tls]` section instead (`force` / `certFile` / `keyFile` / `trustedCaFile`, `frp-core/src/config/normalize.rs:798-816`). Two further flat aliases do work, one snake_case and one camelCase: `tls_trusted_ca_file` (→ `tls_ca_file`) and `tlsServerName` (→ `tls_server_name`) (`frp-core/src/config/server.rs:48-51`); both loading paths are pinned by `test_flat_camelcase_tls_spellings_are_not_loader_spellings` in `frp-core/src/config/tests.rs`.

### Server Config Reload (SIGUSR1)

Send `SIGUSR1` to the frps process to hot-reload these settings from the config file:

| Setting | Effect |
|---------|--------|
| `auth.token` / `auth.tokenSource` | Updates the live credential and the bridge encryption key derived from it; new logins use it. Existing connections are unaffected. |
| `auth.additionalAuthScopes` | Changes which message types require authentication (`HeartBeats`, `NewWorkConns`). |
| `auth.authenticationTimeout` / `auth.tokenAuthTimeout` | Changes the login timestamp window and the replay-table prune (read from the live auth config on every login). |
| `allow_ports` / `allow_port_start` / `allow_port_end` | Adjusts port allocation range. Already-allocated ports are not released. |
| TLS certificate/key/CA file paths | Rebuilds the TLS acceptor and swaps it atomically. Existing connections keep the old config; new connections pick up the new cert immediately. (A background task also re-stats the cert/key files every 60s, so in-place rotation — e.g. certbot — is picked up even without a reload.) |

Settings that require a full restart: `bind_port`, `bind_addr`, `auth.method`, the OIDC settings (`oidc_issuer`, `oidc_audience`, the skips, `oidcAdditionalAudience`, `oidcTLSTrustedCAFile`, `oidcProxyURL`, `oidcTokenEndpointURL` — the OIDC verifier is built once at startup), the whole `[log]` section (read once in `init_logging`, before the reload path exists), everything under `[transport]` (the heartbeat timeout, `tcp_mux` and its keepalive/dead-timeout knobs, `max_pool_count`, `tcp_keepalive`, the socket buffers, the QUIC options), `sub_domain_host`, `proxy_bind_addr`, the listener ports (`vhost_http_port`, `vhost_https_port`, `tcpmux_httpconnect_port`, `kcp_bind_port`, `quic_bind_port`, `websocket_port`, `sudp_port`), `vhost_http_timeout`, `user_conn_timeout`, `udp_packet_size`, `detailed_errors_to_client`, `graceful_shutdown_timeout`, `tcp_mux_passthrough`, `nat_hole_analysis_data_reserve_hours`, `http_plugins`, `[web_server]`, `[ssh_tunnel_gateway]`, `[observability]`, `tls_only`, `max_custom_domains_per_proxy`, the two limits `max_connections` / `max_accept_rate`, and the per-client/proxy registration caps `max_ports_per_client`, `max_conns_per_proxy`, `max_proxies_per_client` (they gate live registrations via semaphores/maps, so a reload cannot retroactively rescale them).

Eight parsed fields are in a third position — a restart cannot make them take effect either, because **no code reads them**, so the reload does not mention them as restart-required: `tls_enable` (Go's own server config has no such field — the server's switch is `tls_only`), `auth.useEncryption` (Go's own server auth struct has no such field), `tls_server_name` (a *client* field in Go), `web_server.pprof_enable`, `web_server.tls_ca_file`, `web_server.tls_server_name`, the nested `web_server.tls.enable`, and `[featureGates]` (validated when the file is loaded, read by nothing at runtime). `tls_enable` and `web_server.tls.enable` are the two of the eight that are accepted **and warned about**. For the nested key: nothing reads it, because the dashboard TLS is driven by a non-empty `cert_file` + `key_file` pair, and Go does not have the key at all — its `TLSConfig` carries only `certFile`/`keyFile`/`trustedCaFile`/`serverName` and its strict decoder refuses `enable` (`json: unknown field "enable"`), so frp-rs accepting it is a deliberate divergence. A load that contains the key emits one record — `web_server.tls.enable has no effect: the dashboard HTTPS server is enabled by a non-empty cert_file + key_file pair; without that pair the dashboard serves plaintext HTTP` — at **every load site that has a log sink**: the two startup paths, `frpc verify`, the `frps`/`frpc` SIGUSR1 reload, and the `frpc` admin API's config **GET** — which is polled, so it emits once per **state change** rather than once per request (`frp_client::admin::config_from_file` keeps the last answer it saw on `AdminState`). The loader itself stays silent (on `-c` it runs *before* `init_logging`, so a `tracing::warn` there reached no subscriber); the fact is carried out of the loader on a presence flag and each site emits it, once per load. The flat `tls_enable` warning added here is the server-side counterpart: same mechanism (`ConfigPresence::server_tls_enable_set_in` / `warn_inert_server_tls_enable`), a distinct message, and **three** sites — the two `frps` startup paths and the `frps` SIGUSR1 reload — never in `frpc`/`frp-client`, whose `tls_enable` is live (`frp-client/src/control.rs` reads it), and never in `frps verify`, which installs no subscriber. It fires for a written flat `tls_enable`, one under `[common]`, or a literal `tls_enable` inside `[transport.tls]` (the lift passes unknown keys through), but not for the `tls_enable = true` synthesized from `force` / `certFile` / `keyFile`. The nested section is recognised in its top-level and in its `[common]`-flattened spelling, in either key case — `[web_server.tls]`, `[webServer.tls]`, `[common.web_server.tls]`, `[common.webServer.tls]`, the inline `common = { … }` form, and the same shape in an `includes` file. Measured with stdout and stderr captured separately, occurrence counts (`/tmp/enable-warn-probe/run-probe2.sh`): `frps -c` 1, `frps --config-dir` 1, `frpc -c` 1, `frpc --config-dir` 1; the `[common.web_server.tls]` spelling 1 on each of those four; a `frps -c` SIGUSR1 reload +1 on top of the startup record; and 0 for a config without the key — every one on **stdout** with 0 on stderr. The record is presence-driven, not pair-driven: it fires whenever `enable` is written, so `enable = false` beside a valid pair — where TLS stays **on** against the written value — is not silenced. The `-c` load-before-`init_logging` ordering is unchanged (Go parity); only the emission moved. **Two shapes deliberately get no record**, and the claims above are bounded by them: `frps verify` (its logging is never initialised, which is what keeps its one-line output), and the `[common]` spelling when a top-level `[web_server]`/`[webServer]` is present too (the `[common]` flatten is `or_insert` on the whole value, so the top-level section discards `common.web_server` whole; the detector mirrors that rather than reporting a key the loader dropped). The admin **PUT** emits too: it validates through the string loader (silent) and then triggers the service reload, which emits once per request (measured before the GET was fixed: 3 GETs → +0, 3 PUTs → +3, `/tmp/enable-warn-probe/run-admin-probe.sh`; the GET now emits once per state change, pinned by `frp-client/src/admin.rs`'s `admin_config_get_warns_once_per_state_change`). `frpc verify` emits the same single record it did when the loader warned, because that subcommand installs its console logger before the load, and other library callers of `load_*_config_from_str` see nothing. The nested section has no other fields to report separately: the loader's `normalize_web_server_section` removes the `web_server.tls` table's **mapped** keys before deserialization (only a genuinely unmapped key keeps the table alive, so `check_strict` can report it at its true path, `web_server.tls.<key>`) and maps **all four** spellings of its four value keys — Go's `certFile` / `keyFile` / `trustedCaFile` / `serverName` and the canonical `cert_file` / `key_file` / `trusted_ca_file` / `server_name` — onto the flat `web_server.tls_cert_file` / `tls_key_file` / `tls_ca_file` / `tls_server_name` fields, where the nested value wins over a flat key **in the same section**, in either key order — and an explicitly **empty** nested value is *unset* and falls through to the flat/alias value rather than clearing it (`[web_server.tls] cert_file = ""` beside `[web_server] certFile = "/p.pem"` loads with `tls_cert() == "/p.pem"`) (measured in the change report's before/after table: `[webServer.tls] cert_file = "/c.pem"` loads in either loader mode as `web_server.tls_cert_file = "/c.pem"`, with the nested struct at its default), so the flat entries are what report it. Two shapes that used to limit that mapping are now handled: a file that defines **both** `[webServer]` and `[web_server]` has the two sections merged per key (`[web_server]` winning each shared key), and **`.ini` reaches the mapping too** — the INI reader expands a dotted header whose first segment is a v1 section name (`[webServer.tls]`, `[web_server.tls]`) into nested tables, while legacy `[plugin.NAME]` sections stay flat. `includes` is not reported either, for a third reason: the reload's own config load resolves it, so a change that alters what is loaded shows up as the loaded fields changing, and one that does not is a genuine no-op.

A changed restart-only setting is never silently dropped. The reload **reports** each one it cannot apply in its summary as `name: old -> new (restart required)` (`auth.method: token -> oidc (restart required)`, `transport.heartbeat_timeout: 30 -> 60 (restart required)`, `log.level: info -> debug (restart required)`, …), and **applies** the settings it can re-key in place, naming those too (`auth.authenticationTimeout: 90 -> 7`, `allow_ports: … -> …`). A file that matches the running config still reports `config reloaded: no changes detected`, and the comparison is always against the **running** config, which a reload never updates — so a restart-only difference is reported again on every reload until the process restarts. The classified field list is a compiler-enforced destructure of `ServerConfig` (`frp-core/src/config/restart_only.rs`, the counterpart of the `[auth]` list in `frp-server/src/service.rs`): adding a field to `ServerConfig` — or to `[log]`, `[transport]`, `[web_server]` (and its nested `tls` section), `[ssh_tunnel_gateway]`, `[observability]` or `[featureGates]` — is a compile error until it is named and classified. Two deliberate limits: a field whose only reader is behind a feature is reported only in builds that compile that reader (`web_server.*` beyond `custom_404_page` without `dashboard`, `[ssh_tunnel_gateway]` without `ssh`, the QUIC options without `quic`, `[observability]` without `otel`, and the three gated listener ports `kcp_bind_port` / `quic_bind_port` / `websocket_port` without their own `frp-server` listener. The dashboard is **not** a second reader for any of them: `frp-server/src/dashboard.rs`'s own `#[cfg(feature = "kcp")]` / `cfg(feature = "quic")` are `frp-server`'s features, so it prints `kcpBindPort` / `quicBindPort` only in a build that already has the listener compiled (measured: a dashboard-only build's `/api/v2/system/info` has neither key; the same build with `kcp,quic` added has both); and values are compared as the loader left them, so an absent key and its default are not a change (`udp_packet_size = 0` is read as `1500`, and an absent `max_connections` / `max_accept_rate` is the 512-permit semaphore / no rate limit, so `max_connections = 512` and `max_accept_rate = 0` are the same settings as an absent key — while `max_connections = 0` is *unlimited*, a different setting, and is reported). Credential-shaped fields are named without their values: `web_server.password`, and `http_plugins`, whose `addr` may carry `user:pass@`.

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
oidc_skip_audience = false
oidc_additional_audience = []
oidc_tls_trusted_ca_file = ""
oidc_proxy_url = ""
additional_auth_scopes = []

[log]
level = "info"
file = "/var/log/frps.log"
max_days = 3
format = "text"

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
| `server_addr` | `string` | `"0.0.0.0"` | `serverAddr` | Server address (IP or hostname). Defaults to `0.0.0.0` (Go frp parity, client.go:86 — only useful with an explicit `server_port`). |
| `server_port` | `u16` | `7000` | `serverPort` | Server control port. |
| `transport_protocol` | `string` | `"tcp"` | `protocol` | Transport protocol: `"tcp"`, `"websocket"` / `"ws"`, `"wss"`, `"quic"`, `"kcp"`. |
| `token` | `string` | `""` | `auth.token` | Authentication token. Must match the server's token. This is a convenience field; for full auth config use `[auth]` section. |
| `user` | `string` | `""` | `user` | User identity string for multi-tenant setups. Sent in the Login message. |
| `client_id` | `string` | `""` | `clientId` | Unique client identifier. When empty, no ID is sent — Login sends `None` (not auto-generated). |
| `metas` | `map<string,string>` | `{}` | `metadatas` | Client-level metadata key-value pairs sent in the Login message. Available to server plugins. |
| `proxy_url` | `string` | `""` | `transport.proxyURL` | Upstream HTTP/SOCKS5 proxy for the client-to-server control connection. Supports `http://` and `socks5://` schemes. Empty = direct connection. |
| `nat_hole_stun_server` | `string` | `"stun.easyvoip.com:3478"` | `natHoleStunServer` | Custom STUN server address for NAT traversal. Format: `"stun:host:port"`. |
| `start` | `string[]` | `[]` | `start` | Selective proxy start list. If non-empty, only proxies with names in this list are started. Empty = start all proxies. |
| `includes` | `string[]` | `[]` | `includes` | Glob patterns for additional config files to merge (`.toml`, `.ini`, `.json`, `.yaml`, `.yml`). Relative to the main config file directory. |
| `tls_enable` | `bool` | `true` | `transport.tls.enable` | Enable TLS for the connection to the server. |
| `tls_cert_file` | `string` | `""` | `transport.tls.certFile` | Client TLS certificate PEM file (for mTLS). |
| `tls_key_file` | `string` | `""` | `transport.tls.keyFile` | Client TLS private key PEM file (for mTLS). |
| `tls_ca_file` | `string` | `""` | `transport.tls.trustedCaFile` | CA certificate PEM file for verifying the server's TLS certificate. |
| `tls_server_name` | `string` | `""` | `tlsServerName` | Server name for TLS SNI. Empty = use `server_addr`. |
| `disable_custom_tls_first_byte` | `bool` | `true` | `disableCustomTLSFirstByte` | When true, the client skips the Go frp protocol marker byte (`0x17`) and starts TLS directly. Set this when connecting to a non-frp TLS endpoint. |
| `login_fail_exit` | `bool` | `true` | `loginFailExit` | When true, the client exits on login failure. When false, it keeps retrying. |
| `pool_count` | `i32` | `1` | `poolCount` | Number of pre-established work connections kept in the server-side pool. Higher values reduce latency for new proxy connections. Negative values are rejected at config load (fail-fast divergence — Go frp has no client-side check and the server rejects at login instead). |
| `heartbeat_interval` | `i64` | `30` | `transport.heartbeatInterval` | Ping interval in seconds. Client sends a heartbeat `Ping` at this interval. When `tcp_mux` is enabled (the default), this is normalized to `-1` (disabled — yamux keepalive covers liveness). |
| `dns_server` | `string` | `""` | `dnsServer` | Custom DNS server address for resolving `server_addr`. Empty = system DNS. Queries `A` and `AAAA` records concurrently, preferring IPv4 (an `A` answer wins even when `AAAA` also succeeds); falls back to IPv6 when only `AAAA` resolves. |
| `dial_server_keepalive` | `i64` | `7200` | `dialServerKeepalive` | TCP keepalive idle time in seconds for outbound connections to the server. 0 = use the 7200s default (Go parity — not a disable switch). |
| `connect_server_local_ip` | `string` | `""` | `connectServerLocalIP` | Local IP address to bind when dialing the frp server. Empty = system default. |
| `tcp_mux` | `bool` | `true` | `transport.tcpMux` | Enable TCP multiplexing (yamux) for work connections. |
| `tcp_mux_keepalive_timeout` | `i64` | `0` | — (frp-rs extension) | Dead-session reaper silence bound in seconds. `0` = auto (`3 × keepalive`, floored 30s); `>0` = explicit bound (floored 30s); `<0` = disable the reaper (never close on idle). Not reloadable. |
| `v2` | `bool` | `false` | `transport.wireProtocol = "v2"` | Enable V2 wire protocol framing. Requires `tcp_mux` for yamux multiplexing. |

### `[auth]` Section (Client)

Full OIDC authentication configuration. When `method = "oidc"`, the client obtains a JWT from the OIDC provider and sends it as the login token.

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `method` | `string` | `"token"` | `auth.method` | Authentication method: exactly `"token"` or `"oidc"`. An empty value completes to `"token"` (Go's `Auth.Complete()`); any other spelling is a **config-load error** with Go's text (`invalid auth method, optional values are [token oidc]`) on stdout and exit 1 — no lower-casing, no trimming. |
| `token` | `string` | `""` | `auth.token` | Shared secret token (when `method = "token"`). |
| `token_source` | `table` | `null` | `auth.tokenSource` | Dynamic token source. Mutually exclusive with `token`. |
| `oidc_client_id` | `string` | `""` | `auth.oidcClientId` | OIDC client ID for the token endpoint. |
| `oidc_client_secret` | `string` | `""` | `auth.oidcClientSecret` | OIDC client secret for the token endpoint. |
| `oidc_audience` | `string` | `""` | `auth.oidcAudience` | OIDC audience claim to request. |
| `oidc_token_endpoint` | `string` | `""` | `auth.oidcTokenEndpoint` | OIDC token endpoint URL. |
| `oidc_scope` | `string` | `""` | `auth.oidcScope` | OIDC scope string (e.g. `"openid profile"`). |
| `oidc_issuer` | `string` | `""` | `auth.oidcIssuer` | OIDC issuer URL. |
| `additional_endpoint_params` | `table` | `{}` | `auth.additionalEndpointParams` | Extra key/value parameters appended to the token endpoint request (map). |
| `oidc_token_source` | `table` | `null` | `auth.oidcTokenSource` | Dynamic OIDC token source (`type = "file"`/`"exec"`), same shape as `tokenSource`. |
| `authentication_timeout` | `i64` | `90` | `auth.authenticationTimeout` | Login timestamp freshness window in seconds (replay protection; `0` = disabled, Go frp default). |
| `oidc_tls_trusted_ca_file` | `string` | `""` | `auth.tlsTrustedCaFile` | Custom CA certificate PEM file for OIDC provider TLS verification. |
| `oidc_tls_insecure_skip_verify` | `bool` | `false` | `auth.insecureSkipVerify` | Skip TLS certificate verification for OIDC provider. For development only. |
| `oidc_proxy_url` | `string` | `""` | `auth.oidcProxyURL` | HTTP/SOCKS5 proxy URL for OIDC provider HTTP requests. |
| `additional_auth_scopes` | `string[]` | `[]` | `auth.additionalAuthScopes` | Client-side auth scopes. Unioned with the server's scopes. Values: `"HeartBeats"`, `"NewWorkConns"`. |

The client `auth.tokenSource` table has the same shape as the server version: `type = "file"` with `file.path`, or `type = "exec"` with `exec.command`, `exec.args`, and `exec.env`. Exec sources require `--allow-unsafe TokenSourceExec`.

### `[web_server]` Section (Client Admin API)

Admin REST API for the client. Same fields as the server `[web_server]` section — including the `[webServer]` alias (merged per key), the nested `[web_server.tls]` / `[webServer.tls]` spellings and their four-spelling precedence, and the empty-nested-means-unset rule. The nested `[web_server.tls] enable` key is the one exception: it is inert everywhere and warned about on load (see the reload section below).

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `addr` | `string` | `"127.0.0.1"` | `webServer.addr` | Admin API bind address. An empty string is completed to `127.0.0.1` (Go's `WebServer.Complete()`); write `"0.0.0.0"` to bind every interface. |
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
- Exception: `tls_enable`, `tls_cert_file`, `tls_key_file` and `tls_ca_file` have no camelCase aliases — use the snake_case names. Their four Go-shaped spellings are carried by the nested `[transport.tls]` section instead (`enable` / `certFile` / `keyFile` / `trustedCaFile`, `frp-core/src/config/normalize.rs:1358-1373`), which the `[transport]` flatten above first lifts to a top-level `tls` table (`frp-core/src/config/normalize.rs:1310-1331`). The flat aliases `tlsServerName` (→ `tls_server_name`) and `disableCustomTLSFirstByte` (→ `disable_custom_tls_first_byte`) do work and their rows stay (`frp-core/src/config/client.rs:282-288`); both loading paths are pinned by `test_flat_camelcase_client_tls_spellings_are_not_loader_spellings` in `frp-core/src/config/tests.rs`.

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
format = "text"

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
| `type` | `string` | — | **Required.** | Proxy type: `"tcp"`, `"udp"`, `"http"`, `"https"`, `"stcp"`, `"xtcp"`, `"tcpmux"`, `"sudp"`, `"vnet"`. |
| `local_ip` | `string` | `"127.0.0.1"` | `localIp` | Local service IP address. |
| `local_port` | `u16` | `0` | `localPort` | Local service port. |
| `remote_port` | `u16` | `0` | `remotePort` | Remote port to expose on the server. 0 = auto-assign from server's port range. |
| `use_encryption` | `bool` | `false` | `useEncryption` | Encrypt proxy traffic with AES-128-CFB (derived from auth token for TCP/UDP/HTTP; from `sk` for STCP/XTCP). |
| `use_compression` | `bool` | `false` | `useCompression` | Compress proxy traffic with Snappy (applied before encryption). |
| `enabled` | `bool` | `true` | `enabled` | Whether this proxy is active. `false` = skipped at startup. |

### TCP/UDP Proxy Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `bandwidth_limit` | `string` | `""` | `bandwidthLimit` | Bandwidth limit string, e.g. `"1MB"`, `"500KB"`. Only `KB`/`MB` suffixes are accepted (1024-based, case-insensitive); bare numbers, `K`/`M`/`G`, and `GB` are rejected (treated as unlimited). |
| `bandwidth_limit_mode` | `string` | `"client"` | `bandwidthLimitMode` | Bandwidth limit mode: `"client"` (limit client→server), `"server"` (limit server→client), or `"both"` (both directions). |
| `group` | `string` | `""` | `group` | Proxy group name for load balancing. Proxies with the same group name are treated as a pool. |
| `group_key` | `string` | `""` | `groupKey` | Group key for authentication within a proxy group. |
| `health_check_type` | `string` | `""` | `healthCheck.type` (nested) | Health check type: `"tcp"` (connect check) or `"http"` (HTTP GET check). Empty = no health checks. `healthCheckType` is **not** a Go name and is refused in strict mode. |
| `health_check_url` | `string` | `""` | `healthCheck.path` (nested) | URL path for HTTP health checks. Only used when `health_check_type = "http"`. `healthCheckURL` is **not** a Go name and is refused in strict mode. |
| `health_check_http_headers` | `map<string,string>` | `{}` | `healthCheck.httpHeaders` (nested) | Custom HTTP headers sent with health check requests. Alias: `healthCheckHttpHeaders`. `healthCheckHTTPHeaders` is **not** a Go name and is refused in strict mode. |
| `health_check_interval_seconds` | `u64` | `10` | `healthCheck.intervalSeconds` (nested) | Seconds between health checks. `0` = default (10). Explicit values below the old minimum are honored (Go parity — the `.max(10)` floor was removed, health.go:57-64). `healthCheckIntervalS` is **not** a Go name and is refused in strict mode; the legacy-INI spelling `health_check_interval_s` is accepted and wins when both are present. |
| `health_check_timeout_seconds` | `u64` | `3` | `healthCheck.timeoutSeconds` (nested) | Health check connect/read timeout in seconds. `0` = default (3). `healthCheckTimeoutS` is **not** a Go name and is refused in strict mode; the legacy-INI spelling `health_check_timeout_s` is accepted. |
| `health_check_max_failed` | `u32` | `1` | `healthCheck.maxFailed` (nested) | Consecutive failures before marking the proxy unhealthy. `0` = default (1). `healthCheckMaxFailed` is **not** a Go name and is refused in strict mode. |
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
| `virtual_net` | `string` | `""` | — (frp-rs proxy extension) | Virtual network name for proxy isolation. Proxies in different virtual nets cannot reach each other. Empty = default (global) network. Go has no per-proxy field for this: its `virtualNet` is a **top-level client** section (`pkg/config/v1/client.go:66`, frp-rs's top-level `[virtualNet]`/`[virtual_net]`), so the flat per-proxy `virtualNet` is not a Go name. |

### Proxy Metadata and Misc Fields

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `annotations` | `map<string,string>` | `{}` | `annotations` | Arbitrary key-value annotations (e.g. `{ owner = "team-a" }`). |
| `metas` | `map<string,string>` | `{}` | `metas` | Key-value metadata sent to server plugins for this proxy. |
| `proxy_protocol_version` | `string` | `""` | `proxyProtocolVersion` | HAProxy PROXY protocol version: `"v1"`, `"v2"`, or `""` (disabled). When set, the client prepends a PROXY protocol header to each connection to the local service. |

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

Visitors are client-side listeners that accept local connections and tunnel them
through the frps server to a remote STCP/XTCP proxy (or, with `type = "sudp"`, forward UDP
datagrams to a remote SUDP proxy — see [SUDP Visitor](proxies.md#sudp-visitor-frpc)).

| Field | Type | Default | Go frp Equivalent | Description |
|-------|------|---------|-------------------|-------------|
| `name` | `string` | `""` | `name` | **Required.** Visitor name (config load error when empty — Go parity, validation/visitor.go:42-63). |
| `type` | `string` | `""` | `type` | Visitor type: `"stcp"`, `"xtcp"`, or `"sudp"`. |
| `server_name` | `string` | `""` | `serverName` | **Required.** The STCP/XTCP proxy name to connect to (must match the proxy's `name`). |
| `secret_key` | `string` | `""` | `sk` / `secretKey` | **Required.** Shared secret key. Must match the STCP proxy's `sk`. |
| `server_user` | `string` | `""` | `serverUser` | Optional server-side user for auth matching. |
| `bind_addr` | `string` | `"127.0.0.1"` | `bindAddr` | Local address to bind for accepting visitor connections. |
| `bind_port` | `i32` | `0` | `bindPort` | Local port for the visitor listener. `0` = rejected at config load (Go parity — "bind port is required"); `-1` = no-bind mode (no local listener; used by `virtual_net` plugin visitors); positive = start a local listener. |
| `plugin` | `[visitors.plugin]` | — | `plugin` | Optional visitor plugin. `type = "virtual_net"` with `destinationIP` advertises the IP as a vnet host route instead of binding a local listener. |
| `fallback_timeout_ms` | `u64` | `1000` | `fallbackTimeoutMs` | XTCP fallback timeout in milliseconds. After this time without a successful hole punch, fall back to the `fallback_to` visitor (usually STCP). |
| `fallback_to` | `string` | `""` | `fallbackTo` | Fallback visitor name if XTCP hole punch fails. Typically points to an STCP visitor. |
| `disable_assisted_addrs` | `bool` | `false` | `disableAssistedAddrs` | Disable NAT traversal assisted address reporting (STUN-discovered mapped addresses shared between peers during XTCP hole punching). |
| `use_encryption` | `bool` | `false` | `useEncryption` | Encrypt tunnel traffic with AES-128-CFB (key derived from `secret_key`). |
| `use_compression` | `bool` | `false` | `useCompression` | Compress tunnel traffic with Snappy. |
| `protocol` | `string` | `"quic"` | `protocol` | XTCP P2P data-plane protocol: `"quic"` (default — Go frp parity, an empty value normalizes to `"quic"` via `EmptyOr`) or `"kcp"`. The QUIC data plane (Go v0.71.0 `protocol=quic` compat: hole-punched UDP socket handed to quinn, no yamux, self-signed TLS + InsecureSkipVerify) is built in by default (the `quic` feature is default ON). On a build without the feature, `"quic"` fails loudly instead of silently falling back to KCP. |
| `keep_tunnel_open` | `bool` | `false` | `keepTunnelOpen` | When true, the XTCP visitor retries NAT hole punching instead of falling back to STCP after a connection ends. |
| `max_retries_an_hour` | `i32` | `8` | `maxRetriesAnHour` | Maximum XTCP NAT hole punch retries per hour. |
| `min_retry_interval` | `i64` | `90` | `minRetryInterval` | Minimum interval in seconds between XTCP retry attempts. |

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
| `KB` | 1,024 | `"500KB"` | 512,000 |
| `MB` | 1,048,576 | `"10MB"` | 10,485,760 |

Only `KB` and `MB` suffixes are accepted, case-insensitively. Bare numbers
(`"500"`), single-letter suffixes (`"K"`/`"M"`/`"G"`), and `GB` are
rejected. An empty string or `"0"` means no limit.

---

## Port Range Format

The `allow_ports` field accepts a comma-separated list of ranges and single ports:

```
"10000-20000"                  # single range
"10000-20000,30000-40000"      # multiple ranges
"1000-2000,8080,30000-40000"   # mixed ranges and single ports
```

Each range is inclusive on both ends. Inverted ranges (e.g. `"20000-10000"`) are automatically swapped. Invalid port numbers (> 65535) are silently ignored. When `allow_ports` is empty, `allow_port_start` and `allow_port_end` define a single contiguous range. A range string can also be generated inline with the `{{ parseNumberRange ... }}` template function (see [Template Functions](#template-functions)).

---

## Config File Includes

Both server and client support merging additional config files via `includes`:

```toml
includes = ["conf.d/*.toml", "secrets.toml"]
```

- Patterns are relative to the directory containing the main config file.
- Supports a single `*` wildcard per path component.
- Supported extensions: `.toml`, `.ini`, `.json`, `.yaml`, `.yml`. Each file is parsed by its extension and merged through the same pipeline.
- Included files are deep-merged: tables merge recursively, arrays concatenate.
- The main config file's explicit values take precedence over included files.

For directory-based config, use `--config-dir`:

```bash
frps --config-dir /etc/frp/conf.d
```

All `.toml`, `.ini`, `.json`, `.yaml`, and `.yml` files in the directory (recursive) are loaded and merged in sorted order.

### Supported Formats

`frps` and `frpc` detect the config format by file extension. TOML is the default; `.ini`, `.json`, `.yaml`, and `.yml` are also accepted. Every format runs through the same pipeline — Go frp key aliases, `includes`, env expansion, template functions, and strict key checking all apply identically.

YAML is parsed with `serde_yaml_ng`, preserving YAML 1.1 scalar typing (`yes`/`no`/`on`/`off` parse as booleans, unquoted numbers stay numeric). YAML merge keys (`<<`) are supported:

```yaml
# frps.yaml
base: &base
  bind_addr: "0.0.0.0"
  bind_port: 7000

<<: *base
token: "my-token"
```

Non-string mapping keys are converted to their string form (YAML allows them; JSON and TOML do not).

#### Legacy `.ini` values are read by the target field's type

Go's legacy INI loader hands every value to the target field as **text** and
lets the field's Go type decide how to read it (`gopkg.in/ini.v1`'s `MapTo`:
`Key.String()` for a string, `Key.Int64()` for an int, `Key.Strings(",")` for a
slice — `struct.go:154-266`). frp-rs's INI reader infers a TOML type first; that
inference is now **lossless** (a value becomes an integer/float/boolean/array
only when rendering it back reproduces the text the file wrote through *both*
renderers — see the magnitude note below), and `.ini` inputs are deserialized
with the field's type deciding — so a bare numeric or a comma list reaches a
string field as the string Go would give it:

| INI line | target field | value read |
|---|---|---|
| `token = 12345678` | `String` | `"12345678"` |
| `token = 10000000000000000000` | `String` | `"10000000000000000000"` (serde_json would render the float as `1e+19`) |
| `allow_ports = 2000-3000,3001` | `String` | `"2000-3000,3001"` |
| `meta_var1 = 123` | `HashMap<String, String>` value | `"123"` |
| `server_port = 7000` | `u16` | `7000` |
| `log_max_days = 3` | `i64` | `3` |
| `tcp_mux = no` | `bool` | `false` (Go's `ini.v1.parseBool` spellings: `1/t/true/yes/y/on` and `0/f/false/no/n/off`) |
| `custom_domains = a, b` | `Vec<String>` | `["a", "b"]` (Go's `Key.Strings(",")`: split on `,`, trim each element, `\,` is a literal comma, a trailing empty element is dropped) |
| `custom_domains = a\,b` | `Vec<String>` | `["a,b"]` (the escape is Go's, measured) |
| `custom_domains = a.example.com,` | `Vec<String>` | `["a.example.com"]` (Go drops the trailing empty, measured) |
| `authenticate_heartbeats = 1` | `bool` (legacy key) | `true` — Go's `parseBool` set, **`.ini` only** (`pkg/auth/legacy/legacy.go:25,28`) |

Scope and residuals, measured on Go frp v0.71.0:

- Only `.ini` uses this reader. TOML/JSON/YAML keep strict serde typing, where a
  numeric `token` is refused exactly as Go's v1 decoder refuses it. Two
  normalizer passes touch the parsed tree regardless of format and are called out
  here so the scope is exact: the legacy-boolean canonicalization is gated on the
  `.ini` format (so a TOML `authenticate_heartbeats = 1` or `"yes"` stays
  *ignored*, as it always was, while `[common]` `= 1`/`= yes` now adds the
  `HeartBeats`/`NewWorkConns` scope), whereas `ini_port_numbers`' new array arm
  applies to the shape-based legacy `[range:...]` collector in **every** format
  (before it, an array there was dropped with `WARN … invalid local_port`; a
  JSON `"local_port": [6010, "6011-6012"]` now expands).
- `007`, `+5`, `1.50`, `1e3`, `YES`, `1e19` and `10000000000000000000`
  keep their text for a string field (this is what makes `token = 007` the token
  `"007"`, not `"7"`); for an integer/float/bool field the same text is parsed —
  `007` → `7`, `1e3` → `1000.0`. Extreme magnitudes matter because Rust's `f64`
  Display is plain decimal (`10000000000000000000`, `0.0000001`) while
  serde_json's `ryu` rendering is exponential (`1e+19`, `1e-7`); a value whose
  two renderings differ stays text, so a string field never receives a
  re-rendered token or domain.
- A comma list that renders back verbatim stays an **array** and is *not*
  filtered: `custom_domains = a.com,,b.com` → `["a.com", "", "b.com"]`,
  matching Go (measured). A list that has to stay text (a space after the
  comma, an escape, a trailing comma) goes through the text path, where frp-rs's
  pre-existing `filter` drops empty elements: `a.com, ,b.com` →
  `["a.com", "b.com"]` here against Go's `["a.com", "", "b.com"]`. So the
  empty-element divergence is narrower than the text-path filter suggests — only
  a text-path middle empty element differs.
- Go's `Key.Int64()` is `strconv.ParseInt(s, 0, 64)` — **base 0**. frp-rs reads
  base 10, which is a silent *different value* for an octal-looking spelling:
  `server_port = 07000` dials 3584 on Go and 7000 here, `010` is 8 on Go and 10
  here, `0x10` is 16 on Go and refused here, and `08` is not a Go integer at all
  (the field keeps its default 7000 there, while frp-rs reads 8). Pre-existing
  (the inference this replaced also read base 10), recorded rather than fixed:
  matching Go fully would also need its non-strict "swallow the parse error and
  keep the default" behaviour, which a serde field cannot express.
- The `["a", "b"]` array-literal spelling is an frp-rs extension, not Go syntax:
  measured on Go v0.71.0, `custom_domains = ["a.example.com","b.example.com"]`
  reaches frps as `['["a.example.com"', '"b.example.com"]']`. A **string** field
  that is given such a literal receives the comma-joined elements (`a.example.com,b.example.com`)
  where Go would give the bracketed text — a divergence this reader introduces
  only for the frp-rs-only spelling.

---

## Environment Variable Expansion

Every string value in the config is expanded for `${VAR}` references. This runs **after** `includes` are merged (values pulled in from include files are expanded too) and **before** key normalization. The subset mirrors Go frp's Viper-based `os.ExpandEnv`:

- `${VAR}` expands to the value of environment variable `VAR`; an **undefined variable expands to the empty string**.
- `$$` expands to a literal `$` — the escape hatch for writing `${VAR}` literally (a frp-rs extension; Go's `os.ExpandEnv` has no `$$` escape).
- A bare `$VAR` (no braces) is left untouched, so `$` in passwords or shell snippets is safe.
- An unclosed `${` (no closing `}`) is kept verbatim.
- `${VAR:-default}` shell default-value syntax is **not** supported.

```toml
# frpc.toml
server_addr = "${FRP_SERVER_ADDR}"
token = "$${literal-braces-not-expanded}"
```

---

## Template Functions

Configuration values support a minimal Go-style template subset with a single function, `parseNumberRange`. A call has the exact form `{{ parseNumberRange "expr" }}` (optional ASCII whitespace after `{{`, around the function name, and before `}}`) and is expanded in place to a comma-separated, space-free list of numbers:

```toml
allow_ports = '{{ parseNumberRange "1000-2000" }}'
# → "1000,1001,...,2000"
```

- The argument is a comma-separated list of segments; each segment is a single number `N` or an inclusive range `N-M` (step 1, `N <= M`). Surrounding whitespace is trimmed.
- Values are constrained to the port range `0..=65535`.
- Invalid expressions (non-numeric, `N > M`, more than one `-` in a segment, out of range) are kept verbatim with a warning — the config still loads (Go frp instead fails the entire template render).
- No other template syntax (variables, control flow, other functions) is processed; anything that does not match the call form is left verbatim.
- Environment expansion runs first, so `{{ parseNumberRange "${PORT_RANGE}" }}` works.

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
| `oidc` | `oidc_issuer`, `oidc_audience`, `oidc_token_endpoint`, `oidc_skip_expiry`, `oidc_skip_issuer`, `oidc_skip_audience`, `oidc_additional_audience`, `oidc_tls_trusted_ca_file`, `oidc_proxy_url` | OIDC token verification not compiled |
| `compression` | `use_compression` (proxy/visitor) | Snappy bridge compression not compiled |
| `chacha20` | V2 cipher fields | XChaCha20-Poly1305 V2 cipher not compiled |
| `ssh` | `[ssh_tunnel_gateway]` section | SSH gateway not compiled |
| `dashboard` | `[web_server]` section | Dashboard HTTP endpoints not compiled |
| `http-proxy` | `type = "http_proxy"` plugin config | Server-side HTTP plugin manager not compiled; the client `http_proxy` plugin compiles unconditionally |
| `vnet` | `[[proxies]]`/`[[visitors]]` `plugin.type = "virtual_net"` + `virtual_net` section fields | L3 VPN / TUN device routing not compiled; `virtual_net` plugin and visitor configs are accepted but the tunnel is never established |

---

### Parse-Only Compatibility Fields

Some Go frp v0.71.0 fields are parsed and validated for source-level
compatibility but are not yet consumed by the frp-rs runtime. They are
accepted so Go frp configs load unchanged; setting them currently has no
runtime effect: `log.disablePrintColor`, and `webServer.pprofEnable`
(served as placeholder routes only).

---

## Environment Variables

Log level can be overridden at runtime via `RUST_LOG` (distinct from the
`${VAR}` config-value expansion described in the Environment Variable
Expansion section above):

```bash
RUST_LOG=debug ./frps -c frps.toml
RUST_LOG=frp_core=trace,frp_server=debug ./frps -c frps.toml
```

Log level resolves in this order (first match wins):

1. **`RUST_LOG`** — overrides everything, and accepts the full
   [`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
   syntax (`RUST_LOG=frp_server=debug,info`).
2. **`log.level` in the config file**, or the `--log-level` CLI flag —
   `trace`, `debug`, `info`, `warn` or `error`.
3. Default: `info`.

Per-connection events (`Bridging user conn…`, `bridge completed`) log at
**`debug`**, not `info` — a busy proxy would otherwise emit a line per
connection into the default output. Enable them with `RUST_LOG=debug` or
`log.level = "debug"`.
