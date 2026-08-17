use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------
// Server Configuration
// ---------------------------------------------------------------

// NOTE: Clone is a deep copy used at config reload boundaries
// (reload.rs snapshots the full ServerConfig). If config size grows
// significantly, consider Arc-wrapping the large sub-structs instead
// of cloning them wholesale on every reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr", alias = "bindAddr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port", alias = "bindPort")]
    pub bind_port: u16,
    #[serde(default, alias = "proxyBindAddr")]
    pub proxy_bind_addr: String,
    #[serde(default, alias = "vhostHTTPPort")]
    pub vhost_http_port: u16,
    #[serde(default, alias = "vhostHTTPSPort")]
    pub vhost_https_port: u16,
    #[serde(default, alias = "kcpBindPort")]
    #[cfg(feature = "kcp")]
    pub kcp_bind_port: u16,
    #[serde(default, alias = "quicBindPort")]
    #[cfg(feature = "quic")]
    pub quic_bind_port: u16,
    /// Shared UDP port for SUDP proxies. When > 0, SUDP proxies
    /// share this port instead of allocating individual ports.
    #[serde(default, alias = "sudpPort")]
    pub sudp_port: u16,
    /// Port for tcpmux HTTP CONNECT multiplexing. When > 0, TCPMux
    /// proxies share this port via HTTP CONNECT Host header routing.
    #[serde(default, alias = "tcpmuxHTTPConnectPort")]
    pub tcpmux_httpconnect_port: u16,
    #[serde(default, alias = "subDomainHost", alias = "subdomain_host")]
    pub sub_domain_host: String,
    #[serde(default, alias = "websocketPort")]
    #[cfg(feature = "websocket")]
    pub websocket_port: u16,
    #[serde(default)]
    pub tls_enable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default, alias = "tls_trusted_ca_file")]
    pub tls_ca_file: String,
    #[serde(default, alias = "tlsServerName")]
    pub tls_server_name: String,
    /// When true, the main bind_port only accepts TLS connections.
    /// Plain TCP and WebSocket upgrades are rejected.
    /// The client must have tls_enable = true to connect.
    #[serde(default)]
    pub tls_only: bool,
    #[serde(default)]
    pub auth: AuthServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default, alias = "webServer")]
    pub web_server: WebServerConfig,
    #[serde(default)]
    pub transport: ServerTransportConfig,
    #[serde(default = "default_allow_port_start")]
    pub allow_port_start: u16,
    #[serde(default = "default_allow_port_end")]
    pub allow_port_end: u16,
    /// Comma-separated port ranges, e.g. "10000-20000,30000-40000".
    /// When set, this takes precedence over allow_port_start/allow_port_end.
    /// Each range is inclusive on both ends.
    #[serde(default)]
    pub allow_ports: String,
    /// Maximum number of proxies a single client can register.
    /// Max ports a single client can occupy. Default 50 to prevent port pool
    /// exhaustion; set to 0 for unlimited. Go frp compat: maxPortsPerClient.
    #[serde(default, alias = "maxPortsPerClient")]
    pub max_ports_per_client: u64,
    /// Maximum concurrent user connections per proxy. 0 = unlimited (Go frp
    /// has no per-proxy cap; default). A flood of user connections to one
    /// proxy would otherwise grow `pending_requests` + fds without bound
    /// (audit D2-2). Go frp compat: no equivalent option.
    /// Clamped to 1,048,576 (2^20) at normalization: larger values are
    /// effectively unlimited but would overflow the `i64` normalized field
    /// (u64::MAX -> -1) and truncate on 32-bit `usize` casts.
    #[serde(default, alias = "maxConnsPerProxy")]
    pub max_conns_per_proxy: u64,
    /// Timeout in seconds for backend HTTP response in VHost handler.
    /// Go frp compat: VhostHTTPTimeout. Default: 60.
    #[serde(default = "default_vhost_http_timeout", alias = "vhostHTTPTimeout")]
    pub vhost_http_timeout: u64,
    /// Idle timeout in seconds on user-facing proxy connections.
    /// Go frp compat: UserConnTimeout. Default: 10.
    #[serde(default = "default_user_conn_timeout", alias = "userConnTimeout")]
    pub user_conn_timeout: u64,
    /// When true (default), internal error details are included in client-facing
    /// error responses. When false, generic messages replace full details.
    /// Go frp compat: detailedErrorsToClient. Default: true.
    #[serde(default = "default_true", alias = "detailedErrorsToClient")]
    pub detailed_errors_to_client: bool,
    /// Maximum time in seconds to wait for active connections to drain
    /// during graceful shutdown. After this timeout, remaining connections
    /// are force-closed. Default: 30.
    #[serde(default = "default_graceful_timeout")]
    pub graceful_shutdown_timeout: u64,
    /// When tcp_mux is enabled and yamux init fails, forward raw bytes
    /// to the VHost handler instead of closing the connection.
    /// Go frp compat: TCPMuxPassthrough. Default: false.
    #[serde(default, alias = "tcpmuxPassthrough")]
    pub tcp_mux_passthrough: bool,
    /// UDP packet buffer size in bytes. Controls the receive buffer for UDP
    /// proxy datagrams. Default: 1500 (Go frp compat).
    /// Go frp compat: udp_packet_size.
    #[serde(default = "default_udp_packet_size", alias = "udpPacketSize")]
    pub udp_packet_size: usize,
    /// Server-side HTTP plugin configurations. Each plugin is an external
    /// HTTP service called on lifecycle events (login, new_proxy, close_proxy).
    /// Go frp compat: http_plugins.
    #[serde(default, alias = "httpPlugins")]
    pub http_plugins: Vec<HttpPluginConfig>,
    /// Experimental feature gates. Go frp compat: [feature] section.
    #[serde(default, alias = "featureGates")]
    pub feature: FeatureConfig,
    /// Config file include patterns. Each entry is a glob pattern for
    /// additional TOML/INI config files to merge. Relative to the main
    /// config file directory.
    /// Go frp compat: includes.
    #[serde(default)]
    pub includes: Vec<String>,
    /// SSH tunnel gateway configuration.
    /// When bind_port > 0, an SSH server listens for `ssh -R` reverse tunnels.
    #[serde(default)]
    pub ssh_tunnel_gateway: SshTunnelGatewayConfig,
    /// NAT hole analysis data retention in hours.
    /// Controls how long historical NAT behavior records are kept.
    /// Go frp compat: natholeAnalysisDataReserveHours. Default: 168 (7 days, Go frp compat).
    #[serde(
        default = "default_nathole_analysis_data_reserve_hours",
        alias = "natholeAnalysisDataReserveHours"
    )]
    pub nat_hole_analysis_data_reserve_hours: u64,
    /// OpenTelemetry / observability settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Maximum concurrent connections allowed. `None` = default (512).
    /// When the limit is reached, new connections are rejected.
    /// Set to 0 to disable the connection limit entirely.
    #[serde(default, alias = "maxConnections")]
    pub max_connections: Option<u32>,
    /// Maximum accept rate in connections per second across all listeners.
    /// 0 = unlimited (default). Uses a token bucket with burst = min(rate, 1024).
    #[serde(default, alias = "maxAcceptRate")]
    pub max_accept_rate: Option<u32>,
}

/// Immutable snapshot of server config fields exposed via the dashboard v2
/// `/api/v2/system/info` endpoint. Captured at startup; not affected by reload.
/// Go frp v0.70.0 compat.
#[derive(Debug, Clone)]
pub struct ServerConfigSnapshot {
    pub bind_port: u16,
    pub vhost_http_port: u16,
    pub vhost_https_port: u16,
    pub tcpmux_httpconnect_port: u16,
    #[cfg(feature = "kcp")]
    pub kcp_bind_port: u16,
    #[cfg(feature = "quic")]
    pub quic_bind_port: u16,
    pub subdomain_host: String,
    pub max_pool_count: i64,
    pub max_ports_per_client: i64,
    pub max_conns_per_proxy: i64,
    pub heartbeat_timeout: i64,
    pub allow_ports_str: String,
    pub tls_force: bool,
}

impl ServerConfigSnapshot {
    /// Build from a server config. Fields that don't have a direct Rust
    /// equivalent default to 0 / empty (Go frp compat shape, populated as
    /// the corresponding config fields are added).
    pub fn from_config(cfg: &ServerConfig) -> Self {
        Self {
            bind_port: cfg.bind_port,
            vhost_http_port: cfg.vhost_http_port,
            vhost_https_port: cfg.vhost_https_port,
            tcpmux_httpconnect_port: cfg.tcpmux_httpconnect_port,
            #[cfg(feature = "kcp")]
            kcp_bind_port: cfg.kcp_bind_port,
            #[cfg(feature = "quic")]
            quic_bind_port: cfg.quic_bind_port,
            subdomain_host: cfg.sub_domain_host.clone(),
            max_pool_count: cfg.transport.max_pool_count,
            max_ports_per_client: cfg.max_ports_per_client as i64,
            max_conns_per_proxy: cfg.max_conns_per_proxy.min(1_048_576) as i64,
            heartbeat_timeout: cfg.transport.heartbeat_timeout,
            allow_ports_str: cfg.allow_ports.clone(),
            tls_force: cfg.tls_only,
        }
    }
}

fn default_allow_port_start() -> u16 {
    1
}
fn default_allow_port_end() -> u16 {
    65535
}
fn default_vhost_http_timeout() -> u64 {
    60
}
fn default_user_conn_timeout() -> u64 {
    10
}
fn default_udp_packet_size() -> usize {
    1500
}

fn default_nathole_analysis_data_reserve_hours() -> u64 {
    168
}
fn default_graceful_timeout() -> u64 {
    30
}
pub(super) fn default_authentication_timeout() -> i64 {
    // Default 90s (Go frp upstream defaults to 0 = replay protection off).
    // With 0, timestamp freshness and duplicate-(run_id, ts) detection are
    // both skipped, so a sniffed Login frame can be replayed for the token's
    // lifetime. Deliberate divergence from Go for a safer default; set
    // `authenticationTimeout = 0` explicitly to restore Go behaviour.
    //
    // frp-rs-only hardening: Go frp v0.71.0 does MD5 equality only
    // (pkg/auth/token.go), no freshness check and no replay table. The
    // 90s window + replay table here is a Rust-side addition — normal Go
    // clients pass (timestamps classified <1e12 as seconds; same-second
    // reconnects are allowed); only a clock skew > 90s between client and
    // server drops the connection.
    90
}
pub(super) fn default_token_auth_timeout() -> bool {
    true
}

/// A single allow-ports entry: a range, or `{single=N}` (Go frp
/// `types.PortsRange`). When `single > 0`, only that exact port is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortsRange {
    pub start: u16,
    pub end: u16,
    pub single: u16,
}

impl PortsRange {
    /// Whether `port` falls inside this entry.
    pub fn contains(&self, port: u16) -> bool {
        if self.single > 0 {
            self.single == port
        } else {
            port >= self.start && port <= self.end
        }
    }

    /// Iterate the ports covered by this entry (single → one port).
    pub fn iter(&self) -> impl Iterator<Item = u16> {
        if self.single > 0 {
            let s = self.single;
            s..=s
        } else {
            self.start..=self.end
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            proxy_bind_addr: String::new(),
            vhost_http_port: 0,
            vhost_https_port: 0,
            #[cfg(feature = "kcp")]
            kcp_bind_port: 0,
            #[cfg(feature = "quic")]
            quic_bind_port: 0,
            sudp_port: 0,
            tcpmux_httpconnect_port: 0,
            sub_domain_host: String::new(),
            #[cfg(feature = "websocket")]
            websocket_port: 0,
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            tls_only: false,
            auth: AuthServerConfig::default(),
            log: LogConfig::default(),
            web_server: WebServerConfig::default(),
            transport: ServerTransportConfig::default(),
            allow_port_start: default_allow_port_start(),
            allow_port_end: default_allow_port_end(),
            allow_ports: String::new(),
            max_ports_per_client: 0,
            max_conns_per_proxy: 0,
            vhost_http_timeout: default_vhost_http_timeout(),
            user_conn_timeout: default_user_conn_timeout(),
            tcp_mux_passthrough: false,
            detailed_errors_to_client: true,
            udp_packet_size: default_udp_packet_size(),
            http_plugins: Vec::new(),
            feature: FeatureConfig::default(),
            includes: Vec::new(),
            ssh_tunnel_gateway: SshTunnelGatewayConfig::default(),
            nat_hole_analysis_data_reserve_hours: default_nathole_analysis_data_reserve_hours(),
            observability: ObservabilityConfig::default(),
            max_connections: None,
            max_accept_rate: None,
            graceful_shutdown_timeout: default_graceful_timeout(),
        }
    }
}

impl ServerConfig {
    /// Apply conditional defaults matching Go frp dev (fatedier/frp@d486018)
    /// `ServerConfig.Complete()`. Call after deserialization, before consuming.
    pub fn complete(&mut self) {
        // When proxy_bind_addr is empty, inherit from bind_addr (Go compat).
        if self.proxy_bind_addr.is_empty() {
            self.proxy_bind_addr = self.bind_addr.clone();
        }
        // When web_server port is set but addr is empty, default to 0.0.0.0 (Go compat).
        if self.web_server.port > 0 && self.web_server.addr.is_empty() {
            self.web_server.addr = "0.0.0.0".into();
        }
        // Auto-force tls_only when tls_ca_file is set (Go frp compat).
        // Go frp auto-sets TLS.Force = true when TrustedCaFile != "".
        if !self.tls_ca_file.is_empty() && !self.tls_only {
            self.tls_only = true;
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}

fn default_bind_port() -> u16 {
    7000
}

// ---------------------------------------------------------------
// SSH Tunnel Gateway Configuration
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTunnelGatewayConfig {
    /// SSH listen port. 0 = disabled (default).
    #[serde(default, alias = "bindPort")]
    pub bind_port: u16,

    /// SSH listen address. Default: "0.0.0.0".
    #[serde(default = "default_bind_addr", alias = "bindAddr")]
    pub bind_addr: String,

    /// Path to SSH host private key file. Auto-generated if empty and
    /// auto_gen_private_key_path does not exist.
    #[serde(default, alias = "privateKeyFile")]
    pub private_key_file: String,

    /// Path where auto-generated SSH host key is written.
    /// Default: "./.autogen_ssh_key".
    #[serde(
        default = "default_autogen_ssh_key_path",
        alias = "autoGenPrivateKeyPath"
    )]
    pub auto_gen_private_key_path: String,

    /// Path to SSH authorized_keys for optional public key auth.
    /// Empty = password auth only.
    #[serde(default, alias = "authorizedKeysFile")]
    pub authorized_keys_file: String,

    /// Authenticated-session idle timeout in seconds. 0 = disabled (default,
    /// Go frp parity — Go has no SSH idle timeout). When enabled, an
    /// authenticated SSH session that stays idle for this long is
    /// disconnected so it cannot hold a connection slot forever.
    #[serde(default, alias = "sshSessionIdleTimeout")]
    pub ssh_session_idle_timeout: u64,

    /// Allow the SSH gateway to start with NO credentials (no
    /// authorized_keys file and no server_token), accepting every SSH
    /// connection without authentication. Default false: with no credentials
    /// the gateway fails closed at startup with a clear error. Set true only
    /// for trusted networks, matching Go frp's NoClientAuth mode.
    #[serde(default, alias = "allowNoneAuth")]
    pub allow_none_auth: bool,
}

fn default_autogen_ssh_key_path() -> String {
    "./.autogen_ssh_key".into()
}

impl Default for SshTunnelGatewayConfig {
    fn default() -> Self {
        Self {
            bind_port: 0,
            bind_addr: default_bind_addr(),
            private_key_file: String::new(),
            auto_gen_private_key_path: default_autogen_ssh_key_path(),
            authorized_keys_file: String::new(),
            ssh_session_idle_timeout: 0,
            allow_none_auth: false,
        }
    }
}

/// Dynamic value source used to resolve the auth token at runtime.
/// Go frp v0.70.1 compat: ValueSource with file and exec sub-sources.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValueSource {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(default)]
    pub file: Option<FileSource>,
    #[serde(default)]
    pub exec: Option<ExecSource>,
}

impl ValueSource {
    /// Validate the source shape. Returns `Ok(())` when the source is
    /// structurally valid, otherwise a human-readable config error.
    pub fn validate(&self) -> Result<(), String> {
        match self.source_type.as_str() {
            "file" => {
                let file = self.file.as_ref().ok_or_else(|| {
                    "file configuration is required when type is 'file'".to_string()
                })?;
                if file.path.is_empty() {
                    return Err("file path cannot be empty".into());
                }
                Ok(())
            }
            "exec" => {
                let exec = self.exec.as_ref().ok_or_else(|| {
                    "exec configuration is required when type is 'exec'".to_string()
                })?;
                if exec.command.is_empty() {
                    return Err("exec command cannot be empty".into());
                }
                for env in &exec.env {
                    if env.name.is_empty() {
                        return Err("exec env name cannot be empty".into());
                    }
                    if env.name.contains('=') {
                        return Err("exec env name cannot contain '='".into());
                    }
                }
                Ok(())
            }
            other => Err(format!(
                "unsupported value source type: {other} (only 'file' and 'exec' are supported)"
            )),
        }
    }
}

/// File source for [`ValueSource`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileSource {
    #[serde(default)]
    pub path: String,
}

/// Exec source for [`ValueSource`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecSource {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<ExecEnvVar>,
}

/// Additional environment variable for [`ExecSource`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecEnvVar {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthServerConfig {
    #[serde(
        default,
        alias = "authentication_method",
        alias = "auth_method",
        alias = "authMethod"
    )]
    pub method: String,
    #[serde(default)]
    pub token: String,
    /// Dynamic source for the auth token. Mutually exclusive with `token`.
    /// Go frp v0.70.1 compat: auth.tokenSource.
    #[serde(default, alias = "tokenSource")]
    pub token_source: Option<ValueSource>,
    #[serde(default)]
    pub oidc_issuer: String,
    #[serde(default)]
    pub oidc_audience: String,
    #[serde(default, alias = "oidc_token_endpoint_url")]
    pub oidc_token_endpoint: String,
    #[serde(
        default,
        alias = "oidcSkipExpiry",
        alias = "oidcSkipExpiryCheck",
        alias = "oidc_skip_expiry_check"
    )]
    pub oidc_skip_expiry: bool,
    #[serde(
        default,
        alias = "oidcSkipIssuer",
        alias = "oidcSkipIssuerCheck",
        alias = "oidc_skip_issuer_check"
    )]
    pub oidc_skip_issuer: bool,
    #[serde(default, alias = "oidcSkipNbf")]
    pub oidc_skip_nbf: bool,
    /// Skip audience ("aud" claim) validation on OIDC tokens entirely.
    /// Go frp compat: oidc_skip_audience (when the audience is empty, Go
    /// skips client-ID verification).
    #[serde(default, alias = "oidcSkipAudience")]
    pub oidc_skip_audience: bool,
    /// Additional accepted audiences for OIDC tokens, in addition to
    /// `oidc_audience`. A token is accepted when its "aud" claim matches
    /// `oidc_audience` OR any entry of this list.
    #[serde(default, alias = "oidcAdditionalAudience")]
    pub oidc_additional_audience: Vec<String>,
    /// Path to a custom CA certificate PEM file used to verify the OIDC
    /// provider's TLS certificate (for openid-configuration / JWKS fetches).
    /// Extends the default root store with the file's certificates.
    #[serde(default, alias = "oidcTLSTrustedCAFile")]
    pub oidc_tls_trusted_ca_file: String,
    /// HTTP/SOCKS5 proxy URL for OIDC HTTP client connections.
    /// Go frp compat: oidcProxyURL.
    #[serde(default, alias = "oidcProxyURL")]
    pub oidc_proxy_url: String,
    /// Additional auth scopes: "HeartBeats", "NewWorkConns".
    /// When listed, corresponding message types require authentication.
    /// Go frp compat: additionalAuthScopes.
    #[serde(default, alias = "additionalAuthScopes", alias = "additionalScopes")]
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection,
    /// in seconds. 0 disables the check. Default: 15.
    /// Go frp v0.69.1 default: 900. This implementation defaults to 15
    /// for tighter replay protection.
    /// Go frp compat: authentication_timeout.
    #[serde(
        default = "default_authentication_timeout",
        alias = "authenticationTimeout"
    )]
    pub authentication_timeout: i64,
    /// When true (default), token auth validates timestamp freshness and
    /// rejects duplicate (run_id, timestamp) pairs to prevent replay attacks.
    /// Set to false to disable timestamp/replay checking.
    /// Go frp compat: tokenAuthTimeout.
    #[serde(default = "default_token_auth_timeout", alias = "tokenAuthTimeout")]
    pub token_auth_timeout: bool,
    /// Whether to encrypt proxy data-plane bridges (AES-128-CFB).
    /// Go frp compat: use_encryption. Default: false (TLS alone is sufficient).
    /// NOTE: Control-plane encryption (AES-128-CFB after LoginResp) is ALWAYS
    /// applied regardless of this flag, matching Go frp behavior where both
    /// frps and frpc unconditionally wrap the control stream in CryptoReadWriter.
    #[serde(default)]
    pub use_encryption: bool,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            method: "token".into(),
            token: String::new(),
            token_source: None,
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_skip_nbf: false,
            oidc_skip_audience: false,
            oidc_additional_audience: Vec::new(),
            oidc_tls_trusted_ca_file: String::new(),
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
            use_encryption: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// File path for log output. Go frp uses `to` ("console" default).
    /// Both `to` and `file` are accepted; `file` takes precedence.
    #[serde(default = "default_log_file", alias = "to")]
    pub file: String,
    #[serde(default = "default_max_days", alias = "maxDays")]
    pub max_days: i32,
    /// Log output format: "text" or "json" (any other value falls back to
    /// "text"). Go frp `log.format` compat.
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default, alias = "disablePrintColor")]
    pub disable_print_color: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: default_log_file(),
            max_days: default_max_days(),
            format: default_log_format(),
            disable_print_color: false,
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_file() -> String {
    "console".into()
}

fn default_max_days() -> i32 {
    3
}

fn default_log_format() -> String {
    "text".into()
}

/// OpenTelemetry / observability configuration.
/// When `otlp_endpoint` is empty (default), OTel export is disabled even when
/// the `otel` feature is compiled in. The `OTEL_EXPORTER_OTLP_ENDPOINT`
/// environment variable takes precedence over this config field.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub otlp_endpoint: String,
    #[serde(default)]
    pub service_name: String,
}

/// Go frp v0.71.0 compat: the nested `webServer.tls` section
/// (`tls.enable` / `tls.certFile` / `tls.keyFile` / `tls.trustedCaFile`).
/// Merged with the flat `tls_cert_file`/`tls_key_file` fields — the nested
/// values take precedence when both are set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebServerTlsConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default, alias = "certFile")]
    pub cert_file: String,
    #[serde(default, alias = "keyFile")]
    pub key_file: String,
    #[serde(default, alias = "trustedCaFile")]
    pub trusted_ca_file: String,
    /// TLS server name (Go WebServerConfig.TLS.serverName).
    #[serde(default, alias = "serverName")]
    pub server_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    /// Dashboard/admin listen address. Default: "127.0.0.1" (Go frp compat,
    /// security: localhost-only by default). Empty string binds to all interfaces.
    #[serde(default = "default_web_server_addr")]
    pub addr: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, alias = "enablePrometheus")]
    pub enable_prometheus: bool,
    #[serde(default, alias = "assetsDir")]
    pub assets_dir: String,
    #[serde(default, alias = "pprofEnable")]
    pub pprof_enable: bool,
    /// TLS certificate file path. When both tls_cert_file and tls_key_file
    /// are non-empty, dashboard/admin server starts with TLS.
    #[serde(default, alias = "certFile")]
    pub tls_cert_file: String,
    /// TLS private key file path.
    #[serde(default, alias = "keyFile")]
    pub tls_key_file: String,
    /// Go frp v0.71.0 nested `webServer.tls` section (enable/certFile/
    /// keyFile/trustedCaFile). Takes precedence over the flat
    /// tls_cert_file/tls_key_file fields.
    #[serde(default, rename = "tls")]
    pub tls: WebServerTlsConfig,
    /// TLS CA file for the dashboard/admin HTTPS server (Go
    /// WebServerConfig.TLS.trustedCaFile; flattened by normalize).
    #[serde(default, alias = "trustedCaFile")]
    pub tls_ca_file: String,
    /// TLS server name (Go WebServerConfig.TLS.serverName; flattened by
    /// normalize).
    #[serde(default, alias = "serverName")]
    pub tls_server_name: String,
    /// Custom 404 page body (HTML). When non-empty, VHost and TCPMux
    /// 404 responses include this content with Content-Type: text/html.
    /// Go frp compat: custom_404_page.
    #[serde(default, alias = "custom404Page")]
    pub custom_404_page: String,
}

impl WebServerConfig {
    /// Effective TLS certificate path: nested `tls.cert_file` first, then
    /// the flat `tls_cert_file`.
    pub fn tls_cert(&self) -> &str {
        if !self.tls.cert_file.is_empty() {
            &self.tls.cert_file
        } else {
            &self.tls_cert_file
        }
    }

    /// Effective TLS key path: nested `tls.key_file` first, then the flat
    /// `tls_key_file`.
    pub fn tls_key(&self) -> &str {
        if !self.tls.key_file.is_empty() {
            &self.tls.key_file
        } else {
            &self.tls_key_file
        }
    }
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".into(),
            port: 0,
            user: String::new(),
            password: String::new(),
            enable_prometheus: false,
            assets_dir: String::new(),
            pprof_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls: WebServerTlsConfig::default(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            custom_404_page: String::new(),
        }
    }
}

fn default_web_server_addr() -> String {
    "127.0.0.1".into()
}

/// Server-side HTTP plugin configuration.
/// Each plugin is an external HTTP service that frps calls on
/// lifecycle events (login, new_proxy, close_proxy).
/// Go frp compat: HTTPPluginOptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPluginConfig {
    /// Plugin name for logging.
    #[serde(default)]
    pub name: String,
    /// Plugin server host:port (Go HTTPPluginOptions.Addr). May carry an
    /// http:// or https:// scheme prefix; a bare host:port gets "http://".
    /// Canonical Go field; `url` remains as an alias for legacy frp-rs
    /// configs.
    #[serde(default, alias = "url")]
    pub addr: String,
    /// Plugin URL path (Go HTTPPluginOptions.Path). Appended after `addr`.
    #[serde(default)]
    pub path: String,
    /// Operation this plugin handles: "login", "new_proxy", "close_proxy".
    /// Empty means all operations.
    #[serde(default)]
    pub ops: Vec<String>,
    /// Timeout in seconds for HTTP call (default: 5).
    #[serde(default = "default_plugin_timeout")]
    pub timeout: u64,
    /// When true, the plugin response determines approve/reject.
    /// When false (default), the plugin is notify-only.
    #[serde(default)]
    pub enable_control: bool,
    /// Whether to verify the plugin server TLS certificate.
    /// Go frp compat: tlsVerify.
    #[serde(default, alias = "tlsVerify")]
    pub tls_verify: bool,
}

fn default_plugin_timeout() -> u64 {
    5
}

/// QUIC transport options.
/// Go frp v0.70.1 compat: quic section in transport config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicOptions {
    /// Keepalive period in seconds. Default: 10.
    #[serde(default = "default_quic_keepalive_period", alias = "keepalivePeriod")]
    pub keepalive_period: i64,
    /// Max idle timeout in seconds. Default: 30.
    #[serde(default = "default_quic_max_idle_timeout", alias = "maxIdleTimeout")]
    pub max_idle_timeout: i64,
    /// Max incoming streams. Default: 100000.
    #[serde(
        default = "default_quic_max_incoming_streams",
        alias = "maxIncomingStreams"
    )]
    pub max_incoming_streams: i64,
}

impl Default for QuicOptions {
    fn default() -> Self {
        Self {
            keepalive_period: default_quic_keepalive_period(),
            max_idle_timeout: default_quic_max_idle_timeout(),
            max_incoming_streams: default_quic_max_incoming_streams(),
        }
    }
}

fn default_quic_keepalive_period() -> i64 {
    10
}
fn default_quic_max_idle_timeout() -> i64 {
    30
}
fn default_quic_max_incoming_streams() -> i64 {
    100000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTransportConfig {
    #[serde(default = "default_tcp_mux_option", alias = "tcpMux")]
    pub tcp_mux: Option<bool>,
    #[serde(default, alias = "tcpMuxKeepaliveInterval")]
    pub tcp_mux_keepalive_interval: i64,
    /// Heartbeat timeout in seconds. Server disconnects if no Ping
    /// received within this interval. Default: 90.
    /// Go frp compat: transport.heartbeatTimeout.
    #[serde(default = "default_heartbeat_timeout", alias = "heartbeatTimeout")]
    pub heartbeat_timeout: i64,
    /// Max work-connection pool count per client. The server caps the
    /// client-requested pool_count at this value. 0 = no server-side
    /// cap (the client's pool_count is used as-is). Default: 5.
    /// Go frp compat: transport.maxPoolCount.
    #[serde(default = "default_max_pool_count", alias = "maxPoolCount")]
    pub max_pool_count: i64,
    /// TCP keepalive interval in seconds for server-side connections.
    /// Go frp v0.70.1 compat: tcpKeepalive. Go default: 7200.
    #[serde(default = "default_tcp_keepalive", alias = "tcpKeepalive")]
    pub tcp_keepalive: i64,
    /// TCP send buffer size in bytes for server-side accepted sockets
    /// (SO_SNDBUF). 0 = OS default. frp-rs extension.
    #[serde(default, alias = "tcpSendBuffer")]
    pub tcp_send_buffer_size: u32,
    /// TCP receive buffer size in bytes for server-side accepted sockets
    /// (SO_RCVBUF). 0 = OS default. frp-rs extension.
    #[serde(default, alias = "tcpRecvBuffer")]
    pub tcp_recv_buffer_size: u32,
    /// QUIC protocol options.
    #[serde(default, rename = "quic")]
    pub quic_options: Option<QuicOptions>,
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            tcp_mux: default_tcp_mux_option(),
            tcp_mux_keepalive_interval: 30,
            heartbeat_timeout: default_heartbeat_timeout(),
            max_pool_count: default_max_pool_count(),
            tcp_keepalive: default_tcp_keepalive(),
            tcp_send_buffer_size: 0,
            tcp_recv_buffer_size: 0,
            quic_options: None,
        }
    }
}

pub(super) fn default_heartbeat_timeout() -> i64 {
    90
}
fn default_tcp_keepalive() -> i64 {
    7200
}
fn default_max_pool_count() -> i64 {
    5
}

impl ServerTransportConfig {
    /// Apply conditional defaults matching Go frp v0.70.0
    /// `ServerTransportConfig.Complete()`. Call after deserialization,
    /// before consuming the config.
    pub fn complete(&mut self) {
        self.complete_with_heartbeat_timeout_set(false);
    }

    pub(super) fn complete_with_heartbeat_timeout_set(&mut self, heartbeat_timeout_set: bool) {
        if self.tcp_mux.unwrap_or(true) && !heartbeat_timeout_set {
            // When tcpMux is enabled, heartbeat of application layer is
            // unnecessary — rely on yamux keepalive instead (Go compat).
            if self.heartbeat_timeout == default_heartbeat_timeout() || self.heartbeat_timeout == 0
            {
                self.heartbeat_timeout = -1;
            }
        }
    }
}

// ---------------------------------------------------------------
// Plugin Configuration
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(default, alias = "httpUser")]
    pub http_user: String,
    #[serde(default, alias = "httpPassword")]
    pub http_password: String,
    #[serde(default, alias = "localAddr", alias = "unixPath")]
    pub local_addr: String,
    #[serde(default, alias = "localPath")]
    pub local_path: String,
    #[serde(default, alias = "stripPrefix")]
    pub strip_prefix: String,
    #[serde(default, alias = "hostHeaderRewrite")]
    pub host_header_rewrite: String,
    #[serde(default, alias = "user")]
    pub username: String,
    #[serde(default, alias = "passwd")]
    pub password: String,
    /// TLS certificate file for plugin listener (https2http, https2https).
    #[serde(
        default,
        alias = "pluginCrtPath",
        alias = "plugin_crt_path",
        alias = "crtPath"
    )]
    pub crt_file: String,
    /// TLS key file for plugin listener (https2http, https2https).
    #[serde(
        default,
        alias = "pluginKeyPath",
        alias = "plugin_key_path",
        alias = "keyPath"
    )]
    pub key_file: String,
    /// Server name for STCP/XTCP visitor plugin (Go frp compat: serverName).
    #[serde(default, alias = "serverName")]
    pub server_name: String,
    /// Secret key for STCP/XTCP visitor plugin auth (Go frp compat: sk).
    #[serde(default, alias = "sk")]
    pub secret_key: String,
    /// Local address to bind for the visitor plugin listener.
    /// Go frp compat: bindAddr.
    #[serde(default, alias = "bindAddr")]
    pub bind_addr: String,
    /// Local port for the visitor plugin listener. -1 disables binding.
    /// Go frp compat: bindPort.
    #[serde(default, alias = "bindPort")]
    pub bind_port: i32,
    /// PROXY protocol version for the tls2raw plugin ("v1", "v2", or "").
    /// When set, the plugin reads the proxy protocol header from the tunnel
    /// stream and writes it to the local raw TCP connection before TLS
    /// handshake, so the local TLS service sees the real client IP/port.
    /// Go frp compat: proxyProtocolVersion.
    #[serde(default, alias = "proxyProtocolVersion")]
    pub proxy_protocol_version: String,
    /// Request headers to inject on plugin HTTP requests.
    /// Go frp compat: requestHeaders.set.
    #[serde(default)]
    pub request_headers: std::collections::HashMap<String, String>,
    /// Enable HTTP/2 for the plugin TLS listener (https2http/https2https).
    /// Defaults to true (Go frp's `Complete()` backfills nil → true): the
    /// listener advertises ALPN `h2` + `http/1.1` and inbound h2 requests are
    /// decoded and forwarded to the backend as HTTP/1.1. `false` restricts
    /// the listener to HTTP/1.1. http2http/http2https have no such field
    /// (plaintext inbound, HTTP/1.1 only) — Go parity.
    /// Go frp compat: enableHTTP2.
    #[serde(default, alias = "enableHTTP2")]
    pub enable_http2: Option<bool>,
}

/// Feature gate configuration ([feature] section in frps.toml / frpc.toml).
/// Go frp v0.69.1 compat: map of feature name → enabled boolean.
/// Experimental features are gated behind these flags.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeatureConfig {
    #[serde(flatten)]
    pub gates: std::collections::HashMap<String, bool>,
}

// ---------------------------------------------------------------
// Client Configuration
// ---------------------------------------------------------------

/// File-backed store configuration ([store] section in frpc.toml).
/// Go frp v0.70.1 compat: StoreConfig.path.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreConfig {
    /// Path to the JSON file that persists dynamically managed proxies and
    /// visitors. Empty disables the store.
    #[serde(default)]
    pub path: String,
}

pub(super) fn default_true() -> bool {
    true
}

fn default_tcp_mux_option() -> Option<bool> {
    Some(true)
}
