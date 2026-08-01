use serde::{Deserialize, Serialize};
use std::path::Path;

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
    #[serde(default, alias = "subDomainHost")]
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
    #[serde(default)]
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
    /// Maximum concurrent connections allowed. None = default (10000).
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
fn default_udp_packet_size_i64() -> i64 {
    1500
}
fn default_nathole_analysis_data_reserve_hours() -> u64 {
    168
}
fn default_graceful_timeout() -> u64 {
    30
}
fn default_authentication_timeout() -> i64 {
    0
}
fn default_token_auth_timeout() -> bool {
    true
}

/// Parse a bandwidth limit string like "1MB", "500KB", "100KB".
/// Returns bytes per second, or None if unparseable.
/// Go frp compat: only supports "MB" and "KB" suffixes (case-insensitive).
/// Bare numbers, single-letter suffixes ("M", "K"), and "GB" are rejected.
/// Empty string returns Some(0) (no limit, Go compat).
///
/// Note: Empty string returns `Some(0)` (not `None`) so callers using `is_some()`
/// will treat empty as a valid config value. This matches Go frp's behavior where
/// an empty bandwidth limit field means "no limit" (effectively 0). Callers that
/// need to distinguish "not set" from "set to 0" should check `is_empty()` before
/// calling this function.
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return Some(0);
    }
    let s = s.trim();
    let (num_str, mult) = {
        let end = s.len();
        if end > 2 && s[(end - 2)..].eq_ignore_ascii_case("MB") {
            (s[..(end - 2)].trim(), 1_048_576u64)
        } else if end > 2 && s[(end - 2)..].eq_ignore_ascii_case("KB") {
            // Go requires a suffix; bare numbers and single-letter suffixes are invalid.
            // Returns None when "KB" suffix is absent, rejecting bare numbers ("500")
            // and single-letter ("500K").
            (s[..(end - 2)].trim(), 1024u64)
        } else {
            return None;
        }
    };
    let num: f64 = num_str.parse().ok()?;
    if num <= 0.0 {
        return None;
    }
    Some((num * mult as f64) as u64)
}

/// Parse a comma-separated port range string into a list of (start, end) pairs.
/// e.g. "10000-20000,30000-40000" → [(10000, 20000), (30000, 40000)]
/// Returns empty vec if the string is empty.
pub fn parse_allow_ports(s: &str) -> Vec<(u16, u16)> {
    if s.trim().is_empty() {
        return vec![];
    }
    s.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            if let Some((a, b)) = part.split_once('-') {
                let start: u16 = a.trim().parse().ok()?;
                let end: u16 = b.trim().parse().ok()?;
                if start <= end {
                    Some((start, end))
                } else {
                    Some((end, start)) // swap inverted ranges
                }
            } else {
                // Single port: treat as start=end
                let p: u16 = part.parse().ok()?;
                Some((p, p))
            }
        })
        .collect()
}

/// Compute the total number of ports across all ranges.
pub fn count_ports(ranges: &[(u16, u16)]) -> u16 {
    ranges
        .iter()
        .fold(0u32, |acc, (s, e)| {
            acc.saturating_add(e.saturating_sub(*s) as u32 + 1)
        })
        .min(u16::MAX as u32) as u16
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
fn default_visitor_bind_addr() -> String {
    "127.0.0.1".into()
}
fn default_bind_port() -> u16 {
    7000
}
fn default_fallback_timeout_ms() -> u64 {
    1000
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
    #[serde(default)]
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
    #[serde(default)]
    pub oidc_token_endpoint: String,
    #[serde(default, alias = "oidcSkipExpiry", alias = "oidcSkipExpiryCheck")]
    pub oidc_skip_expiry: bool,
    #[serde(default, alias = "oidcSkipIssuer", alias = "oidcSkipIssuerCheck")]
    pub oidc_skip_issuer: bool,
    #[serde(default, alias = "oidcSkipNbf")]
    pub oidc_skip_nbf: bool,
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
    #[serde(default, alias = "disablePrintColor")]
    pub disable_print_color: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: default_log_file(),
            max_days: default_max_days(),
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
fn default_pool_count() -> i32 {
    1
}

fn default_health_check_url() -> String {
    "".into()
}

fn default_local_ip() -> String {
    "127.0.0.1".into()
}

fn default_bandwidth_limit_mode() -> String {
    "client".into()
}

fn default_health_check_timeout_seconds() -> u64 {
    3
}

fn default_health_check_max_failed() -> u32 {
    1
}

fn default_health_check_interval_seconds() -> u64 {
    10
}
fn default_max_days() -> i32 {
    3
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
    /// Custom 404 page body (HTML). When non-empty, VHost and TCPMux
    /// 404 responses include this content with Content-Type: text/html.
    /// Go frp compat: custom_404_page.
    #[serde(default)]
    pub custom_404_page: String,
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
    /// URL of the plugin server (e.g. "http://127.0.0.1:4000/handler").
    pub url: String,
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
    /// Go frp v0.70.1 compat: tcpKeepalive. Default: 7200.
    #[serde(default = "default_tcp_keepalive", alias = "tcpKeepalive")]
    pub tcp_keepalive: i64,
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
            quic_options: None,
        }
    }
}

fn default_heartbeat_timeout() -> i64 {
    90
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

    fn complete_with_heartbeat_timeout_set(&mut self, heartbeat_timeout_set: bool) {
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
    /// Enable HTTP/2 for the plugin tunnel (https2http/https2https).
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

/// Client-side authentication configuration ([auth] section in frpc.toml).
/// Mirrors Go frp v0.69.1 AuthClientConfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClientConfig {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub token: String,
    /// Dynamic source for the auth token. Mutually exclusive with `token`.
    /// Go frp v0.70.1 compat: auth.tokenSource.
    #[serde(default, alias = "tokenSource")]
    pub token_source: Option<ValueSource>,
    #[serde(default, alias = "oidcClientId")]
    pub oidc_client_id: String,
    #[serde(default, alias = "oidcClientSecret")]
    pub oidc_client_secret: String,
    #[serde(default, alias = "oidcAudience")]
    pub oidc_audience: String,
    #[serde(default, alias = "oidcTokenEndpoint")]
    pub oidc_token_endpoint: String,
    #[serde(default, alias = "oidcScope")]
    pub oidc_scope: String,
    #[serde(default, alias = "oidcIssuer")]
    pub oidc_issuer: String,
    /// Extra params for token endpoint.
    #[serde(default, alias = "additionalEndpointParams")]
    pub additional_endpoint_params: String,
    /// Path to a custom CA certificate PEM file for OIDC provider TLS.
    /// Go frp compat: tls_trusted_ca_file.
    #[serde(default, alias = "tls_trusted_ca_file")]
    pub oidc_tls_trusted_ca_file: String,
    /// Skip TLS certificate verification for OIDC (dev only).
    /// Go frp compat: insecure_skip_verify.
    #[serde(default)]
    pub oidc_tls_insecure_skip_verify: bool,
    /// HTTP/SOCKS5 proxy URL for OIDC HTTP client connections.
    /// Go frp compat: oidcProxyURL.
    #[serde(default, alias = "oidcProxyURL")]
    pub oidc_proxy_url: String,
    /// Additional auth scopes: "HeartBeats", "NewWorkConns".
    /// Client-side scopes, unioned with server's scopes.
    /// Go frp compat: additionalAuthScopes.
    #[serde(default, alias = "additionalAuthScopes", alias = "additionalScopes")]
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection
    /// (server-side only; client ignores this field). 0 disables the check.
    /// Go frp compat: authentication_timeout.
    #[serde(
        default = "default_authentication_timeout",
        alias = "authenticationTimeout"
    )]
    pub authentication_timeout: i64,
    /// When true (default), token auth validates timestamp freshness and
    /// rejects duplicate (run_id, timestamp) pairs to prevent replay attacks.
    /// This field is primarily configured on the server; the client includes
    /// it for config passthrough.
    /// Go frp compat: tokenAuthTimeout.
    #[serde(default = "default_token_auth_timeout", alias = "tokenAuthTimeout")]
    pub token_auth_timeout: bool,
}

impl Default for AuthClientConfig {
    fn default() -> Self {
        Self {
            method: "token".into(),
            token: String::new(),
            token_source: None,
            oidc_client_id: String::new(),
            oidc_client_secret: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
            oidc_scope: String::new(),
            oidc_issuer: String::new(),
            additional_endpoint_params: String::new(),
            oidc_tls_trusted_ca_file: String::new(),
            oidc_tls_insecure_skip_verify: false,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 0,
            token_auth_timeout: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_transport_protocol")]
    pub transport_protocol: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub auth: Option<AuthClientConfig>,
    #[serde(default)]
    pub user: String,
    #[serde(default, alias = "clientID")]
    pub client_id: String,
    /// Client-level metadata sent in the Login message.
    /// Go frp compat: metadatas.
    #[serde(default, alias = "metadatas")]
    pub metas: std::collections::HashMap<String, String>,
    /// Upstream proxy URL for the client→server control connection.
    /// Supports http://, socks5:// schemes. Empty = direct connection.
    /// Go frp compat: transport.proxyURL.
    #[serde(default, alias = "proxyURL")]
    pub proxy_url: String,
    /// Custom STUN server address for NAT traversal.
    /// Format: "stun:host:port". Empty = use default.
    /// Go frp compat: natHoleStunServer. Default: "stun.easyvoip.com:3478".
    #[serde(default = "default_nat_hole_stun_server", alias = "natHoleStunServer")]
    pub nat_hole_stun_server: String,
    /// Selective proxy start: if non-empty, only proxies with names in this
    /// list are started. Empty = start all proxies.
    /// Go frp compat: start.
    #[serde(default)]
    pub start: Vec<String>,
    /// Config file include patterns. Each entry is a glob pattern for
    /// additional TOML/INI config files to merge. Relative to the main
    /// config file directory.
    /// Go frp compat: includes.
    #[serde(default)]
    pub includes: Vec<String>,
    /// File-backed runtime config store. When path is set, proxies and
    /// visitors managed through the store API are loaded from and persisted
    /// to the JSON file, overlaying config-file entries with the same name.
    /// Go frp v0.70.1 compat: [store] section.
    #[serde(default, alias = "store")]
    pub store: Option<StoreConfig>,
    #[serde(default = "default_true")]
    pub tls_enable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default)]
    pub tls_ca_file: String,
    #[serde(default, alias = "tlsServerName")]
    pub tls_server_name: String,
    /// Disable the custom TLS head byte (0x17) written before the TLS handshake.
    /// When true, the client skips the Go frp protocol marker and starts TLS directly.
    /// Go frp compat: disableCustomTLSFirstByte. Default: true.
    #[serde(default = "default_true", alias = "disableCustomTLSFirstByte")]
    pub disable_custom_tls_first_byte: bool,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default = "default_true", alias = "loginFailExit")]
    pub login_fail_exit: bool,
    #[serde(default = "default_pool_count", alias = "poolCount")]
    pub pool_count: i32,
    /// Ping interval in seconds. Client sends a heartbeat Ping at this
    /// interval. Default: 30. Go frp compat: transport.heartbeatInterval.
    #[serde(default = "default_heartbeat_interval", alias = "heartbeatInterval")]
    pub heartbeat_interval: i64,
    /// Heartbeat timeout in seconds. Disconnect if no Pong received within
    /// this interval. Default: 90. Go frp compat: transport.heartbeatTimeout.
    #[serde(default = "default_heartbeat_timeout", alias = "heartbeatTimeout")]
    pub heartbeat_timeout: i64,
    #[serde(default, alias = "dnsServer")]
    pub dns_server: String,
    /// TCP keepalive interval in seconds for outbound connections to the
    /// frp server. 0 disables. Go frp compat: dialServerKeepalive.
    #[serde(default, alias = "dialServerKeepalive")]
    pub dial_server_keepalive: i64,
    /// Timeout in seconds for dialing the frp server.
    /// Go frp v0.70.1 compat: dialServerTimeout. Default: 10.
    #[serde(default = "default_dial_server_timeout", alias = "dialServerTimeout")]
    pub dial_server_timeout: i64,
    /// Local IP address to bind when dialing the frp server.
    /// Empty means use system default. Go frp compat: connectServerLocalIP.
    #[serde(default, alias = "connectServerLocalIP")]
    pub connect_server_local_ip: String,
    #[serde(default = "default_tcp_mux")]
    pub tcp_mux: bool,
    /// TCP mux keepalive interval in seconds. Controls how often yamux
    /// sends keepalive pings to detect dead peers. Default: 30.
    /// Go frp compat: transport.tcpMuxKeepaliveInterval.
    #[serde(default, alias = "tcpMuxKeepaliveInterval")]
    pub tcp_mux_keepalive_interval: i64,
    #[serde(default)]
    pub v2: bool,
    /// QUIC protocol options.
    #[serde(default, rename = "quic")]
    pub quic_options: Option<QuicOptions>,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,
    #[serde(default, alias = "webServer")]
    pub web_server: WebServerConfig,
    /// Experimental feature gates. Go frp compat: [feature] section.
    #[serde(default, alias = "featureGates")]
    pub feature: FeatureConfig,
    /// UDP packet buffer size in bytes. Controls the receive buffer for UDP
    /// proxy datagrams. Default: 1500 (Go frp compat).
    /// Go frp compat: udpPacketSize / UDPPacketSize.
    #[serde(default = "default_udp_packet_size_i64", alias = "udpPacketSize")]
    pub udp_packet_size: i64,
    /// OpenTelemetry / observability settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".into(),
            server_port: default_server_port(),
            transport_protocol: default_transport_protocol(),
            token: String::new(),
            auth: None,
            user: String::new(),
            client_id: String::new(),
            metas: std::collections::HashMap::new(),
            proxy_url: String::new(),
            nat_hole_stun_server: default_nat_hole_stun_server(),
            start: Vec::new(),
            includes: Vec::new(),
            store: None,
            tls_enable: true,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            disable_custom_tls_first_byte: true,
            log: LogConfig::default(),
            login_fail_exit: true,
            pool_count: 1,
            heartbeat_interval: default_heartbeat_interval(),
            heartbeat_timeout: default_heartbeat_timeout(),
            dns_server: String::new(),
            dial_server_keepalive: 7200,
            dial_server_timeout: default_dial_server_timeout(),
            connect_server_local_ip: String::new(),
            tcp_mux: default_tcp_mux(),
            tcp_mux_keepalive_interval: 30,
            v2: false,
            quic_options: None,
            proxies: vec![],
            visitors: vec![],
            web_server: WebServerConfig::default(),
            feature: FeatureConfig::default(),
            udp_packet_size: default_udp_packet_size_i64(),
            observability: ObservabilityConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Apply conditional defaults matching Go frp dev (fatedier/frp@d486018)
    /// `ClientCommonConfig.Complete()` + `ClientTransportConfig.Complete()`.
    /// Call after deserialization, before consuming the config.
    pub fn complete(&mut self) {
        self.complete_with_heartbeat_set(false, false);
    }

    fn complete_with_heartbeat_set(
        &mut self,
        heartbeat_interval_set: bool,
        heartbeat_timeout_set: bool,
    ) {
        // MEDIUM-7: Fallback to http_proxy/HTTP_PROXY env var when proxy_url is empty
        if self.proxy_url.is_empty() {
            if let Ok(proxy) = std::env::var("http_proxy") {
                if !proxy.is_empty() {
                    self.proxy_url = proxy;
                }
            } else if let Ok(proxy) = std::env::var("HTTP_PROXY") {
                if !proxy.is_empty() {
                    self.proxy_url = proxy;
                }
            }
        }

        // Go v0.70.1: with tcpMux enabled, application-layer heartbeats are
        // disabled by default (-1) and yamux keepalive covers liveness. An
        // explicit value is preserved (Option-style set tracking).
        if self.tcp_mux {
            if !heartbeat_interval_set {
                self.heartbeat_interval = -1;
            }
            if !heartbeat_timeout_set {
                self.heartbeat_timeout = -1;
            }
        }

        // Go v0.70.1: dialServerTimeout = 0 means "use the default" (10s).
        if self.dial_server_timeout == 0 {
            self.dial_server_timeout = default_dial_server_timeout();
        }
    }

    /// Merge file-stored proxies/visitors over this config.
    ///
    /// Go frp v0.70.1 uses the store source as a higher-priority overlay:
    /// store entries with the same name replace config-file entries, disabled
    /// store entries are kept so they suppress the lower-priority entry, and
    /// names present only in one source are carried through unchanged.
    pub fn merge_store_items(
        &self,
        store_proxies: impl IntoIterator<Item = ProxyConfig>,
        store_visitors: impl IntoIterator<Item = VisitorConfig>,
    ) -> Self {
        let mut merged = self.clone();
        let mut proxy_map: std::collections::HashMap<String, ProxyConfig> = merged
            .proxies
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect();
        for p in store_proxies {
            proxy_map.insert(p.name.clone(), p);
        }
        merged.proxies = proxy_map.into_values().collect();
        merged.proxies.sort_by(|a, b| a.name.cmp(&b.name));

        let mut visitor_map: std::collections::HashMap<String, VisitorConfig> = merged
            .visitors
            .into_iter()
            .map(|v| (v.name.clone(), v))
            .collect();
        for v in store_visitors {
            visitor_map.insert(v.name.clone(), v);
        }
        merged.visitors = visitor_map.into_values().collect();
        merged.visitors.sort_by(|a, b| a.name.cmp(&b.name));
        merged
    }
}

fn default_server_port() -> u16 {
    7000
}
fn default_transport_protocol() -> String {
    "tcp".into()
}
fn default_true() -> bool {
    true
}
fn default_tcp_mux() -> bool {
    true
}
fn default_tcp_mux_option() -> Option<bool> {
    Some(true)
}
fn default_heartbeat_interval() -> i64 {
    30
}
fn default_nat_hole_stun_server() -> String {
    "stun.easyvoip.com:3478".into()
}
fn default_tcp_keepalive() -> i64 {
    7200
}
fn default_dial_server_timeout() -> i64 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    #[serde(default = "default_local_ip", alias = "localIp", alias = "localIP")]
    pub local_ip: String,
    #[serde(default, alias = "localPort")]
    pub local_port: u16,
    #[serde(default, alias = "remotePort")]
    pub remote_port: u16,
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,
    #[serde(default, alias = "secretKey")]
    pub sk: String,
    #[serde(default)]
    pub plugin: Option<PluginConfig>,
    #[serde(default, alias = "customDomains")]
    pub custom_domains: Vec<String>,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default, alias = "httpUser")]
    pub http_user: String,
    #[serde(default, alias = "httpPwd")]
    pub http_pwd: String,
    #[serde(default, alias = "httpPassword")]
    pub http_password: String,
    #[serde(default)]
    pub locations: Vec<String>,
    #[serde(default, alias = "hostHeaderRewrite")]
    pub host_header_rewrite: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default, alias = "responseHeaders")]
    pub response_headers: std::collections::HashMap<String, String>,
    #[serde(default, alias = "routeByHTTPUser")]
    pub route_by_http_user: String,
    #[serde(default, alias = "allowUsers")]
    pub allow_users: Vec<String>,
    #[serde(default, alias = "bandwidthLimit")]
    pub bandwidth_limit: String,
    #[serde(default = "default_bandwidth_limit_mode", alias = "bandwidthLimitMode")]
    pub bandwidth_limit_mode: String,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
    #[serde(default, alias = "metadatas")]
    pub metas: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub multiplexer: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub group_key: String,
    #[serde(default)]
    pub health_check_type: String,
    #[serde(default = "default_health_check_url")]
    pub health_check_url: String,
    /// Custom HTTP headers for health check requests (Go frp compat: healthCheckHttpHeaders).
    #[serde(default, alias = "healthCheckHttpHeaders")]
    pub health_check_http_headers: std::collections::HashMap<String, String>,
    #[serde(default = "default_health_check_interval_seconds")]
    pub health_check_interval_seconds: u64,
    #[serde(default = "default_health_check_timeout_seconds")]
    pub health_check_timeout_seconds: u64,
    #[serde(default = "default_health_check_max_failed")]
    pub health_check_max_failed: u32,
    /// Virtual network name for STCP/XTCP proxy isolation.
    /// Proxies in different virtual nets cannot reach each other.
    /// Empty string (default) means the default (global) network.
    #[serde(default)]
    pub virtual_net: String,
    /// CIDR subnet this vnet client advertises to peers (e.g. "10.0.0.0/24").
    /// Only used when type = "vnet". Go frp compat: advertiseSubnet.
    #[serde(default, alias = "advertiseSubnet")]
    pub advertise_subnet: String,
    /// IP address for the local TUN device. Go frp compat: vnetIp.
    #[serde(default, alias = "vnetIp")]
    pub vnet_ip: String,
    /// Netmask for the TUN device (default: 255.255.255.0). Go frp compat: vnetNetmask.
    #[serde(default = "default_vnet_netmask", alias = "vnetNetmask")]
    pub vnet_netmask: String,
    /// MTU for the TUN device (default: 1420). Go frp compat: vnetMtu.
    #[serde(default = "default_vnet_mtu", alias = "vnetMtu")]
    pub vnet_mtu: u16,
    /// PROXY protocol version: "v1", "v2", or "" (disabled).
    /// Go frp compat: proxyProtocolVersion.
    #[serde(default, alias = "proxyProtocolVersion")]
    pub proxy_protocol_version: String,
    /// Whether this proxy is enabled. Disabled proxies are not started.
    /// Go frp compat: enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Disable NAT traversal assisted address reporting for XTCP.
    /// Go frp compat: natTraversal.disableAssistedAddrs.
    #[serde(default, alias = "disableAssistedAddrs")]
    pub disable_assisted_addrs: bool,
}

/// STCP/XTCP visitor configuration — used by frpc to expose a local port
/// that tunnels traffic to a remote STCP/XTCP proxy through the frps server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorConfig {
    /// Name for this visitor (used in logs).
    #[serde(default)]
    pub name: String,
    /// Proxy type: "stcp" or "xtcp".
    #[serde(rename = "type", default)]
    pub visitor_type: String,
    /// The STCP/XTCP proxy name to connect to (maps to proxy_name in NewVisitorConn).
    #[serde(default, alias = "serverName")]
    pub server_name: String,
    /// Shared secret key — must match the STCP proxy's `sk`.
    #[serde(default, alias = "secretKey", alias = "sk")]
    pub secret_key: String,
    /// Protocol for XTCP P2P connections: "kcp" or "quic". Default: "quic".
    /// Go frp v0.70.1 compat.
    #[serde(default = "default_xtcp_protocol", alias = "protocol")]
    pub protocol: String,
    /// Optional server user for auth matching.
    #[serde(default, alias = "serverUser")]
    pub server_user: String,
    /// Local address to bind for accepting connections.
    #[serde(default = "default_visitor_bind_addr", alias = "bindAddr")]
    pub bind_addr: String,
    /// Local port for the visitor listener. 0 = disabled, -1 = no-bind (do not
    /// listen locally), positive values start a local listener. Go frp uses `int`
    /// and negative values mean "don't bind".
    #[serde(default, alias = "bindPort")]
    pub bind_port: i32,
    /// Fallback timeout in milliseconds before switching from XTCP to STCP.
    /// Go frp compat: fallbackTimeoutMs. Default: 1000 (1 second, Go frp compat)
    #[serde(default = "default_fallback_timeout_ms", alias = "fallbackTimeoutMs")]
    pub fallback_timeout_ms: u64,
    /// Fallback visitor name if this one fails.
    #[serde(default, alias = "fallbackTo")]
    pub fallback_to: String,
    /// Disable NAT traversal assisted address reporting (STUN-discovered
    /// mapped addresses shared between peers during XTCP hole punching).
    /// Go frp compat: natTraversal.disableAssistedAddrs.
    #[serde(default, alias = "disableAssistedAddrs")]
    pub disable_assisted_addrs: bool,
    /// Encrypt the tunnel traffic.
    #[serde(default, alias = "useEncryption")]
    pub use_encryption: bool,
    /// Compress the tunnel traffic.
    #[serde(default, alias = "useCompression")]
    pub use_compression: bool,
    /// Keep XTCP tunnel open after connection ends. When true, the
    /// visitor retries NAT hole punching instead of falling back to STCP.
    /// Go frp compat: keepTunnelOpen.
    #[serde(default, alias = "keepTunnelOpen")]
    pub keep_tunnel_open: bool,
    /// Maximum XTCP NAT hole punch retries per hour.
    /// Go frp compat: maxRetriesAnHour. Default: 8.
    #[serde(default = "default_max_retries_an_hour", alias = "maxRetriesAnHour")]
    pub max_retries_an_hour: i32,
    /// Minimum interval in seconds between XTCP retry attempts.
    /// Go frp compat: minRetryInterval. Default: 90 (Go frp compat)
    #[serde(default = "default_min_retry_interval", alias = "minRetryInterval")]
    pub min_retry_interval: i64,
    /// Whether this visitor is enabled. Disabled visitors are not started.
    /// Go frp compat: enabled. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for VisitorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            visitor_type: String::new(),
            server_name: String::new(),
            secret_key: String::new(),
            server_user: String::new(),
            bind_addr: default_visitor_bind_addr(),
            bind_port: 0,
            fallback_timeout_ms: default_fallback_timeout_ms(),
            fallback_to: String::new(),
            disable_assisted_addrs: false,
            use_encryption: false,
            use_compression: false,
            keep_tunnel_open: false,
            max_retries_an_hour: default_max_retries_an_hour(),
            min_retry_interval: default_min_retry_interval(),
            protocol: default_xtcp_protocol(),
            enabled: true,
        }
    }
}

fn default_max_retries_an_hour() -> i32 {
    8
}
fn default_min_retry_interval() -> i64 {
    90
}
fn default_xtcp_protocol() -> String {
    "quic".into()
}
fn default_vnet_netmask() -> String {
    "255.255.255.0".to_string()
}
fn default_vnet_mtu() -> u16 {
    1420
}

/// Normalize a parsed TOML value from Go frp format to frp-rs format.
/// Handles:
/// - `[common]` section → flatten to top level
/// - Flat auth_*, log_*, web_server_*, transport_* → nested structs
/// - Field name differences (protocol → transport_protocol, etc.)
pub fn load_server_config_from_str(
    content: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_server_config(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    let json_value = toml_to_json(value);
    let mut cfg: ServerConfig =
        serde_json::from_value(json_value).map_err(|e| format!("config validation error: {e}"))?;
    validate_server_config(&cfg)?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

pub fn load_client_config_from_str(
    content: &str,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML parse error: {e}"))?;
    normalize_client_config(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    let mut cfg: ClientConfig = serde_json::from_value(toml_to_json(value))
        .map_err(|e| format!("config validation error: {e}"))?;
    validate_client_config(&cfg)?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Presence flags for fields whose Go default depends on whether the user
/// explicitly configured them. Computed from the normalized TOML value so
/// serde defaults cannot be confused with explicit values.
#[derive(Debug, Clone, Copy, Default)]
struct ConfigPresence {
    server_heartbeat_timeout_set: bool,
    client_heartbeat_interval_set: bool,
    client_heartbeat_timeout_set: bool,
}

impl ConfigPresence {
    fn from_normalized_value(value: &toml::Value) -> Self {
        let mut presence = Self::default();
        let Some(table) = value.as_table() else {
            return presence;
        };
        presence.client_heartbeat_interval_set =
            table.contains_key("heartbeat_interval") || table.contains_key("heartbeatInterval");
        presence.client_heartbeat_timeout_set =
            table.contains_key("heartbeat_timeout") || table.contains_key("heartbeatTimeout");
        presence.server_heartbeat_timeout_set = presence.client_heartbeat_timeout_set
            || table
                .get("transport")
                .and_then(toml::Value::as_table)
                .is_some_and(|transport| {
                    transport.contains_key("heartbeat_timeout")
                        || transport.contains_key("heartbeatTimeout")
                });
        presence
    }
}

/// Validate proxy configs after deserialization. Catches invalid bandwidth
/// limits, CR/LF in response headers, and other semantic issues that serde
/// cannot express.
fn validate_proxy_configs(proxies: &[ProxyConfig]) -> Result<(), String> {
    const VALID_PROXY_TYPES: &[&str] = &[
        "tcp", "udp", "http", "https", "stcp", "xtcp", "sudp", "tcpmux",
    ];
    for p in proxies {
        // Validate proxy_type
        if !VALID_PROXY_TYPES.contains(&p.proxy_type.as_str()) {
            return Err(format!(
                "proxy '{}': invalid proxy_type '{}'. Valid types: tcp, udp, http, https, stcp, xtcp, sudp, tcpmux",
                p.name, p.proxy_type
            ));
        }

        // Validate response headers: no CR or LF in names or values
        for (name, value) in &p.response_headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': response header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate health check HTTP headers too (same CR/LF risk)
        for (name, value) in &p.health_check_http_headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header name contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': health check header value for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate proxy headers field (injected into forwarded requests)
        for (name, value) in &p.headers {
            if name.contains('\r') || name.contains('\n') {
                return Err(format!(
                    "proxy '{}': header name in 'headers' contains CR/LF: {name:?}",
                    p.name
                ));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(format!(
                    "proxy '{}': header value in 'headers' for {name:?} contains CR/LF",
                    p.name
                ));
            }
        }

        // Validate host_header_rewrite (injected into Host header)
        if p.host_header_rewrite.contains('\r') || p.host_header_rewrite.contains('\n') {
            return Err(format!(
                "proxy '{}': host_header_rewrite contains CR/LF",
                p.name
            ));
        }

        // Validate bandwidth_limit: non-empty strings must parse
        if !p.bandwidth_limit.is_empty() && parse_bandwidth_limit(&p.bandwidth_limit).is_none() {
            let hint = if p.bandwidth_limit == "0" || p.bandwidth_limit == "0KB" {
                "value must be positive; use empty string for no limit"
            } else {
                "must be a positive number followed by KB, MB, or GB"
            };
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit: {:?} ({})",
                p.name, p.bandwidth_limit, hint
            ));
        }

        // Validate bandwidth_limit_mode: must be "client" or "server" (Go frp compat).
        if !p.bandwidth_limit_mode.is_empty()
            && p.bandwidth_limit_mode != "client"
            && p.bandwidth_limit_mode != "server"
        {
            return Err(format!(
                "proxy '{}': invalid bandwidth_limit_mode: {:?}, must be \"client\" or \"server\"",
                p.name, p.bandwidth_limit_mode
            ));
        }
    }
    Ok(())
}

/// Validate token/tokenSource mutual exclusivity and source structure.
/// Go frp v0.70.1 compat: validation/auth.go validateAuthTokenSource.
pub fn validate_auth_token_source(
    token: &str,
    token_source: &Option<ValueSource>,
) -> Result<(), String> {
    if !token.is_empty() && token_source.is_some() {
        return Err("cannot specify both auth.token and auth.tokenSource".into());
    }
    if let Some(source) = token_source {
        source
            .validate()
            .map_err(|e| format!("invalid auth.tokenSource: {e}"))?;
    }
    Ok(())
}

fn validate_server_config(cfg: &ServerConfig) -> Result<(), String> {
    validate_auth_token_source(&cfg.auth.token, &cfg.auth.token_source)?;
    // ServerConfig has no inline proxy definitions — proxies are registered
    // by clients at runtime. No proxy-level validation to do here.
    Ok(())
}

fn validate_client_config(cfg: &ClientConfig) -> Result<(), String> {
    validate_proxy_configs(&cfg.proxies)?;
    validate_no_duplicate_names(&cfg.proxies, &cfg.visitors)?;
    if let Some(auth) = &cfg.auth {
        let token = if cfg.token.is_empty() {
            auth.token.as_str()
        } else {
            cfg.token.as_str()
        };
        validate_auth_token_source(token, &auth.token_source)?;
    }
    Ok(())
}

/// Reject duplicate proxy or visitor names. Go frp v0.70.0 compat:
/// proxies and visitors are keyed by name, and duplicates would otherwise
/// be silently overwritten with no error (Go) or logged as a warning (Rust).
///
/// Cross-type duplicates (same name used for a proxy AND a visitor) are
/// allowed because they live in separate namespaces (Go frp behavior).
fn validate_no_duplicate_names(
    proxies: &[ProxyConfig],
    visitors: &[VisitorConfig],
) -> Result<(), String> {
    let mut seen = std::collections::HashSet::with_capacity(proxies.len());
    for p in proxies {
        if !seen.insert(&p.name) {
            return Err(format!("proxy name [{}] is duplicated", p.name));
        }
    }

    seen.clear();
    for v in visitors {
        if !seen.insert(&v.name) {
            return Err(format!("visitor name [{}] is duplicated", v.name));
        }
    }

    Ok(())
}

/// Convert a toml::Value to a serde_json::Value for deserialization.
/// This is needed because toml::Value can't be directly deserialized into
/// arbitrary Rust types (the round-trip through toml::to_string produces
/// invalid TOML for inline tables).
fn toml_to_json(v: toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => serde_json::Number::from_f64(f).map_or_else(
            || {
                tracing::warn!(float = %f, "NaN/Inf float value in TOML config replaced with null");
                serde_json::Value::Null
            },
            serde_json::Value::Number,
        ),
        toml::Value::Boolean(b) => serde_json::Value::Bool(b),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
        toml::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(toml_to_json).collect())
        }
        toml::Value::Table(table) => {
            let map: serde_json::Map<String, serde_json::Value> = table
                .into_iter()
                .map(|(k, v)| (k, toml_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
    }
}

/// Move matching top-level keys into a sub-table, optionally stripping known prefixes.
/// e.g. `flatten_to_table(t, &["log_file","log_level"], "log", &["log_"])`
fn flatten_to_table(table: &mut toml::Table, keys: &[&str], target: &str, strip_prefixes: &[&str]) {
    let mut items: Vec<(String, toml::Value)> = Vec::new();
    for &key in keys {
        if let Some(v) = table.remove(key) {
            let sub_key = strip_prefixes
                .iter()
                .find_map(|p| key.strip_prefix(p))
                .unwrap_or(key)
                .to_string();
            items.push((sub_key, v));
        }
    }
    if !items.is_empty() {
        let target_table = table
            .entry(target.to_string())
            .or_insert_with(|| toml::Value::Table(Default::default()));
        if let toml::Value::Table(ref mut t) = target_table {
            for (k, v) in items {
                t.insert(k, v);
            }
        }
    }
}

/// Generic config loader shared by `load_server_config` and `load_client_config`.
fn load_config_from_file<C: serde::de::DeserializeOwned>(
    path: &str,
    strict_config: bool,
    known_keys: fn() -> std::collections::HashSet<&'static str>,
    normalize: fn(&mut toml::Value),
    validate: fn(&C) -> Result<(), String>,
) -> Result<(C, ConfigPresence), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: failed to read config file: {e}"))?;
    let format = detect_format(path);
    let mut value: toml::Value =
        parse_to_toml_value(&content, format).map_err(|e| format!("{path}: parse error: {e}"))?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir)?;
    normalize(&mut value);
    let presence = ConfigPresence::from_normalized_value(&value);
    if strict_config {
        run_strict_check(&value, &known_keys(), path)?;
    }
    let json_value = toml_to_json(value);
    let cfg: C = serde_json::from_value(json_value)
        .map_err(|e| format!("{path}: config validation error: {e}"))?;
    validate(&cfg).map_err(|e| format!("{path}: {e}"))?;
    Ok((cfg, presence))
}

fn normalize_server_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section: merge into top level
        if let Some(Value::Table(common_table)) = table.remove("common") {
            for (k, v) in common_table {
                table.entry(k).or_insert(v);
            }
        }

        // Rename canonical Go camelCase section names.
        if let Some(v) = table.remove("webServer") {
            table.entry("web_server").or_insert(v);
        }
        normalize_web_server_section(table);
        if let Some(v) = table.remove("featureGates") {
            table.entry("feature").or_insert(v);
        }

        // Rename canonical Go camelCase section names.
        if let Some(v) = table.remove("webServer") {
            table.entry("web_server").or_insert(v);
        }
        normalize_web_server_section(table);
        if let Some(v) = table.remove("httpPlugins") {
            table.entry("http_plugins").or_insert(v);
        }
        if let Some(v) = table.remove("featureGates") {
            table.entry("feature").or_insert(v);
        }

        // Go allowPorts is an array of {start,end} ranges; normalize to the
        // existing comma-separated "start-end" string form.
        if let Some(Value::Array(ranges)) = table.remove("allowPorts") {
            let mut parts = Vec::new();
            for range in ranges {
                if let Some(t) = range.as_table() {
                    let start = t.get("start").and_then(Value::as_integer).unwrap_or(0);
                    let end = t.get("end").and_then(Value::as_integer).unwrap_or(start);
                    parts.push(format!("{start}-{end}"));
                }
            }
            if !parts.is_empty() {
                table.insert("allow_ports".to_string(), Value::String(parts.join(",")));
            }
        }

        // Move bare `token` into [auth] table as well
        if let Some(v) = table.remove("token") {
            let auth_table = table
                .entry("auth")
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ref mut t) = auth_table {
                t.entry("token".to_string()).or_insert(v);
            }
        }

        flatten_to_table(
            table,
            &[
                "auth_method",
                "auth_token",
                "token",
                "oidc_issuer",
                "oidc_audience",
                "oidc_token_endpoint",
            ],
            "auth",
            &["auth_", "oidc_"],
        );
        flatten_to_table(
            table,
            &["log_file", "log_level", "log_max_days"],
            "log",
            &["log_"],
        );
        flatten_to_table(
            table,
            &[
                "web_server_addr",
                "web_server_port",
                "web_server_user",
                "web_server_password",
                "web_server_enable_prometheus",
                "enable_prometheus",
                "enablePrometheus",
                "web_server_tls_cert_file",
                "web_server_tls_key_file",
            ],
            "web_server",
            &["web_server_"],
        );
        flatten_to_table(
            table,
            &[
                "tcp_mux",
                "tcp_mux_keepalive_interval",
                "heartbeat_timeout",
                "max_pool_count",
            ],
            "transport",
            &[],
        );

        // Flatten canonical Go frp [transport.tls] fields to the legacy
        // top-level Rust TLS fields. Explicit top-level values keep precedence.
        let transport_tls = table
            .get_mut("transport")
            .and_then(toml::Value::as_table_mut)
            .and_then(|transport| transport.remove("tls"));
        if let Some(Value::Table(tls_table)) = transport_tls {
            let tls_enable = tls_table.get("force").and_then(Value::as_bool) == Some(true)
                || tls_table.contains_key("certFile")
                || tls_table.contains_key("keyFile");
            for (key, value) in tls_table {
                let flat_key = match key.as_str() {
                    "force" => "tls_only",
                    "certFile" => "tls_cert_file",
                    "keyFile" => "tls_key_file",
                    "trustedCaFile" => "tls_ca_file",
                    "serverName" => "tls_server_name",
                    other => other,
                };
                table.entry(flat_key.to_string()).or_insert(value);
            }
            if tls_enable {
                table
                    .entry("tls_enable".to_string())
                    .or_insert(Value::Boolean(true));
            }
        }

        // MEDIUM-9: Normalize legacy top-level transport fields into [transport]
        flatten_to_table(
            table,
            &[
                "heartbeat_timeout",
                "max_pool_count",
                "heartbeatTimeout",
                "maxPoolCount",
            ],
            "transport",
            &[],
        );

        // Normalize canonical Go frp camelCase keys inside [transport] to
        // snake_case so serde aliases and presence tracking see one shape.
        if let Some(transport) = table.get_mut("transport").and_then(Value::as_table_mut) {
            const RENAMES: &[(&str, &str)] = &[
                ("tcpMux", "tcp_mux"),
                ("tcpMuxKeepaliveInterval", "tcp_mux_keepalive_interval"),
                ("heartbeatTimeout", "heartbeat_timeout"),
                ("maxPoolCount", "max_pool_count"),
                ("tcpKeepalive", "tcp_keepalive"),
            ];
            for (from, to) in RENAMES {
                if let Some(v) = transport.remove(*from) {
                    transport.entry((*to).to_string()).or_insert(v);
                }
            }
        }

        // MEDIUM-5: Normalize [auth.oidc] sub-table → auth.oidc_* flat fields
        if let Some(toml::Value::Table(ref mut auth_table)) = table.get_mut("auth") {
            if let Some(toml::Value::Table(oidc_table)) = auth_table.remove("oidc") {
                for (k, v) in oidc_table {
                    let flat_key = match k.as_str() {
                        "issuer" => "oidc_issuer",
                        "audience" => "oidc_audience",
                        "tokenEndpointUrl" | "tokenEndpointURL" => "oidc_token_endpoint",
                        "skipExpiry" => "oidc_skip_expiry",
                        "skipExpiryCheck" => "oidc_skip_expiry",
                        "skipIssuer" => "oidc_skip_issuer",
                        "skipIssuerCheck" => "oidc_skip_issuer",
                        "skipNbf" => "oidc_skip_nbf",
                        "proxyURL" => "oidc_proxy_url",
                        "additionalAuthScopes" => "additional_auth_scopes",
                        other => other,
                    };
                    auth_table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // MEDIUM-8: Normalize top-level custom_404_page / custom404Page → web_server.custom_404_page
        if let Some(v) = table
            .remove("custom_404_page")
            .or_else(|| table.remove("custom404Page"))
        {
            let ws_table = table
                .entry("web_server")
                .or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ref mut ws) = ws_table {
                ws.entry("custom_404_page".to_string()).or_insert(v);
            }
        }

        // MEDIUM-6: Normalize http_plugins[*].addr + .path → .url
        if let Some(toml::Value::Array(plugins)) = table.get_mut("http_plugins") {
            for plugin_val in plugins.iter_mut() {
                if let Some(ref mut pt) = plugin_val.as_table_mut() {
                    if !pt.contains_key("url") {
                        let addr = pt.get("addr").and_then(|v| v.as_str()).map(String::from);
                        let path = pt.get("path").and_then(|v| v.as_str()).map(String::from);
                        if let Some(addr) = addr {
                            let url = if let Some(p) = path {
                                let p = if p.starts_with('/') {
                                    p
                                } else {
                                    format!("/{}", p)
                                };
                                format!("{}{}", addr.trim_end_matches('/'), p)
                            } else {
                                addr
                            };
                            pt.insert("url".to_string(), toml::Value::String(url));
                        }
                    }
                }
            }
        }

        // Normalize camelCase section names to snake_case
        if let Some(ssh_section) = table.remove("sshTunnelGateway") {
            table.entry("ssh_tunnel_gateway").or_insert(ssh_section);
        }

        // Extract meta_* prefixed keys into metas map (Go frp legacy compat).
        let meta_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("meta_"))
            .cloned()
            .collect();
        if !meta_keys.is_empty() {
            let mut meta_map = toml::Table::new();
            for key in &meta_keys {
                if let Some(v) = table.remove(key) {
                    let sub_key = key.strip_prefix("meta_").unwrap().to_string();
                    meta_map.insert(sub_key, v);
                }
            }
            table
                .entry("metas".to_string())
                .or_insert(toml::Value::Table(meta_map));
        }
    }
}

fn normalize_client_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section
        if let Some(Value::Table(common_table)) = table.remove("common") {
            for (k, v) in common_table {
                table.entry(k).or_insert(v);
            }
        }

        // Rename protocol → transport_protocol (Go frp uses "protocol")
        if let Some(v) = table.remove("protocol") {
            table.entry("transport_protocol").or_insert(v);
        }

        // Rename tls_trusted_ca_file → tls_ca_file
        if let Some(v) = table.remove("tls_trusted_ca_file") {
            table.entry("tls_ca_file").or_insert(v);
        }

        // Rename serverAddr → server_addr, serverPort → server_port (Go frp uses camelCase)
        if let Some(v) = table.remove("serverAddr") {
            table.entry("server_addr").or_insert(v);
        }
        if let Some(v) = table.remove("serverPort") {
            table.entry("server_port").or_insert(v);
        }

        // Flatten legacy top-level auth_*, oidc_* fields into [auth] table.
        // Go frp uses auth.method, auth.token, auth.oidc_* in client config.
        flatten_to_table(
            table,
            &[
                "auth_method",
                "auth_token",
                "token",
                "oidc_issuer",
                "oidc_audience",
                "oidc_token_endpoint",
                "oidc_client_id",
                "oidc_client_secret",
                "oidc_scope",
                "oidc_proxy_url",
            ],
            "auth",
            &["auth_", "oidc_"],
        );

        // Also copy token from [auth] to top-level for backward compat
        // (ClientConfig has both flat `token` and nested `auth.token`).
        // Extract the token first to avoid mutable borrow conflict with table.
        let auth_token = table
            .get("auth")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("token"))
            .cloned();
        if let Some(token_val) = auth_token {
            table.entry("token").or_insert(token_val);
        }

        // Flatten [transport] section → top-level (ClientConfig has tcp_mux at top level,
        // but Go frp config puts it under [transport])
        if let Some(Value::Table(tr_table)) = table.remove("transport") {
            for (k, v) in tr_table {
                if k == "wireProtocol" {
                    // transport.wireProtocol = "v2" → top-level v2 = true (Go frp compat)
                    if v.as_str() == Some("v2") {
                        table.insert("v2".to_string(), Value::Boolean(true));
                    }
                } else {
                    let flat_key = match k.as_str() {
                        "protocol" => "transport_protocol",
                        "tcpMux" => "tcp_mux",
                        "heartbeatInterval" => "heartbeat_interval",
                        "heartbeatTimeout" => "heartbeat_timeout",
                        "dialServerTimeout" => "dial_server_timeout",
                        "poolCount" => "pool_count",
                        other => other,
                    };
                    table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // Flatten canonical Go [auth.oidc] sub-table → auth.oidc_* flat fields.
        if let Some(toml::Value::Table(ref mut auth_table)) = table.get_mut("auth") {
            if let Some(toml::Value::Table(oidc_table)) = auth_table.remove("oidc") {
                for (k, v) in oidc_table {
                    let flat_key = match k.as_str() {
                        "clientID" => "oidc_client_id",
                        "clientSecret" => "oidc_client_secret",
                        "audience" => "oidc_audience",
                        "tokenEndpointUrl" | "tokenEndpointURL" => "oidc_token_endpoint",
                        "scope" => "oidc_scope",
                        "issuer" => "oidc_issuer",
                        "additionalEndpointParams" => "additional_endpoint_params",
                        "trustedCaFile" => "oidc_tls_trusted_ca_file",
                        "insecureSkipVerify" => "oidc_tls_insecure_skip_verify",
                        "proxyURL" => "oidc_proxy_url",
                        "additionalAuthScopes" => "additional_auth_scopes",
                        other => other,
                    };
                    auth_table.entry(flat_key.to_string()).or_insert(v);
                }
            }
        }

        // Flatten [transport.tls] sub-table → top-level tls_* fields
        // Go frp compat: transport.tls.enable → tls_enable, etc.
        if let Some(Value::Table(tls_table)) = table.remove("tls") {
            for (k, v) in tls_table {
                let flat_key = match k.as_str() {
                    "enable" => "tls_enable",
                    "certFile" => "tls_cert_file",
                    "keyFile" => "tls_key_file",
                    "trustedCaFile" => "tls_ca_file",
                    "serverName" => "tls_server_name",
                    "disableCustomTLSFirstByte" => "disable_custom_tls_first_byte",
                    other => other,
                };
                table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten log_* fields into log table (client side)
        flatten_to_table(
            table,
            &["log_file", "log_level", "log_max_days"],
            "log",
            &["log_"],
        );

        // Normalize Go-format proxy sub-tables into flat fields
        normalize_proxies(table);
        normalize_visitors(table);

        // Extract meta_* prefixed keys into metas map (Go frp legacy compat).
        let meta_keys: Vec<String> = table
            .keys()
            .filter(|k| k.starts_with("meta_"))
            .cloned()
            .collect();
        if !meta_keys.is_empty() {
            let mut meta_map = toml::Table::new();
            for key in &meta_keys {
                if let Some(v) = table.remove(key) {
                    let sub_key = key.strip_prefix("meta_").unwrap().to_string();
                    meta_map.insert(sub_key, v);
                }
            }
            table
                .entry("metas".to_string())
                .or_insert(toml::Value::Table(meta_map));
        }
    }
}

/// Normalize canonical Go `[webServer.tls]` (and `[web_server.tls]`) into the
/// existing flat `web_server.tls_cert_file` / `tls_key_file` fields.
fn normalize_web_server_section(table: &mut toml::Table) {
    use toml::Value;

    let Some(Value::Table(ws)) = table.get_mut("web_server") else {
        return;
    };
    if let Some(Value::Table(tls)) = ws.remove("tls") {
        for (k, v) in tls {
            let flat_key = match k.as_str() {
                "certFile" => "tls_cert_file",
                "keyFile" => "tls_key_file",
                "trustedCaFile" => "tls_ca_file",
                "serverName" => "tls_server_name",
                other => other,
            };
            ws.entry(flat_key.to_string()).or_insert(v);
        }
    }
}

/// Normalize Go-format proxy sub-tables into flat fields for each proxy entry.
///
/// Handles:
/// - `[proxies.transport]` → flat fields (useEncryption, bandwidthLimit, ...)
/// - `[proxies.healthCheck]` → flat fields (type, intervalSeconds, ...)
/// - `[proxies.loadBalancer]` → flat fields (group, groupKey)
/// - `[proxies.requestHeaders.set]` → `headers.*`
/// - `[proxies.responseHeaders.set]` → `response_headers.*`
fn normalize_proxies(table: &mut toml::Table) {
    use toml::Value;

    let proxies = match table.get_mut("proxies") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for proxy_val in proxies.iter_mut() {
        let proxy_table = match proxy_val.as_table_mut() {
            Some(t) => t,
            _ => continue,
        };

        // Flatten [proxies.transport] sub-table
        if let Some(Value::Table(transport)) = proxy_table.remove("transport") {
            for (k, v) in transport {
                let flat_key = match k.as_str() {
                    "useEncryption" => "use_encryption",
                    "useCompression" => "use_compression",
                    "bandwidthLimit" => "bandwidth_limit",
                    "proxyProtocolVersion" => "proxy_protocol_version",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten [proxies.healthCheck] sub-table
        if let Some(Value::Table(hc)) = proxy_table.remove("healthCheck") {
            for (k, v) in hc {
                let flat_key = match k.as_str() {
                    "type" => "health_check_type",
                    "url" => "health_check_url",
                    "path" => "health_check_url",
                    "httpHeaders" => "health_check_http_headers",
                    "intervalSeconds" => "health_check_interval_seconds",
                    "timeoutSeconds" => "health_check_timeout_seconds",
                    "maxFailed" => "health_check_max_failed",
                    other => other,
                };
                let value = if k == "httpHeaders" {
                    match v {
                        Value::Array(items) => {
                            let mut map = toml::Table::new();
                            for item in items {
                                if let Some(t) = item.as_table() {
                                    let name =
                                        t.get("name").and_then(Value::as_str).unwrap_or_default();
                                    let value =
                                        t.get("value").and_then(Value::as_str).unwrap_or_default();
                                    map.insert(name.to_string(), Value::String(value.to_string()));
                                }
                            }
                            Value::Table(map)
                        }
                        other => other,
                    }
                } else {
                    v
                };
                proxy_table.entry(flat_key.to_string()).or_insert(value);
            }
        }

        // Flatten [proxies.loadBalancer] sub-table
        if let Some(Value::Table(lb)) = proxy_table.remove("loadBalancer") {
            for (k, v) in lb {
                let flat_key = match k.as_str() {
                    "group" => "group",
                    "groupKey" => "group_key",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Flatten [proxies.natTraversal] sub-table
        if let Some(Value::Table(nt)) = proxy_table.remove("natTraversal") {
            for (k, v) in nt {
                let flat_key = match k.as_str() {
                    "disableAssistedAddrs" => "disable_assisted_addrs",
                    other => other,
                };
                proxy_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        // Normalize [proxies.requestHeaders.set] → flat headers map
        if let Some(Value::Table(rh)) = proxy_table.remove("requestHeaders") {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table.get_mut("headers") {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else {
                    proxy_table.insert("headers".to_string(), Value::Table(set.clone()));
                }
            }
        }

        // Normalize [proxies.responseHeaders.set] → flat response_headers map
        if let Some(Value::Table(rh)) = proxy_table.remove("responseHeaders") {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table.get_mut("response_headers") {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else {
                    proxy_table.insert("response_headers".to_string(), Value::Table(set.clone()));
                }
            }
        }

        // Normalize Go-style flat plugin fields:
        //   plugin = "unix_domain_socket"
        //   plugin_local_addr = "/var/run/docker.sock"
        // into the nested `[proxies.plugin]` shape used by frp-rs.
        if let Some(Value::String(plugin_type)) = proxy_table.get("plugin").cloned() {
            proxy_table.remove("plugin");
            let mut plugin_table = toml::Table::new();
            plugin_table.insert("type".to_string(), Value::String(plugin_type));

            let plugin_keys: Vec<String> = proxy_table
                .keys()
                .filter(|k| k.starts_with("plugin_") || k.starts_with("plugin"))
                .cloned()
                .collect();
            for key in plugin_keys {
                if let Some(v) = proxy_table.remove(&key) {
                    let flat_key = match key.as_str() {
                        "plugin_local_addr" | "pluginLocalAddr" => "local_addr",
                        "plugin_local_path" | "pluginLocalPath" => "local_path",
                        "plugin_unix_path" | "pluginUnixPath" => "local_addr",
                        "plugin_http_user" | "pluginHttpUser" => "http_user",
                        "plugin_http_password"
                        | "pluginHttpPassword"
                        | "plugin_http_passwd"
                        | "pluginHttpPasswd" => "http_password",
                        "plugin_user" | "pluginUser" => "username",
                        "plugin_passwd" | "pluginPasswd" => "password",
                        "plugin_strip_prefix" | "pluginStripPrefix" => "strip_prefix",
                        "plugin_host_header_rewrite" | "pluginHostHeaderRewrite" => {
                            "host_header_rewrite"
                        }
                        "plugin_crt_path" | "pluginCrtPath" => "plugin_crt_path",
                        "plugin_key_path" | "pluginKeyPath" => "plugin_key_path",
                        other => other,
                    };
                    plugin_table.entry(flat_key.to_string()).or_insert(v);
                }
            }

            if let Some(Value::Table(existing)) = proxy_table.get_mut("plugin") {
                for (k, v) in plugin_table {
                    existing.entry(k).or_insert(v);
                }
            } else {
                proxy_table.insert("plugin".to_string(), Value::Table(plugin_table));
            }
        }

        // Normalize [proxies.plugin.requestHeaders.set] → request_headers map,
        // including nested `[proxies.plugin]` tables.
        if let Some(Value::Table(rh)) = proxy_table
            .get_mut("plugin")
            .and_then(Value::as_table_mut)
            .and_then(|t| t.remove("requestHeaders"))
        {
            if let Some(Value::Table(set)) = rh.get("set") {
                if let Some(Value::Table(existing)) = proxy_table
                    .get_mut("plugin")
                    .and_then(Value::as_table_mut)
                    .and_then(|t| t.get_mut("request_headers"))
                {
                    for (k, v) in set.clone() {
                        existing.entry(k).or_insert(v);
                    }
                } else if let Some(plugin) =
                    proxy_table.get_mut("plugin").and_then(Value::as_table_mut)
                {
                    plugin.insert("request_headers".to_string(), Value::Table(set.clone()));
                }
            }
        }
    }
}

/// Normalize Go-format visitor sub-tables into flat fields for each visitor.
///
/// Handles `[visitors.transport]` and `[visitors.natTraversal]`.
fn normalize_visitors(table: &mut toml::Table) {
    use toml::Value;

    let visitors = match table.get_mut("visitors") {
        Some(Value::Array(arr)) => arr,
        _ => return,
    };

    for visitor_val in visitors.iter_mut() {
        let visitor_table = match visitor_val.as_table_mut() {
            Some(t) => t,
            _ => continue,
        };

        if let Some(Value::Table(transport)) = visitor_table.remove("transport") {
            for (k, v) in transport {
                let flat_key = match k.as_str() {
                    "useEncryption" => "use_encryption",
                    "useCompression" => "use_compression",
                    other => other,
                };
                visitor_table.entry(flat_key.to_string()).or_insert(v);
            }
        }

        if let Some(Value::Table(nat)) = visitor_table.remove("natTraversal") {
            for (k, v) in nat {
                let flat_key = match k.as_str() {
                    "disableAssistedAddrs" => "disable_assisted_addrs",
                    other => other,
                };
                visitor_table.entry(flat_key.to_string()).or_insert(v);
            }
        }
    }
}

/// Load a server configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_server_config(
    path: &str,
    strict_config: bool,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ServerConfig>(
        path,
        strict_config,
        known_server_keys,
        normalize_server_config,
        validate_server_config,
    )?;
    cfg.transport
        .complete_with_heartbeat_timeout_set(presence.server_heartbeat_timeout_set);
    cfg.complete();
    Ok(cfg)
}

/// Load a client configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_client_config(
    path: &str,
    strict_config: bool,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let (mut cfg, presence) = load_config_from_file::<ClientConfig>(
        path,
        strict_config,
        known_client_keys,
        normalize_client_config,
        validate_client_config,
    )?;
    cfg.complete_with_heartbeat_set(
        presence.client_heartbeat_interval_set,
        presence.client_heartbeat_timeout_set,
    );
    Ok(cfg)
}

/// Process `includes` directives in a TOML config: for each glob pattern,
/// find matching files relative to `base_dir`, parse each, and deep-merge
/// into the main config. Removes the `includes` key after processing.
fn process_includes(
    value: &mut toml::Value,
    base_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use toml::Value;

    let table = match value.as_table_mut() {
        Some(t) => t,
        None => return Ok(()),
    };

    // Extract includes list (support both "includes" and "include" keys)
    let patterns: Vec<String> = match table.remove("includes").or_else(|| table.remove("include")) {
        Some(Value::Array(arr)) => arr
            .into_iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => vec![s],
        _ => Vec::new(),
    };

    if patterns.is_empty() {
        return Ok(());
    }

    for pattern in &patterns {
        let full_pattern = if Path::new(pattern).is_absolute() {
            pattern.clone()
        } else {
            base_dir.join(pattern).to_string_lossy().to_string()
        };

        let paths = match simple_glob(&full_pattern) {
            Ok(paths) => paths,
            Err(_) => continue,
        };

        for path in &paths {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Include file {}: read error: {}", path.display(), e);
                    continue;
                }
            };
            let inc_value: Value = match toml::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Include file {}: parse error: {}", path.display(), e);
                    continue;
                }
            };

            // Deep-merge included config into main config
            deep_merge_toml(value, &inc_value);
            tracing::debug!(path = %path.display(), "Merged include file: {}", path.display());
        }
    }

    Ok(())
}

/// Simple glob matching that supports a single `*` wildcard per path component.
/// Returns sorted list of matching file paths.
fn simple_glob(pattern: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let pattern_path = Path::new(pattern);

    // Split into: base directory (non-wildcard prefix) + wildcard component
    let parent = pattern_path.parent().unwrap_or(Path::new("."));
    let filename_part = pattern_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("*");

    if !filename_part.contains('*') {
        // No wildcard — check if exact file exists
        let path = Path::new(pattern);
        if path.is_file() {
            return Ok(vec![path.to_path_buf()]);
        }
        return Ok(Vec::new());
    }

    if !parent.exists() || !parent.is_dir() {
        return Ok(Vec::new());
    }

    // Build prefix/suffix for matching
    let (prefix, suffix) = if let Some(pos) = filename_part.find('*') {
        (&filename_part[..pos], &filename_part[pos + 1..])
    } else {
        (filename_part, "")
    };

    let ext = pattern_path.extension().and_then(|s| s.to_str());

    let mut results = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        // Match extension
        if let Some(ext) = ext {
            if path.extension().and_then(|s| s.to_str()) != Some(ext) {
                continue;
            }
        }
        // Match prefix and suffix
        if name.starts_with(prefix) && name.ends_with(suffix) {
            results.push(path);
        }
    }

    results.sort();
    Ok(results)
}

/// Deep-merge two TOML values. `base` is mutated to include all keys from `overlay`.
/// - Scalars: overlay replaces base
/// - Tables: recursively merged
/// - Arrays: concatenated (base + overlay)
fn deep_merge_toml(base: &mut toml::Value, overlay: &toml::Value) {
    use toml::Value;

    match (base, overlay) {
        (Value::Table(ref mut base_table), Value::Table(ref overlay_table)) => {
            for (key, val) in overlay_table {
                match base_table.get_mut(key) {
                    Some(base_val) => {
                        deep_merge_toml(base_val, val);
                    }
                    None => {
                        base_table.insert(key.clone(), val.clone());
                    }
                }
            }
        }
        (Value::Array(ref mut base_arr), Value::Array(ref overlay_arr)) => {
            base_arr.extend(overlay_arr.clone());
        }
        (base_val, _) => {
            *base_val = overlay.clone();
        }
    }
}

/// Collect all non-directory entries from a directory tree (recursive walk).
/// Returns file paths in sorted order. Used for `--config-dir` mode.
pub fn collect_config_files(
    dir: &Path,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_config_files_inner(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_config_files_inner(
    dir: &Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", dir.display()).into());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_config_files_inner(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext == "toml" || ext == "ini" || ext == "json")
        {
            files.push(path);
        }
    }
    Ok(())
}

// ─── Format detection ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConfigFormat {
    Toml,
    Ini,
    Json,
}

fn detect_format(path: &str) -> ConfigFormat {
    let path_lower = path.to_lowercase();
    if path_lower.ends_with(".ini") {
        ConfigFormat::Ini
    } else if path_lower.ends_with(".json") {
        ConfigFormat::Json
    } else {
        ConfigFormat::Toml
    }
}

fn parse_to_toml_value(
    content: &str,
    format: ConfigFormat,
) -> Result<toml::Value, Box<dyn std::error::Error>> {
    match format {
        ConfigFormat::Toml => Ok(toml::from_str(content)?),
        ConfigFormat::Ini => ini_to_toml(content),
        ConfigFormat::Json => {
            let json_val: serde_json::Value = serde_json::from_str(content)?;
            Ok(json_to_toml(json_val))
        }
    }
}

/// Convert serde_json::Value to toml::Value for normalization pipeline.
fn json_to_toml(v: serde_json::Value) -> toml::Value {
    match v {
        serde_json::Value::Null => toml::Value::String(String::new()),
        serde_json::Value::Bool(b) => toml::Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s),
        serde_json::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let table: toml::Table = map.into_iter().map(|(k, v)| (k, json_to_toml(v))).collect();
            toml::Value::Table(table)
        }
    }
}

// ─── INI parser (Go Viper-compatible type inference) ─────────────────

/// Parse INI content into a toml::Value.
/// Type inference rules match Go Viper behavior.
fn ini_to_toml(content: &str) -> Result<toml::Value, Box<dyn std::error::Error>> {
    let mut root = toml::Table::new();
    let mut current_section: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header: [section]
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1].trim();
            current_section = Some(section.to_string());
            root.entry(section.to_string())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            continue;
        }

        // Key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value_str = line[eq_pos + 1..].trim();

            if key.is_empty() {
                continue;
            }

            let parsed_value = infer_ini_value(value_str);

            if let Some(ref section) = current_section {
                if let Some(toml::Value::Table(ref mut table)) = root.get_mut(section) {
                    table.insert(key, parsed_value);
                }
            } else {
                root.insert(key, parsed_value);
            }
        }
    }

    Ok(toml::Value::Table(root))
}

/// Infer INI value type matching Go Viper behavior.
fn infer_ini_value(s: &str) -> toml::Value {
    let s = s.trim();

    if s.is_empty() {
        return toml::Value::String(String::new());
    }

    // Quoted string → strip quotes
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return toml::Value::String(s[1..s.len() - 1].to_string());
    }

    // Boolean
    match s.to_lowercase().as_str() {
        "true" | "yes" => return toml::Value::Boolean(true),
        "false" | "no" => return toml::Value::Boolean(false),
        _ => {}
    }

    // Comma-separated → Array (type-infer each element)
    if s.contains(',') {
        let parts: Vec<toml::Value> = s.split(',').map(|p| infer_ini_value(p.trim())).collect();
        return toml::Value::Array(parts);
    }

    // Integer
    if let Ok(i) = s.parse::<i64>() {
        return toml::Value::Integer(i);
    }

    // Float
    if let Ok(f) = s.parse::<f64>() {
        return toml::Value::Float(f);
    }

    // Default: string
    toml::Value::String(s.to_string())
}

// ─── Strict config mode ──────────────────────────────────────────────

fn known_set_from(keys: &[&'static str]) -> std::collections::HashSet<&'static str> {
    let mut set = std::collections::HashSet::new();
    set.extend(keys);
    set
}

fn known_server_keys() -> std::collections::HashSet<&'static str> {
    known_set_from(&[
        "bind_addr",
        "bind_port",
        "proxy_bind_addr",
        "vhost_http_port",
        "vhost_https_port",
        "kcp_bind_port",
        "quic_bind_port",
        "sudp_port",
        "tcpmux_httpconnect_port",
        "sub_domain_host",
        "websocket_port",
        "tls_enable",
        "tls_cert_file",
        "tls_key_file",
        "tls_ca_file",
        "tls_server_name",
        "tlsServerName",
        "tls_only",
        "auth",
        "log",
        "web_server",
        "transport",
        "allow_port_start",
        "allow_port_end",
        "allow_ports",
        "max_ports_per_client",
        "vhost_http_timeout",
        "user_conn_timeout",
        "detailed_errors_to_client",
        "tcp_mux_passthrough",
        "udp_packet_size",
        "http_plugins",
        "feature",
        "includes",
        "ssh_tunnel_gateway",
        "nat_hole_analysis_data_reserve_hours",
        "observability",
        // Go compat normalization aliases
        "common",
        "auth_method",
        "auth_token",
        "token",
        "oidc_issuer",
        "oidc_audience",
        "oidc_token_endpoint",
        "log_file",
        "log_level",
        "log_max_days",
        "web_server_addr",
        "web_server_port",
        "web_server_user",
        "web_server_password",
        "web_server_enable_prometheus",
        "web_server_tls_cert_file",
        "web_server_tls_key_file",
        "enable_prometheus",
        "tcp_mux",
        "tcp_mux_keepalive_interval",
        "tcpMux",
        "tcpMuxKeepaliveInterval",
        "heartbeatTimeout",
        "maxPoolCount",
        "tcpKeepalive",
        "max_connections",
        "max_accept_rate",
        "graceful_shutdown_timeout",
        "sshTunnelGateway",
        "bindPort",
        "bindAddr",
        "vhostHTTPPort",
        "vhostHTTPSPort",
        "kcpBindPort",
        "quicBindPort",
        "sudpPort",
        "tcpmuxHTTPConnectPort",
        "proxyBindAddr",
        "websocketPort",
        "maxPortsPerClient",
        "userConnTimeout",
        "natholeAnalysisDataReserveHours",
    ])
}

fn known_client_keys() -> std::collections::HashSet<&'static str> {
    known_set_from(&[
        "server_addr",
        "server_port",
        "transport_protocol",
        "token",
        "auth",
        "user",
        "client_id",
        "metas",
        "metadatas",
        "proxy_url",
        "proxyURL",
        "nat_hole_stun_server",
        "natHoleStunServer",
        "start",
        "includes",
        "include",
        "store",
        "tls_enable",
        "tls_cert_file",
        "tls_key_file",
        "tls_ca_file",
        "tls_server_name",
        "disable_custom_tls_first_byte",
        "disableCustomTLSFirstByte",
        "log",
        "login_fail_exit",
        "pool_count",
        "heartbeat_interval",
        "heartbeatInterval",
        "dns_server",
        "dial_server_keepalive",
        "dialServerKeepalive",
        "connect_server_local_ip",
        "connectServerLocalIP",
        "tcp_mux",
        "tcp_mux_keepalive_interval",
        "tcpMuxKeepaliveInterval",
        "v2",
        "proxies",
        "visitors",
        "web_server",
        "feature",
        "common",
        "protocol",
        "tls_trusted_ca_file",
        "serverAddr",
        "serverPort",
        "transport",
        "log_file",
        "log_level",
        "log_max_days",
        "observability",
        // Go frp v0.70.1 compat — new fields
        "quic",
        "dial_server_timeout",
        "dialServerTimeout",
        "clientID",
        "tlsServerName",
        // Client-side auth flat field normalization aliases
        "auth_method",
        "auth_token",
        "oidc_client_id",
        "oidc_client_secret",
        "oidc_audience",
        "oidc_token_endpoint",
        "oidc_scope",
        "oidc_issuer",
        "oidc_proxy_url",
    ])
}

fn run_strict_check(
    value: &toml::Value,
    known: &std::collections::HashSet<&str>,
    config_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let toml::Value::Table(ref table) = value {
        let errors = check_strict(table, known, "", config_path);
        if !errors.is_empty() {
            return Err(errors.join("\n").into());
        }
    }
    Ok(())
}

/// Compute Levenshtein distance between two strings.
/// Used to suggest corrections for unknown config fields.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let n = a_chars.len();
    let m = b_chars.len();
    let mut prev = (0..=m).collect::<Vec<_>>();
    let mut curr = vec![0; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

fn check_strict(
    table: &toml::Table,
    known: &std::collections::HashSet<&str>,
    path: &str,
    config_path: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    // Sections whose keys are wildcards (HashMap via #[serde(flatten)])
    let wildcard_sections: &[&str] = &["feature"];

    for key in table.keys() {
        let full_key = if path.is_empty() {
            key.clone()
        } else {
            format!("{}.{}", path, key)
        };

        if !known.contains(key.as_str()) {
            let parent_section = path.rsplit('.').next().unwrap_or("");
            if !wildcard_sections.contains(&parent_section) {
                let mut msg = format!(
                    "unknown field \"{}\" in config file {}",
                    full_key, config_path
                );
                // Suggest closest known key if within edit distance 3
                let mut best: Option<(&str, usize)> = None;
                for known_key in known.iter() {
                    let d = levenshtein(key, known_key);
                    if d <= 3 && (best.is_none() || d < best.unwrap().1) {
                        best = Some((known_key, d));
                    }
                }
                if let Some((suggestion, _)) = best {
                    msg.push_str(&format!(" — did you mean '{}'?", suggestion));
                }
                errors.push(msg);
            }
        }
    }
    errors
}

/// Load server configs from a directory, merging all `.toml` files.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_client_toml() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
        let cfg: ClientConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].proxy_type, "tcp");
    }

    #[test]
    fn test_parse_client_store_config() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[store]
path = "./frpc_store.json"
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert_eq!(
            cfg.store.as_ref().unwrap().path,
            "./frpc_store.json",
            "[store] path should be parsed"
        );
    }

    #[test]
    fn test_parse_client_store_defaults_to_none() {
        let cfg: ClientConfig = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();
        assert!(
            cfg.store.is_none(),
            "store defaults to None without [store]"
        );
    }

    #[test]
    fn test_merge_store_items_overlays_by_name() {
        let base = ClientConfig {
            server_addr: "127.0.0.1".into(),
            proxies: vec![
                ProxyConfig {
                    name: "shared".into(),
                    proxy_type: "tcp".into(),
                    local_port: 1000,
                    ..Default::default()
                },
                ProxyConfig {
                    name: "config-only".into(),
                    proxy_type: "tcp".into(),
                    local_port: 2000,
                    ..Default::default()
                },
            ],
            visitors: vec![VisitorConfig {
                name: "shared-visitor".into(),
                visitor_type: "stcp".into(),
                bind_port: 3000,
                ..Default::default()
            }],
            ..Default::default()
        };
        let store_proxies = vec![ProxyConfig {
            name: "shared".into(),
            proxy_type: "tcp".into(),
            local_port: 4000,
            enabled: false,
            ..Default::default()
        }];
        let store_visitors = vec![VisitorConfig {
            name: "store-visitor".into(),
            visitor_type: "xtcp".into(),
            bind_port: 5000,
            ..Default::default()
        }];

        let merged = base.merge_store_items(store_proxies, store_visitors);
        let shared = merged.proxies.iter().find(|p| p.name == "shared").unwrap();
        assert_eq!(shared.local_port, 4000, "store entry overlays config entry");
        assert!(
            merged.proxies.iter().any(|p| p.name == "config-only"),
            "config-only proxy is preserved"
        );
        assert!(
            merged.visitors.iter().any(|v| v.name == "store-visitor"),
            "store visitor is added"
        );
    }

    #[test]
    fn test_go_format_server_toml() {
        let toml_str = r#"
[common]
bind_addr = "0.0.0.0"
bind_port = 7000
auth_method = "token"
token = "my-token"
log_file = "./frps.log"
log_level = "info"
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.bind_port, 7000);
        assert_eq!(cfg.auth.token, "my-token");
        assert_eq!(cfg.auth.method, "token");
    }

    #[test]
    fn test_go_camelcase_server_port_aliases() {
        // Go frp uses camelCase: bindPort, kcpBindPort, vhostHTTPPort, etc.
        // These must map to Rust snake_case fields via serde aliases.
        let toml_str = r#"
bindPort = 7000
kcpBindPort = 7100
vhostHTTPPort = 10080
vhostHTTPSPort = 10443
quicBindPort = 7200
sudpPort = 7300
tcpmuxHTTPConnectPort = 7400
websocketPort = 7500
proxyBindAddr = "10.0.0.1"
auth.method = "token"
auth.token = "test"
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.bind_port, 7000, "bindPort");
        #[cfg(feature = "kcp")]
        assert_eq!(cfg.kcp_bind_port, 7100, "kcpBindPort");
        assert_eq!(cfg.vhost_http_port, 10080, "vhostHTTPPort");
        assert_eq!(cfg.vhost_https_port, 10443, "vhostHTTPSPort");
        #[cfg(feature = "quic")]
        assert_eq!(cfg.quic_bind_port, 7200, "quicBindPort");
        assert_eq!(cfg.sudp_port, 7300, "sudpPort");
        assert_eq!(cfg.tcpmux_httpconnect_port, 7400, "tcpmuxHTTPConnectPort");
        #[cfg(feature = "websocket")]
        assert_eq!(cfg.websocket_port, 7500, "websocketPort");
        assert_eq!(cfg.proxy_bind_addr, "10.0.0.1", "proxyBindAddr");
    }

    #[test]
    fn test_go_format_client_with_plugin_toml() {
        let toml_str = r#"
serverAddr = "140.245.66.216"
serverPort = 7000
auth.method = "token"
auth.token = "my-secret-token"

[[proxies]]
name = "home-arm-qb-proxy"
type = "tcp"
remotePort = 10081
[proxies.plugin]
type = "http_proxy"
httpUser = "cdf"
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.server_addr, "140.245.66.216");
        assert_eq!(cfg.server_port, 7000);
        assert_eq!(cfg.token, "my-secret-token");
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].name, "home-arm-qb-proxy");
        assert_eq!(cfg.proxies[0].proxy_type, "tcp");
        assert_eq!(cfg.proxies[0].remote_port, 10081);
        let plugin = cfg.proxies[0].plugin.as_ref().unwrap();
        assert_eq!(plugin.plugin_type, "http_proxy");
        assert_eq!(plugin.http_user, "cdf");
    }

    #[test]
    fn test_go_flat_plugin_unix_domain_socket_toml() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker_api"
type = "tcp"
remotePort = 9000
plugin = "unix_domain_socket"
plugin_local_addr = "/var/run/docker.sock"
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        let plugin = cfg.proxies[0]
            .plugin
            .as_ref()
            .expect("Go-style flat plugin must be parsed");
        assert_eq!(plugin.plugin_type, "unix_domain_socket");
        assert_eq!(plugin.local_addr, "/var/run/docker.sock");
    }

    #[test]
    fn test_go_flat_plugin_http_proxy_fields_toml() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web_proxy"
type = "tcp"
remotePort = 9001
plugin = "http_proxy"
plugin_http_user = "alice"
plugin_http_password = "secret"
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        let plugin = cfg.proxies[0]
            .plugin
            .as_ref()
            .expect("Go-style flat http_proxy plugin must be parsed");
        assert_eq!(plugin.plugin_type, "http_proxy");
        assert_eq!(plugin.http_user, "alice");
        assert_eq!(plugin.http_password, "secret");
    }

    #[test]
    fn test_go_proxy_camelcase_local_fields_toml() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "docker"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2375
remotePort = 6001
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.proxies[0].local_ip, "127.0.0.1");
        assert_eq!(cfg.proxies[0].local_port, 2375);
        assert_eq!(cfg.proxies[0].remote_port, 6001);
    }

    #[test]
    fn test_go_camelcase_server_fields_and_allow_ports() {
        let toml_str = r#"
bindAddr = "0.0.0.0"
bindPort = 7000
subDomainHost = "example.com"
vhostHTTPTimeout = 30
detailedErrorsToClient = false
tcpmuxPassthrough = true
enablePrometheus = true
allowPorts = [{ start = 2000, end = 3000 }, { start = 4000, end = 5000 }]

[webServer]
addr = "127.0.0.1"
port = 7500
user = "admin"
password = "secret"

[auth.oidc]
skipExpiryCheck = true
skipIssuerCheck = true

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]

[featureGates]
VirtualNet = true
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0");
        assert_eq!(cfg.sub_domain_host, "example.com");
        assert_eq!(cfg.vhost_http_timeout, 30);
        assert!(!cfg.detailed_errors_to_client);
        assert!(cfg.tcp_mux_passthrough);
        assert_eq!(cfg.web_server.port, 7500);
        assert!(cfg.web_server.enable_prometheus);
        assert_eq!(cfg.allow_ports, "2000-3000,4000-5000");
        assert_eq!(cfg.http_plugins.len(), 1);
        assert!(cfg.auth.oidc_skip_expiry);
        assert!(cfg.auth.oidc_skip_issuer);
        assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));
    }

    #[test]
    fn test_go_camelcase_client_sections_oidc_visitor_and_plugins() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
poolCount = 5

[webServer]
port = 7500

[auth.oidc]
clientID = "client-1"
clientSecret = "secret"
tokenEndpointURL = "https://issuer.example.com/token"
scope = "openid"

[featureGates]
VirtualNet = true

[[proxies]]
name = "web"
type = "http"
remotePort = 80
customDomains = ["example.com"]
metadatas = { env = "prod" }
useEncryption = true
useCompression = true
plugin = "unix_domain_socket"
plugin_unix_path = "/var/run/docker.sock"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindAddr = "0.0.0.0"
bindPort = 1234
fallbackTimeoutMs = 500

[visitors.transport]
useEncryption = true
useCompression = true

[visitors.natTraversal]
disableAssistedAddrs = true
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.pool_count, 5);
        assert_eq!(cfg.web_server.port, 7500);
        let auth = cfg.auth.as_ref().expect("auth");
        assert_eq!(auth.oidc_client_id, "client-1");
        assert_eq!(auth.oidc_client_secret, "secret");
        assert_eq!(auth.oidc_token_endpoint, "https://issuer.example.com/token");
        assert_eq!(auth.oidc_scope, "openid");
        assert_eq!(cfg.feature.gates.get("VirtualNet"), Some(&true));

        let proxy = &cfg.proxies[0];
        assert_eq!(proxy.custom_domains, vec!["example.com".to_string()]);
        assert_eq!(proxy.metas.get("env").map(String::as_str), Some("prod"));
        assert!(proxy.use_encryption);
        assert!(proxy.use_compression);
        let plugin = proxy.plugin.as_ref().expect("plugin");
        assert_eq!(plugin.plugin_type, "unix_domain_socket");
        assert_eq!(plugin.local_addr, "/var/run/docker.sock");

        let visitor = &cfg.visitors[0];
        assert_eq!(visitor.bind_addr, "0.0.0.0");
        assert_eq!(visitor.bind_port, 1234);
        assert_eq!(visitor.fallback_timeout_ms, 500);
        assert!(visitor.use_encryption);
        assert!(visitor.use_compression);
        assert!(visitor.disable_assisted_addrs);
    }

    #[test]
    fn test_go_extended_server_config_fields() {
        let toml_str = r#"
bindAddr = "127.0.0.1"
bindPort = 7000

[log]
disablePrintColor = true

[webServer]
assetsDir = "/srv/assets"
pprofEnable = true

[webServer.tls]
certFile = "/etc/frps/dash.crt"
keyFile = "/etc/frps/dash.key"

[[httpPlugins]]
name = "hook"
addr = "http://127.0.0.1:4000"
path = "/handler"
ops = ["login"]
tlsVerify = true
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
        assert!(cfg.log.disable_print_color);
        assert_eq!(cfg.web_server.assets_dir, "/srv/assets");
        assert!(cfg.web_server.pprof_enable);
        assert_eq!(cfg.web_server.tls_cert_file, "/etc/frps/dash.crt");
        assert_eq!(cfg.web_server.tls_key_file, "/etc/frps/dash.key");
        assert!(cfg.http_plugins[0].tls_verify);
    }

    #[test]
    fn test_go_extended_proxy_visitor_config_fields() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "web"
type = "http"
remotePort = 80

[proxies.natTraversal]
disableAssistedAddrs = true

[proxies.healthCheck]
type = "http"
url = "http://localhost/health"
httpHeaders = [{ name = "X-Token", value = "abc" }]

[proxies.plugin]
type = "https2http"
crtPath = "/crt"
keyPath = "/key"
enableHTTP2 = true

[proxies.plugin.requestHeaders.set]
X-Custom = "v"

[[visitors]]
name = "vis"
type = "stcp"
serverName = "s"
bindPort = 1234
enabled = false
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        let proxy = &cfg.proxies[0];
        assert!(proxy.disable_assisted_addrs);
        assert_eq!(
            proxy
                .health_check_http_headers
                .get("X-Token")
                .map(String::as_str),
            Some("abc")
        );
        let plugin = proxy.plugin.as_ref().expect("plugin");
        assert_eq!(plugin.crt_file, "/crt");
        assert_eq!(plugin.key_file, "/key");
        assert_eq!(plugin.enable_http2, Some(true));
        assert_eq!(
            plugin.request_headers.get("X-Custom").map(String::as_str),
            Some("v")
        );
        assert!(!cfg.visitors[0].enabled);
    }

    #[test]
    fn test_parse_allow_ports() {
        // Empty → empty
        assert!(parse_allow_ports("").is_empty());
        // Single range
        assert_eq!(parse_allow_ports("10000-20000"), vec![(10000, 20000)]);
        // Multiple ranges
        assert_eq!(
            parse_allow_ports("10000-20000,30000-40000"),
            vec![(10000, 20000), (30000, 40000)]
        );
        // With spaces
        assert_eq!(
            parse_allow_ports("10000-20000, 30000-40000"),
            vec![(10000, 20000), (30000, 40000)]
        );
        // Inverted range swapped
        assert_eq!(parse_allow_ports("20000-10000"), vec![(10000, 20000)]);
        // Single port
        assert_eq!(parse_allow_ports("8080"), vec![(8080, 8080)]);
        // Mixed
        assert_eq!(
            parse_allow_ports("1000-2000,8080,30000-40000"),
            vec![(1000, 2000), (8080, 8080), (30000, 40000)]
        );
    }

    #[test]
    fn test_count_ports() {
        assert_eq!(count_ports(&[(10000, 10009)]), 10);
        assert_eq!(count_ports(&[(10000, 10009), (20000, 20004)]), 15);
        assert_eq!(count_ports(&[]), 0);
    }

    #[test]
    fn test_go_format_client_toml() {
        let toml_str = r#"
[common]
server_addr = "127.0.0.1"
server_port = 7000
token = "my-token"
protocol = "tcp"
pool_count = 1

[[proxies]]
name = "test-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 80
remote_port = 7001
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert_eq!(cfg.server_port, 7000);
        assert_eq!(cfg.transport_protocol, "tcp");
        assert_eq!(cfg.proxies.len(), 1);
    }

    #[test]
    fn test_parse_allow_ports_edge_cases() {
        // Empty string
        let result = parse_allow_ports("");
        assert!(result.is_empty());

        // Garbage input
        let result = parse_allow_ports("not-a-port");
        assert!(result.is_empty());

        // Single port
        let result = parse_allow_ports("8080");
        assert_eq!(result, vec![(8080, 8080)]);

        // Two single ports (parsed individually)
        let result = parse_allow_ports("9000,8000");
        assert_eq!(result, vec![(9000, 9000), (8000, 8000)]);

        // Mixed ranges and single ports
        let result = parse_allow_ports("1000-2000,3000,5000-6000");
        assert_eq!(result, vec![(1000, 2000), (3000, 3000), (5000, 6000)]);

        // Whitespace handling
        let result = parse_allow_ports(" 1000 , 2000-3000 ");
        assert_eq!(result, vec![(1000, 1000), (2000, 3000)]);

        // Out of range values filtered (returns empty vec via None from parse)
        let result = parse_allow_ports("99999"); // > u16::MAX
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_bandwidth_limit_edge_cases() {
        // Empty → Some(0) (no limit, Go compat)
        assert_eq!(parse_bandwidth_limit(""), Some(0));
        // Bare number without suffix → None (Go requires "KB"/"MB"/"GB")
        assert_eq!(parse_bandwidth_limit("0"), None);

        // KB variant (binary: 1KB = 1024)
        assert_eq!(parse_bandwidth_limit("1KB"), Some(1024));

        // Single-letter suffix "K" → None (Go requires "KB")
        assert_eq!(parse_bandwidth_limit("1K"), None);

        // MB variant
        assert_eq!(parse_bandwidth_limit("1MB"), Some(1_048_576));

        // Single-letter suffix "M" → None (Go requires "MB")
        assert_eq!(parse_bandwidth_limit("1M"), None);

        // GB variant — Go frp rejects "GB"; must use "MB" or "KB"
        assert_eq!(parse_bandwidth_limit("1GB"), None);

        // Bare number → None (Go requires a suffix)
        assert_eq!(parse_bandwidth_limit("500"), None);

        // Case insensitive (input uppercased internally)
        assert_eq!(parse_bandwidth_limit("1mb"), Some(1_048_576));
        assert_eq!(parse_bandwidth_limit("1kb"), Some(1024));

        // Garbage → None
        assert_eq!(parse_bandwidth_limit("not-a-number"), None);
        assert_eq!(parse_bandwidth_limit("abc"), None);

        // Large value doesn't overflow
        assert!(parse_bandwidth_limit("999MB").is_some());
    }

    #[test]
    fn test_auth_client_config_default() {
        let cfg = AuthClientConfig::default();
        assert_eq!(cfg.method, "token");
        assert!(cfg.token.is_empty());
        assert!(cfg.oidc_client_id.is_empty());
        assert!(cfg.oidc_client_secret.is_empty());
        assert!(cfg.oidc_audience.is_empty());
        assert!(cfg.oidc_token_endpoint.is_empty());
        assert!(cfg.oidc_scope.is_empty());
        assert!(cfg.oidc_issuer.is_empty());
        assert!(cfg.additional_endpoint_params.is_empty());
    }

    #[test]
    fn test_parse_server_token_source_file() {
        let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml_str).unwrap();
        let source = cfg.auth.token_source.expect("tokenSource should parse");
        assert_eq!(source.source_type, "file");
        assert_eq!(source.file.unwrap().path, "/tmp/frp-token");
        assert!(source.exec.is_none());
    }

    #[test]
    fn test_parse_client_token_source_exec() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000

[auth.tokenSource]
type = "exec"
exec.command = "/bin/sh"
exec.args = ["-c", "printf '%s' \"$TOKEN\""]
exec.env = [{ name = "TOKEN", value = "secret" }]
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        let source = cfg
            .auth
            .unwrap()
            .token_source
            .expect("tokenSource should parse");
        assert_eq!(source.source_type, "exec");
        let exec = source.exec.expect("exec source should parse");
        assert_eq!(exec.command, "/bin/sh");
        assert_eq!(exec.args, vec!["-c", "printf '%s' \"$TOKEN\""]);
        assert_eq!(exec.env.len(), 1);
        assert_eq!(exec.env[0].name, "TOKEN");
        assert_eq!(exec.env[0].value, "secret");
    }

    #[test]
    fn test_reject_token_and_token_source_server() {
        let toml_str = r#"
bind_port = 7000

[auth]
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
        let err = load_server_config_from_str(toml_str)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot specify both auth.token and auth.tokenSource"),
            "{err}"
        );
    }

    #[test]
    fn test_reject_token_and_token_source_client() {
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "static-token"

[auth.tokenSource]
type = "file"
file.path = "/tmp/frp-token"
"#;
        let err = load_client_config_from_str(toml_str)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cannot specify both auth.token and auth.tokenSource"),
            "{err}"
        );
    }

    #[test]
    fn test_reject_unsupported_token_source_type() {
        let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "env"
file.path = "/tmp/frp-token"
"#;
        let err = load_server_config_from_str(toml_str)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported value source type"), "{err}");
    }

    #[test]
    fn test_reject_token_source_missing_file_path() {
        let toml_str = r#"
bind_port = 7000

[auth.tokenSource]
type = "file"
file = {}
"#;
        let err = load_server_config_from_str(toml_str)
            .unwrap_err()
            .to_string();
        assert!(err.contains("file path cannot be empty"), "{err}");
    }

    #[test]
    fn test_client_transport_flatten() {
        // Go frp client config uses [transport] section.
        // normalize_client_config should flatten it to top-level.
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"

[transport]
tcp_mux = false
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        // tcp_mux=false from [transport] should override default (true)
        assert!(!cfg.tcp_mux);
    }

    #[test]
    fn test_client_transport_flatten_default() {
        // Without [transport] section, tcp_mux defaults to true
        let toml_str = r#"
server_addr = "127.0.0.1"
server_port = 7000
token = "test-token"
"#;
        let cfg: ClientConfig = load_client_config_from_str(toml_str).unwrap();
        assert!(cfg.tcp_mux);
    }

    #[test]
    fn test_tcp_mux_defaults_application_heartbeats_disabled_go_compat() {
        let cfg = load_client_config_from_str("server_addr = '127.0.0.1'").unwrap();

        assert!(cfg.tcp_mux);
        assert_eq!(cfg.heartbeat_interval, -1);
        assert_eq!(cfg.heartbeat_timeout, -1);
    }

    #[test]
    fn test_tcp_mux_preserves_explicit_application_heartbeats() {
        let cfg = load_client_config_from_str(
            r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = 15
heartbeatTimeout = 45
"#,
        )
        .unwrap();

        assert!(cfg.tcp_mux);
        assert_eq!(cfg.heartbeat_interval, 15);
        assert_eq!(cfg.heartbeat_timeout, 45);
    }

    #[test]
    fn test_tcp_mux_disabled_keeps_application_heartbeat_defaults() {
        let cfg = load_client_config_from_str(
            r#"
serverAddr = "127.0.0.1"
[transport]
tcpMux = false
"#,
        )
        .unwrap();

        assert!(!cfg.tcp_mux);
        assert_eq!(cfg.heartbeat_interval, default_heartbeat_interval());
        assert_eq!(cfg.heartbeat_timeout, default_heartbeat_timeout());
    }

    #[test]
    fn test_dial_server_timeout_zero_means_default() {
        let cfg = load_client_config_from_str(
            r#"
serverAddr = "127.0.0.1"
[transport]
dialServerTimeout = 0
"#,
        )
        .unwrap();

        assert_eq!(cfg.dial_server_timeout, default_dial_server_timeout());
    }

    #[test]
    fn test_go_v0701_server_transport_mux_toml() {
        let cfg = load_server_config_from_str(
            r#"
bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 15
"#,
        )
        .unwrap();

        assert_eq!(cfg.transport.tcp_mux, Some(false));
        assert_eq!(cfg.transport.tcp_mux_keepalive_interval, 15);
    }

    #[test]
    fn test_explicit_server_heartbeat_timeout_90_is_preserved_with_tcp_mux() {
        let cfg = load_server_config_from_str(
            r#"
bindPort = 7000
[transport]
heartbeatTimeout = 90
"#,
        )
        .unwrap();

        assert_eq!(cfg.transport.heartbeat_timeout, 90);
    }

    #[test]
    fn test_explicit_disabled_client_heartbeat_is_preserved() {
        let cfg = load_client_config_from_str(
            r#"
serverAddr = "127.0.0.1"
[transport]
heartbeatInterval = -1
heartbeatTimeout = -1
"#,
        )
        .unwrap();

        assert!(cfg.tcp_mux);
        assert_eq!(cfg.heartbeat_interval, -1);
        assert_eq!(cfg.heartbeat_timeout, -1);
    }

    #[test]
    fn test_go_v0701_client_transport_toml() {
        let toml_str = r#"
serverAddr = "127.0.0.1"
serverPort = 7000

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = false
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#;
        let cfg = load_client_config_from_str(toml_str).unwrap();

        assert_eq!(cfg.transport_protocol, "quic");
        assert!(!cfg.tcp_mux);
        assert!(!cfg.tls_enable);
        assert_eq!(cfg.tls_server_name, "frps.example.com");
        assert!(!cfg.disable_custom_tls_first_byte);
    }

    #[test]
    fn test_go_v0701_server_transport_tls_toml() {
        let toml_str = r#"
bindPort = 7000

[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#;
        let cfg = load_server_config_from_str(toml_str).unwrap();

        assert!(cfg.tls_only);
        assert!(cfg.tls_enable);
        assert_eq!(cfg.tls_cert_file, "/etc/frp/server.crt");
        assert_eq!(cfg.tls_key_file, "/etc/frp/server.key");
        assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
        assert_eq!(cfg.tls_server_name, "frps.example.com");
    }

    #[test]
    fn test_server_legacy_tls_fields_override_canonical_transport_tls() {
        let toml_str = r#"
tls_enable = false
tls_cert_file = "/legacy/server.crt"
tls_key_file = "/legacy/server.key"
tls_ca_file = "/legacy/clients-ca.crt"

[transport.tls]
force = true
certFile = "/canonical/server.crt"
keyFile = "/canonical/server.key"
trustedCaFile = "/canonical/clients-ca.crt"
serverName = "frps.example.com"
"#;
        let cfg = load_server_config_from_str(toml_str).unwrap();

        assert!(!cfg.tls_enable);
        assert_eq!(cfg.tls_cert_file, "/legacy/server.crt");
        assert_eq!(cfg.tls_key_file, "/legacy/server.key");
        assert_eq!(cfg.tls_ca_file, "/legacy/clients-ca.crt");
        assert!(cfg.tls_only);
        assert_eq!(cfg.tls_server_name, "frps.example.com");
    }

    #[test]
    fn test_server_legacy_tls_only_overrides_canonical_force() {
        let cfg = load_server_config_from_str(
            r#"
tls_only = false

[transport.tls]
force = true
"#,
        )
        .unwrap();

        assert!(!cfg.tls_only);
    }

    #[test]
    fn test_server_canonical_trusted_ca_alone_forces_tls_only_on_complete() {
        let cfg = load_server_config_from_str(
            r#"
[transport.tls]
trustedCaFile = "/etc/frp/clients-ca.crt"
"#,
        )
        .unwrap();

        assert_eq!(cfg.tls_ca_file, "/etc/frp/clients-ca.crt");
        assert!(cfg.tls_only);
    }

    #[test]
    fn test_client_legacy_transport_tls_fields_override_canonical_nested_fields() {
        let cfg = load_client_config_from_str(
            r#"
serverAddr = "127.0.0.1"
transport_protocol = "tcp"
tcp_mux = true
tls_enable = false
tls_cert_file = "/legacy/client.crt"
tls_key_file = "/legacy/client.key"
tls_ca_file = "/legacy/server-ca.crt"
tls_server_name = "legacy.example.com"
disable_custom_tls_first_byte = true

[transport]
protocol = "quic"
tcpMux = false

[transport.tls]
enable = true
certFile = "/canonical/client.crt"
keyFile = "/canonical/client.key"
trustedCaFile = "/canonical/server-ca.crt"
serverName = "canonical.example.com"
disableCustomTLSFirstByte = false
"#,
        )
        .unwrap();

        assert_eq!(cfg.transport_protocol, "tcp");
        assert!(cfg.tcp_mux);
        assert!(!cfg.tls_enable);
        assert_eq!(cfg.tls_cert_file, "/legacy/client.crt");
        assert_eq!(cfg.tls_key_file, "/legacy/client.key");
        assert_eq!(cfg.tls_ca_file, "/legacy/server-ca.crt");
        assert_eq!(cfg.tls_server_name, "legacy.example.com");
        assert!(cfg.disable_custom_tls_first_byte);
    }

    #[test]
    fn test_strict_mode_accepts_go_v0701_transport_keys() {
        let mut client_file = tempfile::NamedTempFile::new().unwrap();
        client_file
            .write_all(
                br#"serverAddr = "127.0.0.1"
[transport]
protocol = "quic"
tcpMux = false
[transport.tls]
enable = true
serverName = "frps.example.com"
disableCustomTLSFirstByte = false
"#,
            )
            .unwrap();
        load_client_config(client_file.path().to_str().unwrap(), true).unwrap();

        let mut server_file = tempfile::NamedTempFile::new().unwrap();
        server_file
            .write_all(
                br#"bindPort = 7000
[transport]
tcpMux = false
tcpMuxKeepaliveInterval = 30
[transport.tls]
force = true
certFile = "/etc/frp/server.crt"
keyFile = "/etc/frp/server.key"
trustedCaFile = "/etc/frp/clients-ca.crt"
serverName = "frps.example.com"
"#,
            )
            .unwrap();
        load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
    }

    #[test]
    fn test_strict_mode_rejects_transport_and_tls_typos() {
        let mut client_file = tempfile::NamedTempFile::new().unwrap();
        client_file
            .write_all(
                br#"serverAddr = "127.0.0.1"
[transport]
protcol = "quic"
[transport.tls]
enabel = true
"#,
            )
            .unwrap();

        let error = load_client_config(client_file.path().to_str().unwrap(), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("protcol"));
        assert!(error.contains("enabel"));
    }

    #[test]
    fn test_strict_mode_accepts_server_tls_server_name_alias() {
        let mut server_file = tempfile::NamedTempFile::new().unwrap();
        server_file
            .write_all(
                br#"bindPort = 7000
tlsServerName = "frps.example.com"
"#,
            )
            .unwrap();

        let cfg = load_server_config(server_file.path().to_str().unwrap(), true).unwrap();
        assert_eq!(cfg.tls_server_name, "frps.example.com");
    }

    #[test]
    fn test_client_disable_custom_tls_first_byte_defaults_match_go() {
        assert!(ClientConfig::default().disable_custom_tls_first_byte);

        let cfg: ClientConfig = toml::from_str("server_addr = '127.0.0.1'").unwrap();
        assert!(cfg.disable_custom_tls_first_byte);
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("server_addr", "serverAddr"), 2); // delete '_' + case change
        assert_eq!(levenshtein("bind_port", "bindPort"), 2); // delete '_' + case change
        assert_eq!(levenshtein("token", "tokens"), 1);
        assert_eq!(levenshtein("abc", "xyz"), 3);
        assert_eq!(levenshtein("", ""), 0);
        assert_eq!(levenshtein("a", ""), 1);
    }

    #[test]
    fn test_unknown_field_suggestion() {
        // Build a simple toml table with an unknown key (flat, no sections)
        let toml_str = "token = \"test\"\nserverAddr = \"1.2.3.4\"\n";
        let value: toml::Value = toml::from_str(toml_str).unwrap();
        let known: std::collections::HashSet<&str> =
            ["token", "server_addr"].iter().copied().collect();
        let errors = check_strict(value.as_table().unwrap(), &known, "", "test.toml");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("did you mean 'server_addr'"));
    }

    #[test]
    fn test_auth_client_config_oidc_method() {
        // When method is "oidc", oidc_* fields should be usable
        let cfg = AuthClientConfig {
            method: "oidc".into(),
            oidc_client_id: "client-123".into(),
            oidc_client_secret: "secret-456".into(),
            oidc_audience: "https://api.example.com".into(),
            oidc_issuer: "https://auth.example.com".into(),
            oidc_scope: "openid profile".into(),
            oidc_token_endpoint: "https://auth.example.com/token".into(),
            ..Default::default()
        };
        assert_eq!(cfg.method, "oidc");
        assert_eq!(cfg.oidc_client_id, "client-123");
        assert_eq!(cfg.oidc_audience, "https://api.example.com");
    }

    #[test]
    fn test_ssh_tunnel_gateway_config_snake_case() {
        let toml = r#"
bind_port = 7000

[ssh_tunnel_gateway]
bind_port = 2200
bind_addr = "0.0.0.0"
private_key_file = "/etc/frp/ssh_host_key"
auto_gen_private_key_path = "/var/lib/frp/ssh_key"
authorized_keys_file = "/etc/frp/authorized_keys"
"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
        assert_eq!(cfg.ssh_tunnel_gateway.bind_addr, "0.0.0.0");
        assert_eq!(
            cfg.ssh_tunnel_gateway.private_key_file,
            "/etc/frp/ssh_host_key"
        );
        assert_eq!(
            cfg.ssh_tunnel_gateway.auto_gen_private_key_path,
            "/var/lib/frp/ssh_key"
        );
        assert_eq!(
            cfg.ssh_tunnel_gateway.authorized_keys_file,
            "/etc/frp/authorized_keys"
        );
    }

    #[test]
    fn test_ssh_tunnel_gateway_config_camel_case() {
        let toml = r#"
bindPort = 7000

[sshTunnelGateway]
bindPort = 2200
"#;
        let cfg: ServerConfig = load_server_config_from_str(toml).unwrap();
        assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 2200);
    }

    #[test]
    fn test_ssh_tunnel_gateway_default_disabled() {
        let toml = r#"bind_port = 7000"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.ssh_tunnel_gateway.bind_port, 0);
    }

    // ─── Property-based tests (proptest) ───────────────────────────────

    /// Helper: normalize a TOML string through the full server config pipeline
    /// and return the re-serialized TOML (post-normalization).
    fn normalize_server_toml(toml_str: &str) -> String {
        let mut val: toml::Value = toml::from_str(toml_str).unwrap();
        normalize_server_config(&mut val);
        toml::to_string(&val).unwrap()
    }

    /// Helper: normalize a TOML string through the full client config pipeline.
    fn normalize_client_toml(toml_str: &str) -> String {
        let mut val: toml::Value = toml::from_str(toml_str).unwrap();
        normalize_client_config(&mut val);
        toml::to_string(&val).unwrap()
    }

    mod proptest_tests {
        use proptest::prelude::*;

        // ── Strategies ────────────────────────────────────────────────

        /// Generate a valid server TOML config with [common] section.
        fn arb_server_common_config() -> impl Strategy<Value = String> {
            (any::<u16>(), any::<u16>(), any::<u16>(), any::<u16>()).prop_map(
                |(bind_port, vhost_http, vhost_https, dash_port)| {
                    format!(
                        "[common]\n\
                         bind_port = {bind_port}\n\
                         vhost_http_port = {vhost_http}\n\
                         vhost_https_port = {vhost_https}\n\
                         web_server_port = {dash_port}\n"
                    )
                },
            )
        }

        /// Generate a valid client TOML config with [common] section.
        fn arb_client_common_config() -> impl Strategy<Value = String> {
            (any::<u16>(), "[a-zA-Z0-9._-]{1,16}").prop_map(|(port, addr)| {
                format!(
                    "[common]\n\
                     server_addr = \"{addr}\"\n\
                     server_port = {port}\n\
                     token = \"test-token\"\n"
                )
            })
        }

        // ── Server config properties ──────────────────────────────────

        proptest! {
            /// Server config normalization is idempotent: applying it twice
            /// produces the same result as applying it once.
            #[test]
            fn server_normalization_idempotent(toml_str in arb_server_common_config()) {
                let first = super::normalize_server_toml(&toml_str);
                let second = super::normalize_server_toml(&first);
                prop_assert_eq!(first, second,
                    "normalize(normalize(x)) != normalize(x)");
            }
        }

        proptest! {
            /// Server config: flat auth fields produce same result as nested [auth].
            #[test]
            fn server_auth_flat_vs_nested_equivalent(
                bind_port in any::<u16>(),
                token in "[a-zA-Z0-9]{4,32}",
            ) {
                let flat = format!(
                    "bind_port = {bind_port}\n\
                     auth_method = \"token\"\n\
                     auth_token = \"{token}\"\n"
                );
                let nested = format!(
                    "bind_port = {bind_port}\n\
                     [auth]\n\
                     method = \"token\"\n\
                     token = \"{token}\"\n"
                );
                let flat_norm = super::normalize_server_toml(&flat);
                let nested_norm = super::normalize_server_toml(&nested);
                prop_assert_eq!(flat_norm, nested_norm,
                    "flat auth fields did not normalize to same result as nested [auth]");
            }
        }

        proptest! {
            /// Server config: flat log fields produce same result as nested [log].
            #[test]
            fn server_log_flat_vs_nested_equivalent(
                bind_port in any::<u16>(),
                level in "trace|debug|info|warn|error",
                file in "[a-z/.]{0,32}",
            ) {
                let flat = format!(
                    "bind_port = {bind_port}\n\
                     log_level = \"{level}\"\n\
                     log_file = \"{file}\"\n"
                );
                let nested = format!(
                    "bind_port = {bind_port}\n\
                     [log]\n\
                     level = \"{level}\"\n\
                     file = \"{file}\"\n"
                );
                let flat_norm = super::normalize_server_toml(&flat);
                let nested_norm = super::normalize_server_toml(&nested);
                prop_assert_eq!(flat_norm, nested_norm,
                    "flat log fields did not normalize to same result as nested [log]");
            }
        }

        proptest! {
            /// Server config: flat web_server fields produce same result as nested [web_server].
            #[test]
            fn server_web_server_flat_vs_nested_equivalent(
                bind_port in any::<u16>(),
                ws_port in any::<u16>(),
                ws_user in "[a-zA-Z0-9]{2,16}",
                ws_pwd in "[a-zA-Z0-9]{2,16}",
            ) {
                let flat = format!(
                    "bind_port = {bind_port}\n\
                     web_server_port = {ws_port}\n\
                     web_server_user = \"{ws_user}\"\n\
                     web_server_password = \"{ws_pwd}\"\n"
                );
                let nested = format!(
                    "bind_port = {bind_port}\n\
                     [web_server]\n\
                     port = {ws_port}\n\
                     user = \"{ws_user}\"\n\
                     password = \"{ws_pwd}\"\n"
                );
                let flat_norm = super::normalize_server_toml(&flat);
                let nested_norm = super::normalize_server_toml(&nested);
                prop_assert_eq!(flat_norm, nested_norm,
                    "flat web_server fields did not normalize to same as nested [web_server]");
            }
        }

        // ── Client config properties ─────────────────────────────────

        proptest! {
            /// Client config normalization is idempotent.
            #[test]
            fn client_normalization_idempotent(toml_str in arb_client_common_config()) {
                let first = super::normalize_client_toml(&toml_str);
                let second = super::normalize_client_toml(&first);
                prop_assert_eq!(first, second,
                    "normalize(normalize(x)) != normalize(x)");
            }
        }

        proptest! {
            /// Client config: protocol field maps to transport_protocol.
            #[test]
            fn client_protocol_to_transport_protocol(
                port in any::<u16>(),
                proto in "tcp|kcp|quic|websocket",
                token in "[a-zA-Z0-9]{4,16}",
            ) {
                let input = format!(
                    "[common]\n\
                     server_addr = \"127.0.0.1\"\n\
                     server_port = {port}\n\
                     token = \"{token}\"\n\
                     protocol = \"{proto}\"\n"
                );
                let norm = super::normalize_client_toml(&input);
                // After normalization, "protocol" should become "transport_protocol"
                prop_assert!(norm.contains("transport_protocol"),
                    "protocol was not normalized to transport_protocol: {norm}");
                prop_assert!(!norm.contains("\nprotocol ="),
                    "old protocol key still present after normalization: {norm}");
            }
        }

        proptest! {
            /// Client config: Go camelCase fields normalized to snake_case.
            #[test]
            fn client_camelcase_to_snakecase(
                port in any::<u16>(),
                addr in "[a-z.]{4,16}",
                token in "[a-zA-Z0-9]{4,16}",
            ) {
                let input = format!(
                    "[common]\n\
                     serverAddr = \"{addr}\"\n\
                     serverPort = {port}\n\
                     token = \"{token}\"\n"
                );
                let norm = super::normalize_client_toml(&input);
                prop_assert!(norm.contains("server_addr"),
                    "serverAddr not normalized to server_addr: {norm}");
                prop_assert!(norm.contains("server_port"),
                    "serverPort not normalized to server_port: {norm}");
            }
        }

        proptest! {
            /// Client config: [transport] section flattened to top-level keys.
            #[test]
            fn client_transport_flatten(
                port in any::<u16>(),
                token in "[a-zA-Z0-9]{4,16}",
            ) {
                let input = format!(
                    "server_addr = \"127.0.0.1\"\n\
                     server_port = {port}\n\
                     token = \"{token}\"\n\
                     [transport]\n\
                     tcp_mux = false\n"
                );
                let norm = super::normalize_client_toml(&input);
                // After normalization, [transport] should be gone and tcp_mux at top level
                prop_assert!(norm.contains("tcp_mux"),
                    "transport.tcp_mux not flattened to top-level: {norm}");
                // The [transport] section itself should be gone
                prop_assert!(!norm.contains("[transport]"),
                    "[transport] section still present after flatten: {norm}");
            }
        }

        proptest! {
            /// Server config: [common] section flattened to root, then normalization
            /// is idempotent.
            #[test]
            fn server_common_flatten_idempotent(
                bind_port in any::<u16>(),
                token in "[a-zA-Z0-9]{4,16}",
            ) {
                let input = format!(
                    "[common]\n\
                     bind_port = {bind_port}\n\
                     auth_method = \"token\"\n\
                     auth_token = \"{token}\"\n\
                     log_level = \"info\"\n"
                );
                let first = super::normalize_server_toml(&input);
                let second = super::normalize_server_toml(&first);
                prop_assert_eq!(first.clone(), second,
                    "[common] flatten + normalize not idempotent");
                // [common] should be gone
                prop_assert!(!first.contains("[common]"),
                    "[common] section still present after normalization: {first}");
            }
        }

        // ── Non-proptest edge case tests ─────────────────────────────

        #[test]
        fn server_token_promoted_to_auth() {
            let input = "bind_port = 7000\ntoken = \"my-secret\"\n";
            let norm = super::normalize_server_toml(input);
            assert!(
                norm.contains("[auth]"),
                "token should be promoted into [auth]: {norm}"
            );
            assert!(
                norm.contains("token = \"my-secret\""),
                "token value missing: {norm}"
            );
        }

        #[test]
        fn server_ssh_tunnel_gateway_rename() {
            let input = "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 2200\n";
            let norm = super::normalize_server_toml(input);
            assert!(
                norm.contains("ssh_tunnel_gateway"),
                "sshTunnelGateway not renamed: {norm}"
            );
            assert!(
                !norm.contains("sshTunnelGateway"),
                "old sshTunnelGateway key still present: {norm}"
            );
        }

        #[test]
        fn client_tls_trusted_ca_rename() {
            let input = "server_addr = \"x\"\nserver_port = 7000\ntls_trusted_ca_file = \"/certs/ca.pem\"\n";
            let norm = super::normalize_client_toml(input);
            assert!(
                norm.contains("tls_ca_file"),
                "tls_trusted_ca_file not renamed to tls_ca_file: {norm}"
            );
            assert!(
                !norm.contains("tls_trusted_ca_file"),
                "old tls_trusted_ca_file key still present: {norm}"
            );
        }

        #[test]
        fn server_enable_prometheus_to_web_server() {
            let input = "bind_port = 7000\nenable_prometheus = true\n";
            let norm = super::normalize_server_toml(input);
            assert!(
                norm.contains("[web_server]"),
                "enable_prometheus should create [web_server]: {norm}"
            );
            assert!(
                norm.contains("enable_prometheus"),
                "enable_prometheus value missing: {norm}"
            );
        }

        #[test]
        fn client_transport_wire_protocol_v2() {
            let input =
                "server_addr = \"x\"\nserver_port = 7000\n[transport]\nwireProtocol = \"v2\"\n";
            let norm = super::normalize_client_toml(input);
            assert!(
                norm.contains("v2 = true"),
                "wireProtocol=v2 not converted to v2=true: {norm}"
            );
        }
    }

    // --- validate_no_duplicate_names tests (Go frp v0.70.0 compat) ---

    #[test]
    fn duplicate_proxy_names_rejected() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "dup"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
        let err = super::load_client_config_from_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("proxy name [dup] is duplicated"),
            "expected duplicate proxy error, got: {err}"
        );
    }

    #[test]
    fn duplicate_visitor_names_rejected() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001

            [[visitors]]
            name = "dup"
            type = "stcp"
            server_name = "b"
            secret_key = "secret"
            bind_port = 9002
        "#;
        let err = super::load_client_config_from_str(toml).unwrap_err();
        assert!(
            err.to_string().contains("visitor name [dup] is duplicated"),
            "expected duplicate visitor error, got: {err}"
        );
    }

    #[test]
    fn unique_proxy_names_accepted() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "p1"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[proxies]]
            name = "p2"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 3306
            remote_port = 6001
        "#;
        super::load_client_config_from_str(toml).unwrap();
    }

    #[test]
    fn same_name_across_proxy_and_visitor_allowed() {
        // Go frp v0.70.0: proxies and visitors are separate namespaces.
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000

            [[proxies]]
            name = "same"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 22
            remote_port = 6000

            [[visitors]]
            name = "same"
            type = "stcp"
            server_name = "a"
            secret_key = "secret"
            bind_port = 9001
        "#;
        super::load_client_config_from_str(toml).unwrap();
    }

    // ── HIGH-1 / HIGH-2: Proxy sub-table normalization ────────────────

    #[test]
    fn proxy_transport_subtable_normalized() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.transport]
            useEncryption = true
            bandwidthLimit = "1MB"
            proxyProtocolVersion = "v2"
        "#;
        let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
        let p = &cfg.proxies[0];
        assert!(p.use_encryption, "useEncryption should be true");
        assert_eq!(p.bandwidth_limit, "1MB");
        assert_eq!(p.proxy_protocol_version, "v2");
    }

    #[test]
    fn proxy_healthcheck_subtable_normalized() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.healthCheck]
            type = "tcp"
            intervalSeconds = 5
            timeoutSeconds = 2
            maxFailed = 3
        "#;
        let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(p.health_check_type, "tcp");
        assert_eq!(p.health_check_interval_seconds, 5);
        assert_eq!(p.health_check_timeout_seconds, 2);
        assert_eq!(p.health_check_max_failed, 3);
    }

    #[test]
    fn proxy_loadbalancer_subtable_normalized() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "tcp"
            local_ip = "127.0.0.1"
            local_port = 80
            remote_port = 7001
            [proxies.loadBalancer]
            group = "web"
            groupKey = "secret"
        "#;
        let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(p.group, "web");
        assert_eq!(p.group_key, "secret");
    }

    #[test]
    fn proxy_request_headers_set_normalized() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.requestHeaders.set]
            "x-from-where" = "value"
        "#;
        let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(
            p.headers.get("x-from-where").map(|s| s.as_str()),
            Some("value")
        );
    }

    #[test]
    fn proxy_response_headers_set_normalized() {
        let toml = r#"
            server_addr = "127.0.0.1"
            server_port = 7000
            [[proxies]]
            name = "test"
            type = "http"
            local_ip = "127.0.0.1"
            local_port = 80
            custom_domains = ["example.com"]
            [proxies.responseHeaders.set]
            "X-Frame-Options" = "DENY"
        "#;
        let cfg: super::ClientConfig = super::load_client_config_from_str(toml).unwrap();
        let p = &cfg.proxies[0];
        assert_eq!(
            p.response_headers
                .get("X-Frame-Options")
                .map(|s| s.as_str()),
            Some("DENY")
        );
    }

    // ── MEDIUM-3: LogConfig `to` alias ─────────────────────────────────

    #[test]
    fn log_to_alias_works() {
        let toml = "level = \"debug\"\nto = \"/var/log/frps.log\"\nmax_days = 7\n";
        let cfg: super::LogConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.file, "/var/log/frps.log");
    }

    // ── MEDIUM-4: WebServer addr default ────────────────────────────────

    #[test]
    fn web_server_addr_defaults_to_localhost() {
        let cfg = super::WebServerConfig::default();
        assert_eq!(cfg.addr, "127.0.0.1");
    }

    // ── MEDIUM-5: OIDC nesting normalization ───────────────────────────

    #[test]
    fn auth_oidc_subtable_normalized() {
        let toml = r#"
bind_port = 7000
[auth.oidc]
issuer = "https://auth.example.com"
audience = "https://api.example.com"
tokenEndpointURL = "https://auth.example.com/token"
"#;
        let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
        assert_eq!(cfg.auth.oidc_issuer, "https://auth.example.com");
        assert_eq!(cfg.auth.oidc_audience, "https://api.example.com");
        assert_eq!(
            cfg.auth.oidc_token_endpoint,
            "https://auth.example.com/token"
        );
    }

    // ── MEDIUM-6: HTTP plugins addr+path normalization ─────────────────

    #[test]
    fn http_plugin_addr_path_to_url() {
        let toml = r#"
bind_port = 7000
[[http_plugins]]
name = "test"
addr = "http://127.0.0.1:4000"
path = "/handler"
"#;
        let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
        assert_eq!(cfg.http_plugins[0].url, "http://127.0.0.1:4000/handler");
    }

    // ── MEDIUM-8: custom_404_page normalization ────────────────────────

    #[test]
    fn custom_404_page_top_level_normalized() {
        let toml = r#"
bind_port = 7000
custom404Page = "<html>Not Found</html>"
"#;
        let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
        assert_eq!(cfg.web_server.custom_404_page, "<html>Not Found</html>");
    }

    // ── MEDIUM-9: transport legacy fields normalization ─────────────────

    #[test]
    fn transport_legacy_fields_normalized() {
        let toml = r#"
bind_port = 7000
heartbeat_timeout = 120
max_pool_count = 10
"#;
        let cfg: super::ServerConfig = super::load_server_config_from_str(toml).unwrap();
        assert_eq!(cfg.transport.heartbeat_timeout, 120);
        assert_eq!(cfg.transport.max_pool_count, 10);
    }
}
