use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------
// Server Configuration
// ---------------------------------------------------------------

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
    #[serde(default)]
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
    /// When true, the main bind_port only accepts TLS connections.
    /// Plain TCP and WebSocket upgrades are rejected.
    /// The client must have tls_enable = true to connect.
    #[serde(default)]
    pub tls_only: bool,
    #[serde(default)]
    pub auth: AuthServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
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
    #[serde(default)]
    pub max_ports_per_client: u64,
    /// Timeout in seconds for backend HTTP response in VHost handler.
    /// Go frp compat: VhostHTTPTimeout. Default: 60.
    #[serde(default = "default_vhost_http_timeout")]
    pub vhost_http_timeout: u64,
    /// Idle timeout in seconds on user-facing proxy connections.
    /// Go frp compat: UserConnTimeout. Default: 10.
    #[serde(default = "default_user_conn_timeout")]
    pub user_conn_timeout: u64,
    /// When false (default), internal error details are replaced with generic
    /// messages in client-facing error responses. When true, full Rust error
    /// details are included. Go frp compat: detailedErrorsToClient. Default: false.
    #[serde(default)]
    pub detailed_errors_to_client: bool,
    /// Maximum time in seconds to wait for active connections to drain
    /// during graceful shutdown. After this timeout, remaining connections
    /// are force-closed. Default: 30.
    #[serde(default = "default_graceful_timeout")]
    pub graceful_shutdown_timeout: u64,
    /// When tcp_mux is enabled and yamux init fails, forward raw bytes
    /// to the VHost handler instead of closing the connection.
    /// Go frp compat: TCPMuxPassthrough. Default: false.
    #[serde(default)]
    pub tcp_mux_passthrough: bool,
    /// UDP packet buffer size in bytes. Controls the receive buffer for UDP
    /// proxy datagrams. Default: 65535 (max UDP datagram size).
    /// Go frp compat: udp_packet_size.
    #[serde(default = "default_udp_packet_size")]
    pub udp_packet_size: usize,
    /// Server-side HTTP plugin configurations. Each plugin is an external
    /// HTTP service called on lifecycle events (login, new_proxy, close_proxy).
    /// Go frp compat: http_plugins.
    #[serde(default)]
    pub http_plugins: Vec<HttpPluginConfig>,
    /// Experimental feature gates. Go frp compat: [feature] section.
    #[serde(default)]
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
    /// Go frp compat: natholeAnalysisDataReserveHours. Default: 1 (hour).
    #[serde(default = "default_nathole_analysis_data_reserve_hours")]
    pub nat_hole_analysis_data_reserve_hours: u64,
    /// OpenTelemetry / observability settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

fn default_allow_port_start() -> u16 { 10000 }
fn default_allow_port_end() -> u16 { 50000 }
fn default_vhost_http_timeout() -> u64 { 60 }
fn default_user_conn_timeout() -> u64 { 10 }
fn default_udp_packet_size() -> usize { 65535 }
fn default_nathole_analysis_data_reserve_hours() -> u64 { 1 }
fn default_graceful_timeout() -> u64 { 30 }
fn default_authentication_timeout() -> i64 { 15 }

/// Parse a bandwidth limit string like "1MB", "500KB", "100K".
/// Returns bytes per second, or None if unparseable.
/// Supports suffixes: K/KB, M/MB, G/GB (case-insensitive).
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let s = s.trim().to_uppercase();
    let (num_str, mult) = if let Some(rest) = s.strip_suffix("GB") {
        (rest.trim(), 1_073_741_824u64)
    } else if let Some(rest) = s.strip_suffix('G') {
        (rest.trim(), 1_073_741_824u64)
    } else if let Some(rest) = s.strip_suffix("MB") {
        (rest.trim(), 1_048_576u64)
    } else if let Some(rest) = s.strip_suffix('M') {
        (rest.trim(), 1_048_576u64)
    } else if let Some(rest) = s.strip_suffix("KB") {
        (rest.trim(), 1024u64)
    } else if let Some(rest) = s.strip_suffix('K') {
        (rest.trim(), 1024u64)
    } else {
        (&s[..], 1u64)
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
    ranges.iter().fold(0u32, |acc, (s, e)| {
        acc.saturating_add(e.saturating_sub(*s) as u32 + 1)
    }).min(u16::MAX as u32) as u16
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
            tls_only: false,
            auth: AuthServerConfig::default(),
            log: LogConfig::default(),
            web_server: WebServerConfig::default(),
            transport: ServerTransportConfig::default(),
            allow_port_start: default_allow_port_start(),
            allow_port_end: default_allow_port_end(),
            allow_ports: String::new(),
            max_ports_per_client: 50,
            vhost_http_timeout: default_vhost_http_timeout(),
            user_conn_timeout: default_user_conn_timeout(),
            tcp_mux_passthrough: false,
            detailed_errors_to_client: false,
            udp_packet_size: default_udp_packet_size(),
            http_plugins: Vec::new(),
            feature: FeatureConfig::default(),
            includes: Vec::new(),
            ssh_tunnel_gateway: SshTunnelGatewayConfig::default(),
            nat_hole_analysis_data_reserve_hours: default_nathole_analysis_data_reserve_hours(),
            observability: ObservabilityConfig::default(),
            graceful_shutdown_timeout: default_graceful_timeout(),
        }
    }
}

fn default_bind_addr() -> String { "0.0.0.0".into() }
fn default_bind_port() -> u16 { 7000 }
fn default_fallback_timeout_ms() -> u64 { 5000 }

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
    #[serde(default = "default_autogen_ssh_key_path", alias = "autoGenPrivateKeyPath")]
    pub auto_gen_private_key_path: String,

    /// Path to SSH authorized_keys for optional public key auth.
    /// Empty = password auth only.
    #[serde(default, alias = "authorizedKeysFile")]
    pub authorized_keys_file: String,
}

fn default_autogen_ssh_key_path() -> String { "./.autogen_ssh_key".into() }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthServerConfig {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub oidc_issuer: String,
    #[serde(default)]
    pub oidc_audience: String,
    #[serde(default)]
    pub oidc_token_endpoint: String,
    #[serde(default, alias = "oidcSkipExpiry")]
    pub oidc_skip_expiry: bool,
    #[serde(default, alias = "oidcSkipIssuer")]
    pub oidc_skip_issuer: bool,
    /// HTTP/SOCKS5 proxy URL for OIDC HTTP client connections.
    /// Go frp compat: oidcProxyURL.
    #[serde(default, alias = "oidcProxyURL")]
    pub oidc_proxy_url: String,
    /// Additional auth scopes: "HeartBeats", "NewWorkConns".
    /// When listed, corresponding message types require authentication.
    /// Go frp compat: additionalAuthScopes.
    #[serde(default, alias = "additionalAuthScopes")]
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection,
    /// in seconds. 0 disables the check. Default: 15.
    /// Go frp v0.69.1 default: 900. This implementation defaults to 15
    /// for tighter replay protection.
    /// Go frp compat: authentication_timeout.
    #[serde(default = "default_authentication_timeout", alias = "authenticationTimeout")]
    pub authentication_timeout: i64,
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
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            oidc_proxy_url: String::new(),
            additional_auth_scopes: Vec::new(),
            authentication_timeout: 15,
            use_encryption: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: String,
    #[serde(default = "default_max_days")]
    pub max_days: i32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: String::new(),
            max_days: default_max_days(),
        }
    }
}

fn default_log_level() -> String { "info".into() }
fn default_health_check_url() -> String { "/".into() }
fn default_max_days() -> i32 { 3 }

/// OpenTelemetry / observability configuration.
/// When `otlp_endpoint` is empty (default), OTel export is disabled even when
/// the `otel` feature is compiled in. The `OTEL_EXPORTER_OTLP_ENDPOINT`
/// environment variable takes precedence over this config field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub otlp_endpoint: String,
    #[serde(default)]
    pub service_name: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct WebServerConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub enable_prometheus: bool,
    /// TLS certificate file path. When both tls_cert_file and tls_key_file
    /// are non-empty, dashboard/admin server starts with TLS.
    #[serde(default)]
    pub tls_cert_file: String,
    /// TLS private key file path.
    #[serde(default)]
    pub tls_key_file: String,
    /// Custom 404 page body (HTML). When non-empty, VHost and TCPMux
    /// 404 responses include this content with Content-Type: text/html.
    /// Go frp compat: custom_404_page.
    #[serde(default)]
    pub custom_404_page: String,
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
}

fn default_plugin_timeout() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTransportConfig {
    #[serde(default = "default_true")]
    pub tcp_mux: bool,
    #[serde(default)]
    pub tcp_mux_keepalive_interval: i64,
    /// Heartbeat timeout in seconds. Server disconnects if no Ping
    /// received within this interval. Default: 90.
    /// Go frp compat: transport.heartbeatTimeout.
    #[serde(default = "default_heartbeat_timeout", alias = "heartbeatTimeout")]
    pub heartbeat_timeout: i64,
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 30,
            heartbeat_timeout: default_heartbeat_timeout(),
        }
    }
}

fn default_heartbeat_timeout() -> i64 { 90 }
// ---------------------------------------------------------------
// Plugin Configuration
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct PluginConfig {
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(default, alias = "httpUser")]
    pub http_user: String,
    #[serde(default, alias = "httpPassword")]
    pub http_password: String,
    #[serde(default, alias = "localAddr")]
    pub local_addr: String,
    #[serde(default, alias = "localPath")]
    pub local_path: String,
    #[serde(default, alias = "stripPrefix")]
    pub strip_prefix: String,
    #[serde(default, alias = "hostHeaderRewrite")]
    pub host_header_rewrite: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// TLS certificate file for plugin listener (https2http, https2https).
    #[serde(default, alias = "pluginCrtPath", alias = "plugin_crt_path")]
    pub crt_file: String,
    /// TLS key file for plugin listener (https2http, https2https).
    #[serde(default, alias = "pluginKeyPath", alias = "plugin_key_path")]
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

/// Client-side authentication configuration ([auth] section in frpc.toml).
/// Mirrors Go frp v0.69.1 AuthClientConfig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClientConfig {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub token: String,
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
    #[serde(default, alias = "additionalAuthScopes")]
    pub additional_auth_scopes: Vec<String>,
    /// Maximum allowed clock skew for timestamp-based replay protection
    /// (server-side only; client ignores this field). 0 disables the check.
    /// Go frp compat: authentication_timeout.
    #[serde(default = "default_authentication_timeout", alias = "authenticationTimeout")]
    pub authentication_timeout: i64,
}

impl Default for AuthClientConfig {
    fn default() -> Self {
        Self {
            method: "token".into(),
            token: String::new(),
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
            authentication_timeout: 15,
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
    #[serde(default)]
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
    /// Go frp compat: natHoleStunServer.
    #[serde(default, alias = "natHoleStunServer")]
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
    #[serde(default)]
    pub tls_enable: bool,
    #[serde(default)]
    pub tls_cert_file: String,
    #[serde(default)]
    pub tls_key_file: String,
    #[serde(default)]
    pub tls_ca_file: String,
    #[serde(default)]
    pub tls_server_name: String,
    /// Disable the custom TLS head byte (0x17) written before the TLS handshake.
    /// When true, the client skips the Go frp protocol marker and starts TLS directly.
    /// Go frp compat: disableCustomTLSFirstByte.
    #[serde(default, alias = "disableCustomTLSFirstByte")]
    pub disable_custom_tls_first_byte: bool,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub login_fail_exit: bool,
    #[serde(default)]
    pub pool_count: i32,
    /// Ping interval in seconds. Client sends a heartbeat Ping at this
    /// interval. Default: 30. Go frp compat: transport.heartbeatInterval.
    #[serde(default = "default_heartbeat_interval", alias = "heartbeatInterval")]
    pub heartbeat_interval: i64,
    #[serde(default)]
    pub dns_server: String,
    /// TCP keepalive interval in seconds for outbound connections to the
    /// frp server. 0 disables. Go frp compat: dialServerKeepalive.
    #[serde(default, alias = "dialServerKeepalive")]
    pub dial_server_keepalive: i64,
    /// Local IP address to bind when dialing the frp server.
    /// Empty means use system default. Go frp compat: connectServerLocalIP.
    #[serde(default, alias = "connectServerLocalIP")]
    pub connect_server_local_ip: String,
    #[serde(default = "default_true")]
    pub tcp_mux: bool,
    /// Use V2 protocol framing (binary header + JSON payload).
    /// Requires tcp_mux for yamux multiplexing. Default: false.
    #[serde(default)]
    pub v2: bool,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,
    #[serde(default)]
    pub web_server: WebServerConfig,
    /// Experimental feature gates. Go frp compat: [feature] section.
    #[serde(default)]
    pub feature: FeatureConfig,
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
            nat_hole_stun_server: String::new(),
            start: Vec::new(),
            includes: Vec::new(),
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            disable_custom_tls_first_byte: false,
            log: LogConfig::default(),
            login_fail_exit: true,
            pool_count: 0,
            heartbeat_interval: default_heartbeat_interval(),
            dns_server: String::new(),
            dial_server_keepalive: 0,
            connect_server_local_ip: String::new(),
            tcp_mux: true,
            v2: false,
            proxies: vec![],
            visitors: vec![],
            web_server: WebServerConfig::default(),
            feature: FeatureConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

fn default_server_port() -> u16 { 7000 }
fn default_transport_protocol() -> String { "tcp".into() }
fn default_true() -> bool { true }
fn default_heartbeat_interval() -> i64 { 30 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    #[serde(default, alias = "localIp")]
    pub local_ip: String,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default, alias = "remotePort")]
    pub remote_port: u16,
    #[serde(default)]
    pub use_encryption: bool,
    #[serde(default)]
    pub use_compression: bool,
    #[serde(default)]
    pub sk: String,
    #[serde(default)]
    pub plugin: Option<PluginConfig>,
    #[serde(default)]
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
    #[serde(default, alias = "bandwidthLimitMode")]
    pub bandwidth_limit_mode: String,
    #[serde(default)]
    pub annotations: std::collections::HashMap<String, String>,
    #[serde(default)]
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
    #[serde(default)]
    pub health_check_interval_seconds: u64,
    #[serde(default)]
    pub health_check_timeout_seconds: u64,
    #[serde(default)]
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
}

/// STCP/XTCP visitor configuration — used by frpc to expose a local port
/// that tunnels traffic to a remote STCP/XTCP proxy through the frps server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// Optional server user for auth matching.
    #[serde(default, alias = "serverUser")]
    pub server_user: String,
    /// Local address to bind for accepting connections.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Local port for the visitor listener (0 = disabled).
    #[serde(default, alias = "bindPort")]
    pub bind_port: u16,
    /// Fallback timeout in milliseconds before switching from XTCP to STCP.
    /// Go frp compat: fallbackTimeoutMs. Default: 5000 (5 seconds).
    #[serde(default = "default_fallback_timeout_ms")]
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
    #[serde(default)]
    pub use_encryption: bool,
    /// Compress the tunnel traffic.
    #[serde(default)]
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
    /// Go frp compat: minRetryInterval. Default: 30.
    #[serde(default = "default_min_retry_interval", alias = "minRetryInterval")]
    pub min_retry_interval: i64,
}


fn default_max_retries_an_hour() -> i32 { 8 }
fn default_min_retry_interval() -> i64 { 30 }
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
pub fn load_server_config_from_str(content: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value = toml::from_str(content)?;
    normalize_server_config(&mut value);
    let json_value = toml_to_json(value);
    let cfg: ServerConfig = serde_json::from_value(json_value)?;
    Ok(cfg)
}

pub fn load_client_config_from_str(content: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut value: toml::Value = toml::from_str(content)?;
    normalize_client_config(&mut value);
    let cfg: ClientConfig = serde_json::from_value(toml_to_json(value))?;
    Ok(cfg)
}


/// Convert a toml::Value to a serde_json::Value for deserialization.
/// This is needed because toml::Value can't be directly deserialized into
/// arbitrary Rust types (the round-trip through toml::to_string produces
/// invalid TOML for inline tables).
fn toml_to_json(v: toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::Number(i.into()),
        toml::Value::Float(f) => {
            serde_json::Number::from_f64(f).map_or_else(
                || {
                    tracing::warn!(float = %f, "NaN/Inf float value in TOML config replaced with null");
                    serde_json::Value::Null
                },
                serde_json::Value::Number,
            )
        }
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

#[allow(clippy::collapsible_match)]
fn normalize_server_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section: merge into top level
        if let Some(common) = table.remove("common") {
            if let Value::Table(common_table) = common {
                for (k, v) in common_table {
                    table.entry(k).or_insert(v);
                }
            }
        }

        // Move bare `token` into [auth] table as well
        if let Some(v) = table.remove("token") {
            let auth_table = table.entry("auth").or_insert_with(|| toml::Value::Table(Default::default()));
            if let toml::Value::Table(ref mut t) = auth_table {
                t.entry("token".to_string()).or_insert(v);
            }
        }

        // Flatten auth_* fields into auth table
        let mut auth_items: Vec<(String, Value)> = Vec::new();
        for key in ["auth_method", "auth_token", "token", "oidc_issuer", "oidc_audience", "oidc_token_endpoint"] {
            if let Some(v) = table.remove(key) {
                let sub_key = key.strip_prefix("auth_").or_else(|| key.strip_prefix("oidc_")).unwrap_or(key);
                auth_items.push((sub_key.to_string(), v));
            }
        }
        if !auth_items.is_empty() {
            let auth_table = table.entry("auth").or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(ref mut t) = auth_table {
                for (k, v) in auth_items {
                    t.entry(k).or_insert(v);
                }
            }
        }

        // Flatten log_* fields into log table
        let mut log_items: Vec<(String, Value)> = Vec::new();
        for key in ["log_file", "log_level", "log_max_days"] {
            if let Some(v) = table.remove(key) {
                let sub_key = key.strip_prefix("log_").unwrap_or(key);
                log_items.push((sub_key.to_string(), v));
            }
        }
        if !log_items.is_empty() {
            let log_table = table.entry("log").or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(ref mut t) = log_table {
                for (k, v) in log_items {
                    t.entry(k).or_insert(v);
                }
            }
        }

        // Flatten web_server_* fields into web_server table
        let mut ws_items: Vec<(String, Value)> = Vec::new();
        for key in ["web_server_addr", "web_server_port", "web_server_user", "web_server_password", "web_server_enable_prometheus", "enable_prometheus", "web_server_tls_cert_file", "web_server_tls_key_file"] {
            if let Some(v) = table.remove(key) {
                let sub_key = key.strip_prefix("web_server_").unwrap_or(key);
                ws_items.push((sub_key.to_string(), v));
            }
        }
        if !ws_items.is_empty() {
            let ws_table = table.entry("web_server").or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(ref mut t) = ws_table {
                for (k, v) in ws_items {
                    t.entry(k).or_insert(v);
                }
            }
        }

        // Flatten transport_* fields into transport table
        // Also handle flat tcp_mux, tcp_mux_keepalive_interval at top level
        let mut tr_items: Vec<(String, Value)> = Vec::new();
        for key in ["tcp_mux", "tcp_mux_keepalive_interval"] {
            if let Some(v) = table.remove(key) {
                tr_items.push((key.to_string(), v));
            }
        }
        if !tr_items.is_empty() {
            let tr_table = table.entry("transport").or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(ref mut t) = tr_table {
                for (k, v) in tr_items {
                    t.entry(k).or_insert(v);
                }
            }
        }

        // Normalize camelCase section names to snake_case
        if let Some(ssh_section) = table.remove("sshTunnelGateway") {
            table.entry("ssh_tunnel_gateway").or_insert(ssh_section);
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

        // Extract token from [auth] table (Go frp uses auth.token, auth.method)
        if let Some(Value::Table(auth_table)) = table.remove("auth") {
            if let Some(token_val) = auth_table.get("token") {
                table.entry("token").or_insert(token_val.clone());
            }
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
                    table.entry(k).or_insert(v);
                }
            }
        }

        // Flatten log_* fields into log table (client side)
        let mut log_items: Vec<(String, Value)> = Vec::new();
        for key in ["log_file", "log_level", "log_max_days"] {
            if let Some(v) = table.remove(key) {
                let sub_key = key.strip_prefix("log_").unwrap_or(key);
                log_items.push((sub_key.to_string(), v));
            }
        }
        if !log_items.is_empty() {
            let log_table = table.entry("log").or_insert_with(|| Value::Table(Default::default()));
            if let Value::Table(ref mut t) = log_table {
                for (k, v) in log_items {
                    t.entry(k).or_insert(v);
                }
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
    let content = std::fs::read_to_string(path)?;
    let format = detect_format(path);
    let mut value: toml::Value = parse_to_toml_value(&content, format)?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir)?;
    normalize_server_config(&mut value);
    if strict_config {
        run_strict_check(&value, &known_server_keys(), path)?;
    }
    let json_value = toml_to_json(value);
    let cfg: ServerConfig = serde_json::from_value(json_value)?;
    Ok(cfg)
}

/// Load a client configuration from a file path, auto-detecting format by extension.
/// When `strict_config` is true, unknown fields cause an error (Go frp default).
pub fn load_client_config(
    path: &str,
    strict_config: bool,
) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let format = detect_format(path);
    let mut value: toml::Value = parse_to_toml_value(&content, format)?;
    let base_dir = Path::new(path).parent().unwrap_or(Path::new("."));
    process_includes(&mut value, base_dir)?;
    normalize_client_config(&mut value);
    if strict_config {
        run_strict_check(&value, &known_client_keys(), path)?;
    }
    let cfg: ClientConfig = serde_json::from_value(toml_to_json(value))?;
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
    let patterns: Vec<String> = match table.remove("includes")
        .or_else(|| table.remove("include"))
    {
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
pub fn collect_config_files(dir: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_config_files_inner(dir, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_config_files_inner(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", dir.display()).into());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_config_files_inner(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "toml" || ext == "ini" || ext == "json") {
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

fn parse_to_toml_value(content: &str, format: ConfigFormat) -> Result<toml::Value, Box<dyn std::error::Error>> {
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
            let table: toml::Table = map.into_iter()
                .map(|(k, v)| (k, json_to_toml(v)))
                .collect();
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
        let parts: Vec<toml::Value> = s.split(',')
            .map(|p| infer_ini_value(p.trim()))
            .collect();
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

fn known_server_keys() -> std::collections::HashSet<&'static str> {
    use std::collections::HashSet;
    let mut keys = HashSet::new();
    keys.extend([
        "bind_addr", "bind_port", "proxy_bind_addr", "vhost_http_port",
        "vhost_https_port", "kcp_bind_port", "quic_bind_port", "sudp_port",
        "tcpmux_httpconnect_port", "sub_domain_host", "websocket_port",
        "tls_enable", "tls_cert_file", "tls_key_file", "tls_ca_file",
        "tls_only", "auth", "log", "web_server", "transport",
        "allow_port_start", "allow_port_end", "allow_ports",
        "max_ports_per_client", "vhost_http_timeout", "user_conn_timeout",
        "detailed_errors_to_client", "tcp_mux_passthrough", "udp_packet_size",
        "http_plugins", "feature", "includes", "ssh_tunnel_gateway",
        "nat_hole_analysis_data_reserve_hours", "observability",
    ]);
    // Go compat normalization aliases
    keys.extend([
        "common", "auth_method", "auth_token", "token", "oidc_issuer",
        "oidc_audience", "oidc_token_endpoint", "log_file", "log_level",
        "log_max_days", "web_server_addr", "web_server_port",
        "web_server_user", "web_server_password", "web_server_enable_prometheus",
        "web_server_tls_cert_file", "web_server_tls_key_file",
        "enable_prometheus", "tcp_mux", "tcp_mux_keepalive_interval",
        "sshTunnelGateway", "bindPort", "bindAddr",
        "vhostHTTPPort", "vhostHTTPSPort", "kcpBindPort", "quicBindPort",
        "sudpPort", "tcpmuxHTTPConnectPort", "proxyBindAddr",
        "websocketPort",
    ]);
    keys
}

fn known_client_keys() -> std::collections::HashSet<&'static str> {
    use std::collections::HashSet;
    let mut keys = HashSet::new();
    keys.extend([
        "server_addr", "server_port", "transport_protocol", "token",
        "auth", "user", "client_id", "metas", "metadatas",
        "proxy_url", "proxyURL", "nat_hole_stun_server", "natHoleStunServer",
        "start", "includes", "include",
        "tls_enable", "tls_cert_file", "tls_key_file", "tls_ca_file",
        "tls_server_name", "disable_custom_tls_first_byte",
        "disableCustomTLSFirstByte", "log", "login_fail_exit",
        "pool_count", "heartbeat_interval", "heartbeatInterval",
        "dns_server", "dial_server_keepalive", "dialServerKeepalive",
        "connect_server_local_ip", "connectServerLocalIP",
        "tcp_mux", "v2", "proxies", "visitors", "web_server",
        "feature", "common", "protocol", "tls_trusted_ca_file",
        "serverAddr", "serverPort", "transport",
        "log_file", "log_level", "log_max_days", "observability",
    ]);
    keys
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
                errors.push(format!(
                    "unknown field \"{}\" in config file {}", full_key, config_path
                ));
            }
        }
    }
    errors
}

/// Load server configs from a directory, merging all `.toml` files.

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(cfg.kcp_bind_port, 7100, "kcpBindPort");
        assert_eq!(cfg.vhost_http_port, 10080, "vhostHTTPPort");
        assert_eq!(cfg.vhost_https_port, 10443, "vhostHTTPSPort");
        assert_eq!(cfg.quic_bind_port, 7200, "quicBindPort");
        assert_eq!(cfg.sudp_port, 7300, "sudpPort");
        assert_eq!(cfg.tcpmux_httpconnect_port, 7400, "tcpmuxHTTPConnectPort");
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
        // Empty/zero → None (no limit)
        assert_eq!(parse_bandwidth_limit(""), None);
        assert_eq!(parse_bandwidth_limit("0"), None);

        // KB variants (binary: 1KB = 1024)
        assert_eq!(parse_bandwidth_limit("1KB"), Some(1024));
        assert_eq!(parse_bandwidth_limit("1K"), Some(1024));

        // MB variants
        assert_eq!(parse_bandwidth_limit("1MB"), Some(1_048_576));
        assert_eq!(parse_bandwidth_limit("1M"), Some(1_048_576));

        // GB variant
        assert_eq!(parse_bandwidth_limit("1GB"), Some(1_073_741_824));

        // Plain bytes
        assert_eq!(parse_bandwidth_limit("500"), Some(500));

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
        assert_eq!(cfg.ssh_tunnel_gateway.private_key_file, "/etc/frp/ssh_host_key");
        assert_eq!(cfg.ssh_tunnel_gateway.auto_gen_private_key_path, "/var/lib/frp/ssh_key");
        assert_eq!(cfg.ssh_tunnel_gateway.authorized_keys_file, "/etc/frp/authorized_keys");
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
            assert!(norm.contains("[auth]"), "token should be promoted into [auth]: {norm}");
            assert!(norm.contains("token = \"my-secret\""), "token value missing: {norm}");
        }

        #[test]
        fn server_ssh_tunnel_gateway_rename() {
            let input = "bind_port = 7000\n[sshTunnelGateway]\nbindPort = 2200\n";
            let norm = super::normalize_server_toml(input);
            assert!(norm.contains("ssh_tunnel_gateway"),
                "sshTunnelGateway not renamed: {norm}");
            assert!(!norm.contains("sshTunnelGateway"),
                "old sshTunnelGateway key still present: {norm}");
        }

        #[test]
        fn client_tls_trusted_ca_rename() {
            let input = "server_addr = \"x\"\nserver_port = 7000\ntls_trusted_ca_file = \"/certs/ca.pem\"\n";
            let norm = super::normalize_client_toml(input);
            assert!(norm.contains("tls_ca_file"),
                "tls_trusted_ca_file not renamed to tls_ca_file: {norm}");
            assert!(!norm.contains("tls_trusted_ca_file"),
                "old tls_trusted_ca_file key still present: {norm}");
        }

        #[test]
        fn server_enable_prometheus_to_web_server() {
            let input = "bind_port = 7000\nenable_prometheus = true\n";
            let norm = super::normalize_server_toml(input);
            assert!(norm.contains("[web_server]"),
                "enable_prometheus should create [web_server]: {norm}");
            assert!(norm.contains("enable_prometheus"),
                "enable_prometheus value missing: {norm}");
        }

        #[test]
        fn client_transport_wire_protocol_v2() {
            let input = "server_addr = \"x\"\nserver_port = 7000\n[transport]\nwireProtocol = \"v2\"\n";
            let norm = super::normalize_client_toml(input);
            assert!(norm.contains("v2 = true"),
                "wireProtocol=v2 not converted to v2=true: {norm}");
        }
    }
}
