use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------
// Server Configuration
// ---------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    #[serde(default)]
    pub proxy_bind_addr: String,
    #[serde(default)]
    pub vhost_http_port: u16,
    #[serde(default)]
    pub vhost_https_port: u16,
    #[serde(default)]
    pub kcp_bind_port: u16,
    #[serde(default)]
    pub quic_bind_port: u16,
    /// Shared UDP port for SUDP proxies. When > 0, SUDP proxies
    /// share this port instead of allocating individual ports.
    #[serde(default)]
    pub sudp_port: u16,
    /// Port for tcpmux HTTP CONNECT multiplexing. When > 0, TCPMux
    /// proxies share this port via HTTP CONNECT Host header routing.
    #[serde(default)]
    pub tcpmux_httpconnect_port: u16,
    #[serde(default)]
    pub sub_domain_host: String,
    #[serde(default)]
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
    /// Timeout in seconds for backend HTTP response in VHost handler.
    /// Go frp compat: VhostHTTPTimeout. Default: 60.
    #[serde(default = "default_vhost_http_timeout")]
    pub vhost_http_timeout: u64,
    /// Idle timeout in seconds on user-facing proxy connections.
    /// Go frp compat: UserConnTimeout. Default: 10.
    #[serde(default = "default_user_conn_timeout")]
    pub user_conn_timeout: u64,
    /// When tcp_mux is enabled and yamux init fails, forward raw bytes
    /// to the VHost handler instead of closing the connection.
    /// Go frp compat: TCPMuxPassthrough. Default: false.
    #[serde(default)]
    pub tcp_mux_passthrough: bool,
    /// Server-side HTTP plugin configurations. Each plugin is an external
    /// HTTP service called on lifecycle events (login, new_proxy, close_proxy).
    /// Go frp compat: http_plugins.
    #[serde(default)]
    pub http_plugins: Vec<HttpPluginConfig>,
}

fn default_allow_port_start() -> u16 { 10000 }
fn default_allow_port_end() -> u16 { 50000 }
fn default_vhost_http_timeout() -> u64 { 60 }
fn default_user_conn_timeout() -> u64 { 10 }

/// Parse a bandwidth limit string like "1MB", "500KB", "100K".
/// Returns bytes per second, or None if unparseable.
/// Supports suffixes: K/KB, M/MB, G/GB (case-insensitive).
pub fn parse_bandwidth_limit(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let s = s.trim().to_uppercase();
    let (num_str, mult) = if let Some(rest) = s.strip_suffix("GB") {
        (rest.trim(), 1_000_000_000u64)
    } else if let Some(rest) = s.strip_suffix('G') {
        (rest.trim(), 1_000_000_000u64)
    } else if let Some(rest) = s.strip_suffix("MB") {
        (rest.trim(), 1_000_000u64)
    } else if let Some(rest) = s.strip_suffix('M') {
        (rest.trim(), 1_000_000u64)
    } else if let Some(rest) = s.strip_suffix("KB") {
        (rest.trim(), 1000u64)
    } else if let Some(rest) = s.strip_suffix('K') {
        (rest.trim(), 1000u64)
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
            kcp_bind_port: 0,
            quic_bind_port: 0,
            sudp_port: 0,
            tcpmux_httpconnect_port: 0,
            sub_domain_host: String::new(),
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
            vhost_http_timeout: default_vhost_http_timeout(),
            user_conn_timeout: default_user_conn_timeout(),
            tcp_mux_passthrough: false,
            http_plugins: Vec::new(),
        }
    }
}

fn default_bind_addr() -> String { "0.0.0.0".into() }
fn default_bind_port() -> u16 { 7000 }

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
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            tcp_mux: true,
            tcp_mux_keepalive_interval: 30,
        }
    }
}
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
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub login_fail_exit: bool,
    #[serde(default)]
    pub pool_count: i32,
    #[serde(default)]
    pub dns_server: String,
    #[serde(default = "default_true")]
    pub tcp_mux: bool,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub visitors: Vec<VisitorConfig>,
    #[serde(default)]
    pub web_server: WebServerConfig,
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
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            tls_server_name: String::new(),
            log: LogConfig::default(),
            login_fail_exit: true,
            pool_count: 0,
            dns_server: String::new(),
            tcp_mux: true,
            proxies: vec![],
            visitors: vec![],
            web_server: WebServerConfig::default(),
        }
    }
}

fn default_server_port() -> u16 { 7000 }
fn default_transport_protocol() -> String { "tcp".into() }
fn default_true() -> bool { true }

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
    #[serde(default)]
    pub health_check_interval_seconds: u64,
    #[serde(default)]
    pub health_check_timeout_seconds: u64,
    #[serde(default)]
    pub health_check_max_failed: u32,
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
    /// Optional server user for auth matching.
    #[serde(default, alias = "serverUser")]
    pub server_user: String,
    /// Local address to bind for accepting connections.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Local port for the visitor listener (0 = disabled).
    #[serde(default, alias = "bindPort")]
    pub bind_port: u16,
    /// Fallback visitor name if this one fails.
    #[serde(default, alias = "fallbackTo")]
    pub fallback_to: String,
    /// Encrypt the tunnel traffic.
    #[serde(default)]
    pub use_encryption: bool,
    /// Compress the tunnel traffic.
    #[serde(default)]
    pub use_compression: bool,
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
            serde_json::Number::from_f64(f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
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
        for key in ["web_server_addr", "web_server_port", "web_server_user", "web_server_password", "web_server_enable_prometheus", "enable_prometheus"] {
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
    }
}

fn normalize_client_config(value: &mut toml::Value) {
    use toml::Value;
    if let Some(table) = value.as_table_mut() {
        // Handle [common] section
        if let Some(common) = table.remove("common") {
            if let Value::Table(common_table) = common {
                for (k, v) in common_table {
                    table.entry(k).or_insert(v);
                }
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
        if let Some(v) = table.remove("auth") {
            if let Value::Table(auth_table) = v {
                if let Some(token_val) = auth_table.get("token") {
                    table.entry("token").or_insert(token_val.clone());
                }
            }
        }

        // Flatten [transport] section → top-level (ClientConfig has tcp_mux at top level,
        // but Go frp config puts it under [transport])
        if let Some(v) = table.remove("transport") {
            if let Value::Table(tr_table) = v {
                for (k, v) in tr_table {
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

/// Load a TOML server configuration from a file path.
pub fn load_server_config(path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    load_server_config_from_str(&content)
}

/// Load a TOML client configuration from a file path.
pub fn load_client_config(path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    load_client_config_from_str(&content)
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
        } else if path.extension().is_some_and(|ext| ext == "toml" || ext == "ini") {
            files.push(path);
        }
    }
    Ok(())
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

        // KB variants (decimal: 1KB = 1000)
        assert_eq!(parse_bandwidth_limit("1KB"), Some(1000));
        assert_eq!(parse_bandwidth_limit("1K"), Some(1000));

        // MB variants
        assert_eq!(parse_bandwidth_limit("1MB"), Some(1_000_000));
        assert_eq!(parse_bandwidth_limit("1M"), Some(1_000_000));

        // GB variant
        assert_eq!(parse_bandwidth_limit("1GB"), Some(1_000_000_000));

        // Plain bytes
        assert_eq!(parse_bandwidth_limit("500"), Some(500));

        // Case insensitive (input uppercased internally)
        assert_eq!(parse_bandwidth_limit("1mb"), Some(1_000_000));
        assert_eq!(parse_bandwidth_limit("1kb"), Some(1000));

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
}
