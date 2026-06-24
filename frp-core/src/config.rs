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
}

fn default_allow_port_start() -> u16 { 10000 }
fn default_allow_port_end() -> u16 { 50000 }

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
            sub_domain_host: String::new(),
            websocket_port: 0,
            tls_enable: false,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            tls_ca_file: String::new(),
            auth: AuthServerConfig::default(),
            log: LogConfig::default(),
            web_server: WebServerConfig::default(),
            transport: ServerTransportConfig::default(),
            allow_port_start: default_allow_port_start(),
            allow_port_end: default_allow_port_end(),
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
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            method: "token".into(),
            token: String::new(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
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
fn default_max_days() -> i32 { 3 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebServerConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            port: 0,
            user: String::new(),
            password: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerTransportConfig {
    #[serde(default)]
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
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            plugin_type: String::new(),
            http_user: String::new(),
            http_password: String::new(),
            local_addr: String::new(),
            local_path: String::new(),
            strip_prefix: String::new(),
            host_header_rewrite: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }
}


// ---------------------------------------------------------------
// Client Configuration
// ---------------------------------------------------------------

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
    #[serde(default)]
    pub tcp_mux: bool,
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".into(),
            server_port: default_server_port(),
            transport_protocol: default_transport_protocol(),
            token: String::new(),
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
        }
    }
}

fn default_server_port() -> u16 { 7000 }
fn default_transport_protocol() -> String { "tcp".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub health_check_interval_seconds: u64,
    #[serde(default)]
    pub health_check_timeout_seconds: u64,
    #[serde(default)]
    pub health_check_max_failed: u32,
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
        for key in ["web_server_addr", "web_server_port", "web_server_user", "web_server_password"] {
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
        } else if path.extension().map_or(false, |ext| ext == "toml" || ext == "ini") {
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
}
