use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub local_ip: String,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub use_encryption: bool,
    #[serde(default)]
    pub use_compression: bool,
    #[serde(default)]
    pub sk: String,
    #[serde(default)]
    pub plugin: String,
    #[serde(default)]
    pub custom_domains: Vec<String>,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub http_user: String,
    #[serde(default)]
    pub http_password: String,
    #[serde(default)]
    pub locations: Vec<String>,
    #[serde(default)]
    pub host_header_rewrite: String,
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

/// Load a TOML server configuration from a file path.
pub fn load_server_config(path: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let cfg: ServerConfig = toml::from_str(&content)?;
    Ok(cfg)
}

/// Load a TOML client configuration from a file path.
pub fn load_client_config(path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let cfg: ClientConfig = toml::from_str(&content)?;
    Ok(cfg)
}

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
}
