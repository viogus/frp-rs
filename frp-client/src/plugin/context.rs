use std::sync::Arc;

/// Connection context passed to plugins needing server connectivity.
#[derive(Clone)]
pub struct PluginContext {
    pub server_addr: String,
    pub server_port: u16,
    pub transport_protocol: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub token: String,
    pub oidc_client: Option<Arc<frp_core::auth::OidcClient>>,
    // Transport options matching DialOptions / Go frp connector.
    pub tcp_mux: bool,
    pub tcp_mux_keepalive_interval: i64,
    pub proxy_url: Option<String>,
    pub dns_server: Option<String>,
    pub dial_timeout_secs: u64,
    pub keepalive_secs: u64,
    pub connect_bind_addr: Option<String>,
    pub disable_custom_tls_first_byte: bool,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
}
