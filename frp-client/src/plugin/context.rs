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
}
