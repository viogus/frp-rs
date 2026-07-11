pub mod msg;
pub mod proxy_protocol;
pub mod backoff;
pub mod config_store;
pub mod system;
pub mod protocol;
pub mod transport;
pub mod auth;
pub mod config;
pub mod encryption;
pub mod cipher_stream;
pub mod mux;
pub mod buffer_pool;
pub mod bridge;
pub mod bandwidth;
pub mod metrics;
#[cfg(feature = "admin-auth")]
pub mod admin_auth;
pub mod cli;
#[cfg(feature = "kcp")]
pub mod kcp;
#[cfg(feature = "kcp")]
pub mod kcp_compat;
#[cfg(feature = "quic")]
pub mod quic;
pub mod v2_handshake;
pub mod crypto;
pub mod stun;
pub mod feature_gate;
pub mod unsafe_features;
pub mod internal_listener;
#[cfg(feature = "mem-profile")]
pub mod mem_profile;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Auth error: {0}")]
    Auth(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// frp version string.
pub const VERSION: &str = "0.69.1";

/// Return the user agent string used in login.
pub fn version_str() -> String {
    format!("frp-rs/{}", VERSION)
}

/// Format a host:port string correctly for IPv4 and IPv6.
/// IPv6 addresses are wrapped in brackets: [::1]:7000.
/// Hostnames and IPv4 addresses use plain format: 0.0.0.0:7000.
pub fn format_socket_addr(host: &str, port: u16) -> String {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        std::net::SocketAddr::new(ip, port).to_string()
    } else {
        format!("{host}:{port}")
    }
}
