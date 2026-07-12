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

/// Exit codes for process termination.
/// Mirrored in frps/frpc main.rs — keep in sync.
pub const EXIT_RUNTIME: i32 = 1;   // connection lost, I/O error, unexpected
pub const EXIT_CONFIG: i32 = 2;    // bad config file, unknown field, invalid value
pub const EXIT_AUTH: i32 = 3;      // bad token, OIDC failure
pub const EXIT_BIND: i32 = 4;      // port in use, permission denied

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

impl Error {
    /// Map each error variant to a process exit code.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => EXIT_CONFIG,
            Error::Auth(_) => EXIT_AUTH,
            Error::Io(e) if e.kind() == std::io::ErrorKind::AddrInUse
                || e.kind() == std::io::ErrorKind::PermissionDenied => EXIT_BIND,
            _ => EXIT_RUNTIME,
        }
    }
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
