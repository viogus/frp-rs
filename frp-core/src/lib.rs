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
#[cfg(feature = "profiling")]
pub mod profiling;

use thiserror::Error;

/// Exit codes for process termination.
/// Mirrored in frps/frpc main.rs — keep in sync.
pub const EXIT_RUNTIME: i32 = 1;   // connection lost, I/O error, unexpected
pub const EXIT_CONFIG: i32 = 2;    // bad config file, unknown field, invalid value
pub const EXIT_AUTH: i32 = 3;      // bad token, OIDC failure
pub const EXIT_BIND: i32 = 4;      // port in use, permission denied

// ── Sub-error types with structured context ──────────────────────────

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("invalid V1 message length {length}, raw header: {header}")]
    InvalidV1Length { length: u64, header: String },
    #[error("V1 frame too large: {length} (max {max})")]
    V1FrameTooLarge { length: u64, max: u64 },
    #[error("V2 frame payload too large: {payload_len}")]
    V2PayloadTooLarge { payload_len: usize },
    #[error("read V1 payload: {source}")]
    ReadV1Payload { #[source] source: std::io::Error },
    #[error("read V2 payload: {source}")]
    ReadV2Payload { #[source] source: std::io::Error },
    #[error("deserialize {msg_type} (v1): {source}")]
    DeserializeV1 { msg_type: &'static str, #[source] source: serde_json::Error },
    #[error("deserialize {msg_type} (v2): {source}")]
    DeserializeV2 { msg_type: &'static str, #[source] source: serde_json::Error },
    #[error("write V1 frame: {source}")]
    WriteV1Frame { #[source] source: std::io::Error },
    #[error("write V2 frame: {source}")]
    WriteV2Frame { #[source] source: std::io::Error },
    #[error("serialize V1 msg: {source}")]
    SerializeV1 { #[source] source: serde_json::Error },
    #[error("{0}")]
    Other(String),
}

impl From<String> for ProtocolError {
    fn from(s: String) -> Self { ProtocolError::Other(s) }
}

impl From<&str> for ProtocolError {
    fn from(s: &str) -> Self { ProtocolError::Other(s.to_string()) }
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("TCP connect to {addr}: {source}")]
    TcpConnect { addr: String, #[source] source: std::io::Error },
    #[error("TLS handshake: {source}")]
    TlsHandshake { #[source] source: std::io::Error },
    #[error("KCP connect to {addr}: {source}")]
    KcpConnect { addr: String, #[source] source: Box<dyn std::error::Error + Send + Sync> },
    #[error("QUIC: {0}")]
    Quic(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("WebSocket: {0}")]
    WebSocket(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("TLS config: {source}")]
    TlsConfig { #[source] source: std::io::Error },
    #[error("plugin TLS connector: {source}")]
    PluginTls { #[source] source: Box<dyn std::error::Error + Send + Sync> },
    #[error("WebSocket upgrade: {0}")]
    WebSocketUpgrade(String),
    #[error("WebSocket TLS: {0}")]
    WebSocketTls(String),
    #[error("{0}")]
    Other(String),
}

impl From<String> for TransportError {
    fn from(s: String) -> Self { TransportError::Other(s) }
}

impl From<&str> for TransportError {
    fn from(s: &str) -> Self { TransportError::Other(s.to_string()) }
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("timestamp required for authentication")]
    TimestampRequired,
    #[error("timestamp outside acceptable window")]
    TimestampOutsideWindow,
    #[error("invalid authentication token")]
    InvalidToken,
    #[error("OIDC auth requires server-side verifier (not configured)")]
    OidcNotConfigured,
    #[error("authentication token must not be empty with token auth method")]
    EmptyToken,
    #[error("login failed: {0}")]
    LoginFailed(String),
    #[error("{0}")]
    Other(String),
}

impl From<String> for AuthError {
    fn from(s: String) -> Self { AuthError::Other(s) }
}

impl From<&str> for AuthError {
    fn from(s: &str) -> Self { AuthError::Other(s.to_string()) }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("{0}")]
    Parse(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Other(String),
}

impl From<String> for ConfigError {
    fn from(s: String) -> Self { ConfigError::Other(s) }
}

impl From<&str> for ConfigError {
    fn from(s: &str) -> Self { ConfigError::Other(s.to_string()) }
}

// ── Parent Error ────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum Error {
    #[error("protocol error: {0}")]
    Protocol(#[source] ProtocolError),
    #[error("transport error: {0}")]
    Transport(#[source] TransportError),
    #[error("auth error: {0}")]
    Auth(#[source] AuthError),
    #[error("config error: {0}")]
    Config(#[source] ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
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
