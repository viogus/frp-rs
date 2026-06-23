pub mod msg;
pub mod protocol;
pub mod transport;
pub mod auth;
pub mod config;
pub mod encryption;

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
pub const VERSION: &str = "0.60.0";

/// Return the user agent string used in login.
pub fn version_str() -> String {
    format!("frp-rs/{}", VERSION)
}
