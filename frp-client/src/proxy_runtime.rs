//! Proxy runtime info — always available (no feature gate).

use tokio::sync::oneshot;

/// Runtime state for a registered proxy.
/// Used by work_conn, reload, and service modules regardless of admin feature.
#[derive(Debug, Clone)]
pub struct ProxyRuntimeInfo {
    pub local_addr: String,
    pub proxy_type: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    /// Secret key (sk) for XTCP/STCP proxy encryption.
    pub sk: String,
    pub bandwidth_limit: u64,
    pub bandwidth_limit_mode: String,
    pub proxy_protocol_version: String,
    /// Plugin type (e.g. "http_proxy", "socks5"). Empty if no plugin.
    pub plugin: String,
    /// Remote address assigned by frps (from NewProxyResp).
    pub remote_addr: String,
    /// Last registration error, if any. Cleared on success.
    pub err: String,
    /// Snapshot of original proxy config (JSON) for reload change detection.
    pub config_snapshot: String,
}

/// Request to reload configuration. Sent via channel from admin API or signal handler.
pub struct ReloadRequest {
    pub strict: bool,
    pub reply: oneshot::Sender<Result<String, String>>,
}
