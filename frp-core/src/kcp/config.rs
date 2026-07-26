//! KCP configuration — conservative kcp-go defaults.
//!
//! These are the raw kcp-go library defaults (nodelay=0, interval=40, no FEC).
//! For the aggressive Go frp v0.69.1 defaults (nodelay=1, interval=20, resend=2,
//! nc=1, FEC enabled), use `default_kcp_config()` instead.

/// KCP no-delay configuration.
#[derive(Debug, Clone)]
pub struct KcpNoDelayConfig {
    /// Enable nodelay mode.
    pub nodelay: bool,
    /// Internal update interval in milliseconds.
    pub interval: i32,
    /// Fast retransmit threshold (0 = disabled).
    pub resend: i32,
    /// Disable congestion control (nc = "no congestion").
    pub nc: bool,
}

impl Default for KcpNoDelayConfig {
    /// kcp-go library defaults: nodelay=0, interval=40, resend=0, nc=0.
    fn default() -> Self {
        Self {
            nodelay: false,
            interval: 40,
            resend: 0,
            nc: false,
        }
    }
}

/// KCP transport configuration.
#[derive(Debug, Clone)]
pub struct KcpConfig {
    /// Maximum transmission unit.
    pub mtu: usize,
    /// No-delay / retransmit / congestion parameters.
    pub nodelay: KcpNoDelayConfig,
    /// Send and receive window sizes.
    pub wnd_size: (u16, u16),
    /// Number of FEC data shards (0 = FEC disabled).
    pub data_shards: usize,
    /// Number of FEC parity shards (0 = FEC disabled).
    pub parity_shards: usize,
    /// Stream mode: each KCP output produces a single contiguous datagram.
    pub stream: bool,
}

impl Default for KcpConfig {
    /// Conservative defaults: no FEC, no nodelay, mtu=1350, wnd=1024.
    fn default() -> Self {
        Self {
            mtu: 1350,
            nodelay: KcpNoDelayConfig::default(),
            wnd_size: (1024, 1024),
            data_shards: 0,
            parity_shards: 0,
            stream: true,
        }
    }
}
