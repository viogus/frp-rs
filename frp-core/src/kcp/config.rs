//! KCP configuration — matches Go frp v0.69.1 wire parameters.

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
    fn default() -> Self {
        Self {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
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
    /// Flush after every write.
    pub flush_write: bool,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            mtu: 1350,
            nodelay: KcpNoDelayConfig::default(),
            wnd_size: (1024, 1024),
            data_shards: 10,
            parity_shards: 3,
            stream: true,
            flush_write: true,
        }
    }
}
