use std::{io::Write, sync::Arc, time::Duration};

use kcp::Kcp;

use crate::crypt::BlockCrypt;

/// Listener processing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerMode {
    /// Normal mode: standard CRC32 verification (aligned with kcp-go)
    Normal,
    /// Custom mode: custom CRC32 verification with salt per conv_id
    Custom,
}

impl Default for ListenerMode {
    fn default() -> Self {
        ListenerMode::Normal
    }
}

/// Kcp Delay Config
#[derive(Debug, Clone, Copy)]
pub struct KcpNoDelayConfig {
    /// Enable nodelay
    pub nodelay: bool,
    /// Internal update interval (ms)
    pub interval: i32,
    /// ACK number to enable fast resend
    pub resend: i32,
    /// Disable congetion control
    pub nc: bool,
}

impl Default for KcpNoDelayConfig {
    fn default() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 100,
            resend: 0,
            nc: false,
        }
    }
}

impl KcpNoDelayConfig {
    /// Get a fastest configuration
    ///
    /// 1. Enable NoDelay
    /// 2. Set ticking interval to be 10ms
    /// 3. Set fast resend to be 2
    /// 4. Disable congestion control
    pub const fn fastest() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: true,
            interval: 10,
            resend: 2,
            nc: true,
        }
    }

    /// Get a normal configuration
    ///
    /// 1. Disable NoDelay
    /// 2. Set ticking interval to be 40ms
    /// 3. Disable fast resend
    /// 4. Enable congestion control
    pub const fn normal() -> KcpNoDelayConfig {
        KcpNoDelayConfig {
            nodelay: false,
            interval: 40,
            resend: 0,
            nc: false,
        }
    }
}

/// Kcp Config
#[derive(Debug, Clone)]
pub struct KcpConfig {
    /// Max Transmission Unit
    pub mtu: usize,
    /// nodelay
    pub nodelay: KcpNoDelayConfig,
    /// Send window size
    pub wnd_size: (u16, u16),
    /// Session expire duration (deprecated, no longer used)
    /// 
    /// This field is kept for backward compatibility but has no effect.
    /// Timeout handling should be done at the application level using
    /// `SetReadDeadline`/`SetWriteDeadline` similar to kcp-go.
    pub session_expire: Option<Duration>,
    /// Flush KCP state immediately after write
    pub flush_write: bool,
    /// Flush ACKs immediately after input
    pub flush_acks_input: bool,
    /// Stream mode
    pub stream: bool,
    /// Allow recv 0 byte packet. KCP Segments with 0 byte data are skipped by default.
    pub allow_recv_empty_packet: bool,
    /// FEC data shards (0 to disable FEC)
    pub fec_data_shards: usize,
    /// FEC parity shards (0 to disable FEC)
    pub fec_parity_shards: usize,
    /// 加密算法（None 表示不加密）
    pub crypt: Option<Arc<dyn BlockCrypt>>,
    /// Listener processing mode
    pub listener_mode: ListenerMode,
}

impl Default for KcpConfig {
    fn default() -> KcpConfig {
        KcpConfig {
            mtu: 1400,
            nodelay: KcpNoDelayConfig::normal(),
            wnd_size: (256, 256),
            session_expire: None, // Deprecated, no longer used
            flush_write: false,
            flush_acks_input: false,
            stream: false,
            allow_recv_empty_packet: false,
            fec_data_shards: 0,  // Disabled by default
            fec_parity_shards: 0, // Disabled by default
            crypt: None, // No encryption by default
            listener_mode: ListenerMode::Normal, // Default to normal mode
        }
    }
}

impl KcpConfig {
    /// Applies config onto `Kcp`
    #[doc(hidden)]
    pub fn apply_config<W: Write>(&self, k: &mut Kcp<W>) {
        k.set_mtu(self.mtu).expect("invalid MTU");

        k.set_nodelay(
            self.nodelay.nodelay,
            self.nodelay.interval,
            self.nodelay.resend,
            self.nodelay.nc,
        );

        k.set_wndsize(self.wnd_size.0, self.wnd_size.1);
    }
}
