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

/// KCP wire overhead above the MTU-sized segment when FEC is enabled:
/// the FEC header (SEQID 4B + TYPE 2B — `session::FEC_HEADER_SIZE`) plus
/// the per-shard SIZE field (2B). A max-size KCP output segment is `mtu`
/// bytes (mss = mtu - KCP_OVERHEAD, segment = mss + KCP_OVERHEAD), so the
/// largest wire packet is `mtu + KCP_WIRE_OVERHEAD`.
pub(crate) const KCP_WIRE_OVERHEAD: usize = crate::kcp::session::FEC_HEADER_SIZE + 2;

/// Maximum configurable MTU. The socket driver's receive buffer is fixed
/// (see `socket::DRIVER_RECV_BUF_SIZE`), so the largest wire packet a peer
/// with the same config can send — `mtu + KCP_WIRE_OVERHEAD` — must fit.
/// A larger configured MTU is clamped (with a warning) in `KcpSocket::new`
/// on the listen path, and via `KcpConfig::clamped` on the dial path.
pub const MAX_KCP_MTU: usize = crate::kcp::socket::DRIVER_RECV_BUF_SIZE - KCP_WIRE_OVERHEAD;

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

impl KcpConfig {
    /// Returns a config with `mtu` clamped to `MAX_KCP_MTU` (matching what
    /// `KcpSocket::new` enforces) so dial-side sessions agree with the
    /// socket. `dial_kcp` clamps once via this helper before constructing
    /// both the socket and the session — an un-clamped mtu would let the
    /// session emit `mtu + KCP_WIRE_OVERHEAD`-byte FEC wire packets that the
    /// receiver's fixed 1500-byte driver recv buffer would truncate.
    pub fn clamped(self) -> Self {
        let mut config = self;
        if config.mtu > MAX_KCP_MTU {
            config.mtu = MAX_KCP_MTU;
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_default_differs_from_trait_default_on_wire_relevant_knobs() {
        // Production KCP paths (client/server dial/listen, XTCP hole-punch
        // sessions, nathole) build their config from `default_kcp_config()`,
        // which matches Go frp v0.69.1's aggressive ListenKcp() defaults:
        // nodelay=1/interval=20/resend=2/nc=1 with FEC (10,3) and mtu 1350.
        // `KcpConfig::default()` stays the conservative kcp-go library
        // defaults (nodelay=0, interval=40, no FEC). The split is pin:
        // swapping one for the other would silently disable FEC — a Go peer
        // then sends FEC-wrapped segments this side cannot parse — or drop
        // nodelay (a latency regression on every KCP tunnel).
        let conservative = KcpConfig::default();
        let aggressive = crate::kcp::default_kcp_config();
        let aggressive_client = crate::kcp::default_kcp_client_config();

        assert!(
            !conservative.nodelay.nodelay,
            "trait default keeps kcp-go nodelay=0"
        );
        assert_eq!(conservative.nodelay.interval, 40);
        assert_eq!(
            (conservative.data_shards, conservative.parity_shards),
            (0, 0),
            "trait default has no FEC"
        );

        assert!(aggressive.nodelay.nodelay, "Go frp nodelay=1");
        assert_eq!(aggressive.nodelay.interval, 20);
        assert_eq!(aggressive.nodelay.resend, 2);
        assert!(aggressive.nodelay.nc, "Go frp nc=1");
        assert_eq!((aggressive.data_shards, aggressive.parity_shards), (10, 3));
        assert_eq!(aggressive.mtu, 1350);
        assert_eq!(aggressive.wnd_size, (1024, 1024));

        // The client dial helper must stay wire-identical to the server-side
        // defaults, or FEC-shard counts would diverge per direction.
        assert_eq!(
            aggressive_client.nodelay.nodelay,
            aggressive.nodelay.nodelay
        );
        assert_eq!(
            aggressive_client.nodelay.interval,
            aggressive.nodelay.interval
        );
        assert_eq!(aggressive_client.nodelay.resend, aggressive.nodelay.resend);
        assert_eq!(aggressive_client.nodelay.nc, aggressive.nodelay.nc);
        assert_eq!(
            (
                aggressive_client.data_shards,
                aggressive_client.parity_shards
            ),
            (10, 3)
        );
        assert_eq!(aggressive_client.mtu, aggressive.mtu);
    }
}
