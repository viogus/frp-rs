//! KCP transport — reliable stream over UDP.
//!
//! Direct wrapper around the `kcp` crate (vendored 0.6.0 with Go compat patches)
//! and `kcp_compat::Fec` for forward error correction (GF(2^8) Vandermonde).

mod config;
mod listener;
mod session;
mod socket;
mod stream;

pub use config::{KcpConfig, KcpNoDelayConfig};
pub use listener::{dial_kcp, KcpListener};
pub use stream::KcpStream;

/// Build a KcpConfig matching Go frp v0.69.1 defaults.
pub fn default_kcp_config() -> KcpConfig {
    KcpConfig {
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
        },
        wnd_size: (1024, 1024),
        mtu: 1350,
        // Go frp v0.69.1 ListenKcp() uses kcp.ListenWithOptions(addr, nil, 10, 3).
        // FEC IS enabled by default for KCP in Go frp. Match this for compat.
        data_shards: 10,
        parity_shards: 3,
        stream: true,
        flush_write: true,
    }
}
