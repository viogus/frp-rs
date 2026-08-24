//! KCP transport — reliable stream over UDP.
//!
//! In-tree KCP protocol implementation (`protocol.rs`, aligned with kcp-go
//! v5.6.13 wire behavior) plus `kcp_compat::Fec` for forward error
//! correction (GF(2^8) Vandermonde).

mod config;
mod listener;
pub mod protocol;
pub mod session;
mod socket;
mod stream;

pub use config::{KcpConfig, KcpNoDelayConfig};
pub use listener::{dial_kcp, dial_kcp_with_driver, KcpListener};
pub use session::KcpSession;
pub use stream::KcpStream;

/// Build a KcpConfig matching Go frp v0.69.1 aggressive defaults.
///
/// Go frp uses nodelay=1, interval=20, resend=2, nc=1 with FEC (10,3).
/// This differs from `KcpConfig::default()` which uses conservative kcp-go
/// library defaults (nodelay=0, interval=40, no FEC).
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
    }
}

/// Build a KcpConfig for client-side KCP dialing.
/// Uses the same FEC params as the server (10,3) for wire compatibility.
pub fn default_kcp_client_config() -> KcpConfig {
    KcpConfig {
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
        },
        wnd_size: (1024, 1024),
        mtu: 1350,
        // Go frp v0.69.1 ListenKcp() uses FEC (10,3). Client must match
        // server-side defaults or FEC-wrapped packets will be unparseable.
        data_shards: 10,
        parity_shards: 3,
        stream: true,
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    /// Full KCP roundtrip over real UDP: bind → dial → accept → send both ways.
    #[tokio::test]
    async fn kcp_roundtrip_udp_socket() {
        let config = KcpConfig {
            // Disable FEC for simplicity; FEC encode/decode tested in session.rs.
            data_shards: 0,
            parity_shards: 0,
            ..default_kcp_config()
        };

        // Bind on random port. Port 0 guarantees no conflict.
        let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
            .await
            .expect("bind KCP listener");
        let addr = listener.local_addr().expect("local_addr");

        // Dial from client; write data immediately so the server's driver
        // detects the new peer and pushes a stream through accept_tx.
        let mut client = dial_kcp(&addr.to_string(), config).await.expect("dial");
        client.write_all(b"hello from client").await.unwrap();
        client.flush().await.unwrap();

        // Now the server can accept — the driver has already created a session
        // from the incoming UDP data.
        let mut server = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept");

        // Read what the client sent.
        let mut buf = vec![0u8; 64];
        let n = timeout(Duration::from_secs(5), server.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("server read");
        assert_eq!(&buf[..n], b"hello from client");

        // Server → Client: write back and read on client side.
        server.write_all(b"hello from server").await.unwrap();
        server.flush().await.unwrap();

        let n = timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("client read");
        assert_eq!(&buf[..n], b"hello from server");
    }
}
