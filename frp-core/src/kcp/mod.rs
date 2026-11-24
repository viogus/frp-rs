//! KCP transport — reliable stream over UDP.
//!
//! In-tree KCP protocol implementation (`protocol.rs`, aligned with kcp-go
//! v5.6.13 wire behavior) plus `kcp_compat::Fec` for forward error
//! correction (GF(2^8) Vandermonde).

mod config;
mod driver_thread;
mod listener;
pub mod protocol;
mod send_thread;
pub mod session;
mod socket;
mod stream;

pub use config::{KcpConfig, KcpNoDelayConfig, KCP_DEAD_LINK_DEFAULT};
pub use listener::{dial_kcp, dial_kcp_with_driver, KcpListener};
pub use session::KcpSession;
pub use stream::KcpStream;

/// Build a KcpConfig matching Go frp v0.69.1 aggressive defaults.
///
/// Go frp uses nodelay=1, interval=20, resend=2, nc=1 with FEC (10,3).
/// This differs from `KcpConfig::default()` which uses conservative kcp-go
/// library defaults (nodelay=0, interval=40, no FEC).
///
/// The MTU is 1400, kcp-go's library default; Go frp overrides it to 1350, so
/// this is a deliberate deviation. A
/// datagram then carries 1376 bytes of KCP payload instead of 1326, i.e. 3.6%
/// fewer datagrams for the same stream. Measured at +3.8% throughput and -4.0%
/// CPU per MiB on a bulk KCP stream (six pairs, both orders:
/// `docs/archive/notes/2026-11-11-kcp-mtu-1400.md`). Peers read into a
/// 1500-byte slot (`DRIVER_RECV_BUF_SIZE`), so a 1400-MTU datagram is accepted
/// by any peer built since 2026-08-13 and by Go frp.
pub fn default_kcp_config() -> KcpConfig {
    KcpConfig {
        nodelay: KcpNoDelayConfig {
            nodelay: true,
            interval: 20,
            resend: 2,
            nc: true,
        },
        // Upper bound for the driver's load-dependent autotune (see
        // `kcp::socket::desired_window`): a lone busy session uses it all,
        // several sessions share it down to a 1024-segment floor.
        wnd_size: (4096, 4096),
        mtu: 1400,
        // Go frp v0.69.1 ListenKcp() uses kcp.ListenWithOptions(addr, nil, 10, 3).
        // FEC IS enabled by default for KCP in Go frp. Match this for compat.
        data_shards: 10,
        parity_shards: 3,
        stream: true,
        dead_link: KCP_DEAD_LINK_DEFAULT,
        liveness_probe: true,
        sender_thread: true,
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
        // Upper bound for the driver's load-dependent autotune (see
        // `kcp::socket::desired_window`): a lone busy session uses it all,
        // several sessions share it down to a 1024-segment floor.
        wnd_size: (4096, 4096),
        mtu: 1400,
        // Go frp v0.69.1 ListenKcp() uses FEC (10,3). Client must match
        // server-side defaults or FEC-wrapped packets will be unparseable.
        data_shards: 10,
        parity_shards: 3,
        stream: true,
        dead_link: KCP_DEAD_LINK_DEFAULT,
        liveness_probe: true,
        sender_thread: true,
    }
}

/// The KCP listener config for a server whose `[transport.kcp]` options are
/// `(dead_link, liveness_probe, sender_thread)`. Missing values keep the kcp-go
/// default bound, the probe on, and the send pool bound.
///
/// Extracted from the listener so the config-to-listener hop is testable
/// without standing up a UDP socket.
pub fn kcp_config_from_options(
    dead_link: Option<u32>,
    liveness_probe: Option<bool>,
    sender_thread: Option<bool>,
) -> KcpConfig {
    let mut config = default_kcp_config();
    if let Some(dead_link) = dead_link {
        config.dead_link = dead_link.max(crate::KCP_DEAD_LINK_MIN);
    }
    if let Some(liveness_probe) = liveness_probe {
        config.liveness_probe = liveness_probe;
    }
    if let Some(sender_thread) = sender_thread {
        config.sender_thread = sender_thread;
    }
    config
}

/// The KCP client config for a dial whose `[transport.kcp]` options are
/// `(dead_link, liveness_probe, sender_thread)`. Clamped like the listener's, so
/// a hand-built `DialOptions` cannot produce a session that dies on its first
/// write.
pub fn kcp_client_config(dead_link: u32, liveness_probe: bool, sender_thread: bool) -> KcpConfig {
    let mut config = default_kcp_client_config();
    config.dead_link = dead_link.max(crate::KCP_DEAD_LINK_MIN);
    config.liveness_probe = liveness_probe;
    config.sender_thread = sender_thread;
    config
}

#[cfg(test)]
mod option_tests {
    use super::*;

    #[test]
    fn the_listener_config_takes_the_configured_bound() {
        assert_eq!(kcp_config_from_options(Some(7), None, None).dead_link, 7);
        assert_eq!(
            kcp_config_from_options(None, None, None).dead_link,
            crate::KCP_DEAD_LINK_DEFAULT
        );
    }

    #[test]
    fn the_listener_config_takes_the_probe_toggle() {
        assert!(kcp_config_from_options(None, None, None).liveness_probe);
        assert!(!kcp_config_from_options(None, Some(false), None).liveness_probe);
        assert!(kcp_config_from_options(None, Some(true), None).liveness_probe);
    }

    #[test]
    fn the_sender_thread_is_on_unless_turned_off() {
        assert!(kcp_config_from_options(None, None, None).sender_thread);
        assert!(kcp_config_from_options(None, None, Some(true)).sender_thread);
        assert!(!kcp_config_from_options(None, None, Some(false)).sender_thread);
        assert!(kcp_client_config(9, true, true).sender_thread);
        assert!(!kcp_client_config(9, true, false).sender_thread);
    }

    #[test]
    fn the_dial_config_takes_the_configured_bound_and_clamps() {
        assert_eq!(kcp_client_config(9, true, true).dead_link, 9);
        assert_eq!(
            kcp_client_config(1, true, true).dead_link,
            crate::KCP_DEAD_LINK_MIN,
            "a hand-built DialOptions must not produce a session that dies on its first write"
        );
        assert!(!kcp_client_config(9, false, true).liveness_probe);
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
