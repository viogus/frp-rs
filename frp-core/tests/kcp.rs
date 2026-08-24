//! Integration test: KCP dial → send → recv round-trip.

use std::time::Duration;

use frp_core::kcp::{default_kcp_config, dial_kcp, dial_kcp_with_driver, KcpConfig, KcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

fn no_fec_config() -> KcpConfig {
    KcpConfig {
        data_shards: 0,
        parity_shards: 0,
        ..default_kcp_config()
    }
}

/// Integration test for KCP dial/accept/send/recv round-trip.
///
/// Uses multi-threaded runtime because the KcpSocket driver tasks are spawned
/// on separate tasks and the single-threaded runtime can starve them when
/// the test harness captures output.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_send_recv() {
    let config = no_fec_config();
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind");
    let addr = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    // Spawn the dialer: connect, write, shutdown.
    let dial_handle = tokio::spawn(async move {
        let mut stream = timeout(Duration::from_secs(10), dial_kcp(&addr, config))
            .await
            .expect("dial timeout")
            .expect("dial_kcp");
        stream.write_all(b"hello from dialer").await.expect("write");
        stream.shutdown().await.expect("shutdown");
    });

    // Accept the incoming connection.
    let mut stream = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept timeout")
        .expect("accept");

    // Read with timeout.
    let mut buf = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read");

    assert_eq!(&buf[..n], b"hello from dialer");
    dial_handle.await.expect("dial task");
}

/// Regression (HIGH leak): the dial-path KcpSocket driver used to loop
/// forever after the last stream was dropped — sessions empty, but run()
/// still spinning on tick/recv with the UDP socket open, leaking one task +
/// socket per KCP dial (control conn, each work conn) for the process
/// lifetime; reconnect churn grew it unbounded. The driver must self-exit
/// once its only stream is dropped. Fails (timeout) without the fix.
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_dial_driver_self_exits_after_stream_drop() {
    let config = no_fec_config();

    // Real dial (binds a UDP socket and spawns the driver), then drop the
    // stream immediately — no peer needed, the driver's liveness signal is
    // the stream itself.
    let (stream, driver) = timeout(
        Duration::from_secs(10),
        dial_kcp_with_driver("127.0.0.1:1", config),
    )
    .await
    .expect("dial timeout")
    .expect("dial_kcp_with_driver");
    drop(stream);

    // The driver must terminate promptly once its only stream is gone.
    // (The outer Result is the timeout — the failure this test exists to
    // catch; the driver's own exit status is irrelevant once it resolves.)
    let _: Result<(), _> = timeout(Duration::from_secs(5), driver)
        .await
        .expect("KCP dial driver must self-exit after the last stream is dropped");
}

/// KCP+TLS round-trip: the client wraps the KCP stream in TLS with the
/// 0x17 head byte (Go frp compat); the server strips the head byte and
/// performs a TLS accept, exactly like frp-server/src/service.rs KCP TLS
/// accept path. Verifies dial_server's KCP branch honors tls_enable.
#[cfg(feature = "tls")]
#[tokio::test(flavor = "multi_thread")]
async fn test_kcp_tls_round_trip() {
    use frp_core::transport::{dial_server, DialOptions};
    use tokio::io::AsyncReadExt;

    // dial_server uses default_kcp_client_config (FEC 10,3); the listener
    // must match or FEC-wrapped packets will be unparseable.
    let config = KcpConfig {
        data_shards: 10,
        parity_shards: 3,
        ..default_kcp_config()
    };
    let mut listener = KcpListener::bind("127.0.0.1:0", config.clone())
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Allow driver event loops to start.
    sleep(Duration::from_millis(50)).await;

    let server_cfg = frp_core::transport::generate_self_signed_tls_config()
        .expect("generate self-signed TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg));

    let server_handle = tokio::spawn(async move {
        let mut kcp_stream = timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept timeout")
            .expect("accept");
        // Strip the Go frp 0x17 head byte (service.rs KCP TLS accept path).
        let mut first = [0u8; 1];
        timeout(Duration::from_secs(10), kcp_stream.read_exact(&mut first))
            .await
            .expect("read head byte timeout")
            .expect("read head byte");
        assert_eq!(first[0], frp_core::transport::FRP_TLS_HEAD_BYTE);
        let mut tls_stream = timeout(Duration::from_secs(10), acceptor.accept(kcp_stream))
            .await
            .expect("tls accept timeout")
            .expect("tls accept");
        let mut buf = vec![0u8; 1024];
        let n = timeout(Duration::from_secs(10), tls_stream.read(&mut buf))
            .await
            .expect("tls read timeout")
            .expect("tls read");
        assert_eq!(&buf[..n], b"hello over kcp+tls");
    });

    let opts = DialOptions {
        server_addr: "127.0.0.1".to_string(),
        server_port: port,
        protocol: frp_core::transport::TransportProtocol::Kcp,
        tls_enable: true,
        ..Default::default()
    };
    let io = timeout(Duration::from_secs(10), dial_server(&opts))
        .await
        .expect("dial timeout")
        .expect("dial_server");
    let mut tls_io = io.into_tls().expect("expected IoStream::Tls for KCP+TLS");
    {
        use tokio::io::AsyncWriteExt;
        tls_io
            .write_all(b"hello over kcp+tls")
            .await
            .expect("tls write");
        tls_io.flush().await.expect("tls flush");
    }

    server_handle.await.expect("server task");
}
