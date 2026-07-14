//! Integration test: KCP dial → send → recv round-trip.

use std::time::Duration;

use frp_core::kcp::{default_kcp_config, dial_kcp, KcpConfig, KcpListener};
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
