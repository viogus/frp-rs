mod common;

use common::TestHarness;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// V2 protocol end-to-end test: TCP proxy.
///
/// Starts echo server → frps → frpc (V2 protocol) with a TCP proxy.
/// Connects to the proxy port, sends data, receives echo.
#[tokio::test]
async fn test_v2_e2e_tcp_proxy() {
    let harness = TestHarness::new_v2(false, "test-token").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    let payload = b"hello v2 e2e\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo");

    assert_eq!(&buf, payload, "echo data should match sent data");
}

/// V2 protocol e2e test with encryption (AES-128-CFB).
#[tokio::test]
async fn test_v2_e2e_tcp_proxy_encrypted() {
    let harness = TestHarness::new_v2(true, "test-token").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    let payload = b"hello v2 encrypted\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo");

    assert_eq!(&buf, payload, "echo data should match sent data");
}

/// V2 protocol: multiple round-trips on same connection.
#[tokio::test]
async fn test_v2_e2e_multiple_roundtrips() {
    let harness = TestHarness::new_v2(false, "test-token").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    for i in 0..5 {
        let payload = format!("v2 round {}\n", i).into_bytes();
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");

        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await.expect("read echo");
        assert_eq!(&buf, &payload, "round {} echo mismatch", i);
    }
}
