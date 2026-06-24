mod common;

use common::TestHarness;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// End-to-end test: plain TCP proxy.
///
/// Starts echo server → frps → frpc with a TCP proxy.
/// Connects to the proxy port, sends data, receives echo.
#[tokio::test]
async fn test_e2e_tcp_proxy_plain() {
    let harness = TestHarness::new(false, "").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    // Write data through the proxy
    let payload = b"hello from e2e test\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    // Read echo back
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo from proxy");

    assert_eq!(&buf, payload, "echo data should match sent data");

    // Second round-trip to verify connection is stable
    let payload2 = b"round two - still working\n";
    stream.write_all(payload2).await.expect("write 2");
    stream.flush().await.expect("flush 2");

    let mut buf2 = vec![0u8; payload2.len()];
    stream.read_exact(&mut buf2).await.expect("read 2");

    assert_eq!(&buf2, payload2, "second echo should match");
}

/// End-to-end test: encrypted TCP proxy (AES-128-CFB).
///
/// Same flow as plain test but with use_encryption=true.
/// Requires a shared auth token (key derivation source).
#[tokio::test]
async fn test_e2e_tcp_proxy_encrypted() {
    let harness = TestHarness::new(true, "e2e-encryption-token").await;

    let proxy_addr = format!("127.0.0.1:{}", harness.proxy_port);
    let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy port");

    let payload = b"encrypted tunnel test payload\n";
    stream.write_all(payload).await.expect("write to proxy");
    stream.flush().await.expect("flush");

    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf).await.expect("read echo from proxy");

    assert_eq!(&buf, payload, "echo through encrypted tunnel should match");

    // Send a larger payload to exercise framing
    let large = vec![0xABu8; 4096];
    stream.write_all(&large).await.expect("write large");
    stream.flush().await.expect("flush large");

    let mut large_buf = vec![0u8; large.len()];
    stream.read_exact(&mut large_buf).await.expect("read large");

    assert_eq!(large_buf, large, "large echo through encrypted tunnel should match");
}
