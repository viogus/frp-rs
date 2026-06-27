mod common;

use common::{allocate_port, start_test_server};
use frp_core::config::ServerConfig;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

/// Integration test: start frps with SSH gateway, verify startup + port binding.
#[tokio::test]
async fn test_ssh_gateway_startup_and_bind() {
    // Allocate random ports
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        ..Default::default()
    };
    cfg.ssh_tunnel_gateway.bind_port = ssh_port;
    cfg.ssh_tunnel_gateway.bind_addr = "127.0.0.1".into();

    let (_handle, _port) = start_test_server(cfg).await;

    // Verify SSH port accepts TCP connections
    let mut ssh_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .expect("SSH port should accept connections");
    assert!(
        ssh_stream.peer_addr().is_ok(),
        "SSH port should accept connections"
    );

    // SSH server should send its banner (SSH-2.0-...) on connect.
    // Use a timeout in case russh hasn't polled the accept task yet.
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), ssh_stream.read(&mut buf))
        .await
        .expect("timed out waiting for SSH banner")
        .expect("read error on SSH stream");

    assert!(n > 0, "expected at least one byte of SSH banner");
    let banner = String::from_utf8_lossy(&buf[..n]);
    println!("SSH banner received: {:?}", banner.trim_end());
    assert!(
        banner.starts_with("SSH-"),
        "expected SSH banner, got: {}",
        banner
    );

    drop(ssh_stream);
}
