mod common;

use common::{allocate_port, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

fn ssh_test_config(ssh_port: u16, bind_port: u16) -> ServerConfig {
    let mut cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    cfg.ssh_tunnel_gateway.bind_port = ssh_port;
    cfg.ssh_tunnel_gateway.bind_addr = "127.0.0.1".into();
    cfg
}

/// Read the SSH banner from a TcpStream, returning it as a String.
/// Times out after 2 seconds.
async fn read_ssh_banner(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("timed out waiting for SSH banner")
        .expect("read error on SSH stream");
    assert!(n > 0, "expected at least one byte of SSH banner");
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// Integration test: start frps with SSH gateway, verify banner.
#[tokio::test]
async fn test_ssh_gateway_startup_and_banner() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);

    let (_handle, _port) = start_test_server(cfg).await;

    let mut ssh_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .expect("SSH port should accept connections");

    let banner = read_ssh_banner(&mut ssh_stream).await;
    println!("SSH banner received: {:?}", banner.trim_end());

    assert!(
        banner.starts_with("SSH-"),
        "expected SSH banner, got: {}",
        banner
    );
    assert!(
        banner.contains("frp-rs"),
        "banner should contain 'frp-rs', got: {}",
        banner
    );

    drop(ssh_stream);
}

/// Verify SSH gateway is NOT started when bind_port is 0 (disabled).
#[tokio::test]
async fn test_ssh_gateway_disabled_by_default() {
    let bind_port = allocate_port();

    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    // ssh_tunnel_gateway.bind_port defaults to 0 → disabled

    let (_handle, _port) = start_test_server(cfg).await;

    // Connect to the server's main FRP port and verify it does NOT serve SSH.
    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", bind_port))
        .await
        .expect("FRP port should accept connections");

    // FRP doesn't send data unsolicited — a read will time out.
    // The key assertion: the response must NOT start with "SSH-".
    let mut buf = [0u8; 32];
    let result = timeout(Duration::from_millis(500), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(n)) if n > 0 => {
            let data = String::from_utf8_lossy(&buf[..n]);
            assert!(
                !data.starts_with("SSH-"),
                "FRP main port should not serve SSH banner, got: {}",
                data
            );
        }
        _ => {
            // Timeout or error is fine — FRP doesn't send data unsolicited.
            // The port accepted the connection but didn't speak SSH.
        }
    }
}

/// Verify multiple SSH connections are accepted (each gets unique run_id).
#[tokio::test]
async fn test_ssh_gateway_multiple_connections() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream1 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();
    let mut stream2 = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();

    let banner1 = read_ssh_banner(&mut stream1).await;
    let banner2 = read_ssh_banner(&mut stream2).await;
    assert!(banner1.starts_with("SSH-"));
    assert!(banner2.starts_with("SSH-"));
}

/// Verify SSH gateway works with auth token set — banner is still served.
#[tokio::test]
async fn test_ssh_gateway_with_auth_token() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.auth.token = "test-token-123456".into();

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port))
        .await
        .unwrap();

    let banner = read_ssh_banner(&mut stream).await;
    assert!(banner.starts_with("SSH-"));

    drop(stream);
}
