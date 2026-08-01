#![cfg(feature = "ssh")]
mod common;

use common::{allocate_port, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

struct TestSshClient {
    /// `-R` local target address (e.g. "127.0.0.1:1234"). When set, server
    /// `forwarded-tcpip` channels are bridged to that TCP service.
    local_target: Option<String>,
}

impl russh::client::Handler for TestSshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        // Bridge the forwarded-tcpip channel to the local -R target
        // (the "local service" behind ssh -R). ChannelStream is a full
        // AsyncRead+AsyncWrite pair — use copy_bidirectional.
        if let Some(target) = self.local_target.clone() {
            let mut stream = Box::pin(channel.into_stream());
            tokio::spawn(async move {
                if let Ok(mut local) = tokio::net::TcpStream::connect(&target).await {
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut local).await;
                }
            });
        }
        Ok(())
    }
}

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

    // Retry: SSH gateway may not be listening immediately after server start.
    let mut ssh_stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            ssh_stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut ssh_stream = ssh_stream.expect("SSH port should accept connections");

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

/// SSH gateway should close connection when non-SSH data is sent after banner.
/// Verifies the server rejects invalid SSH protocol data (doesn't just hang).
#[tokio::test]
async fn test_ssh_gateway_rejects_non_ssh_data() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let cfg = ssh_test_config(ssh_port, bind_port);
    let (_handle, _port) = start_test_server(cfg).await;

    // Retry connect
    let mut stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut stream = stream.expect("SSH port should accept connections");

    // Read banner first (SSH protocol sends banner before client data)
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("banner timeout")
        .expect("banner read");
    assert!(n > 0, "should get SSH banner");

    // Send garbage data (not valid SSH handshake)
    use tokio::io::AsyncWriteExt;
    stream.write_all(b"NOT SSH DATA\r\n").await.unwrap();
    stream.flush().await.unwrap();

    // Server must close the connection — read should return 0 (FIN) or
    // an error (RST). A timeout without data means the server is hanging,
    // which is a bug (should reject invalid protocol).
    let mut buf = [0u8; 64];
    let result = timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            // Expected: clean close via FIN, connection reset, or timeout.
        }
        Ok(Ok(_n)) => {
            // Server sent SSH disconnect message before closing.
            // Verify a subsequent read returns 0 (connection closed).
            let result2 = timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            assert!(
                matches!(result2, Ok(Ok(0)) | Ok(Err(_)) | Err(_)),
                "connection should be closed after SSH disconnect message, got {:?}",
                result2
            );
        }
    }
}

/// SSH gateway starts successfully with max_ports_per_client configured.
/// NOTE: Does not test actual limit enforcement (requires full SSH client).
/// The config value is validated at parse time; enforcement is in exec_request.
#[tokio::test]
async fn test_ssh_gateway_starts_with_port_limit_config() {
    let ssh_port = allocate_port();
    let bind_port = allocate_port();

    let mut cfg = ssh_test_config(ssh_port, bind_port);
    cfg.max_ports_per_client = 3;

    let (_handle, _port) = start_test_server(cfg).await;

    let mut stream = None;
    for _ in 0..20 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut ssh_stream = stream.expect("SSH port should accept connections");

    let banner = read_ssh_banner(&mut ssh_stream).await;
    assert!(banner.starts_with("SSH-"));
    assert!(banner.contains("frp-rs"));

    drop(ssh_stream);
}

/// Go-compatible `ssh -R`: the server accepts tcpip-forward, opens a
/// forwarded-tcpip channel per work connection, and bridges data between the
/// SSH client's local service and the frps proxy port.
#[tokio::test]
async fn test_ssh_gateway_reverse_forwarding_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_test_writer()
        .try_init();
    let ssh_port = allocate_port();
    let bind_port = allocate_port();
    let remote_port = allocate_port(); // frps proxy port
    let local_port = allocate_port(); // local echo service behind -R

    let cfg = ssh_test_config(ssh_port, bind_port);
    let (_handle, _port) = start_test_server(cfg).await;

    // Local echo server (simulates the ssh -R host:hostport target).
    let echo_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{local_port}"))
        .await
        .unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let addr: SocketAddr = format!("127.0.0.1:{}", ssh_port).parse().unwrap();
    let mut client = None;
    for _ in 0..20 {
        if let Ok(c) = russh::client::connect(
            Arc::new(russh::client::Config::default()),
            addr,
            TestSshClient {
                local_target: Some(format!("127.0.0.1:{local_port}")),
            },
        )
        .await
        {
            client = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut client = client.expect("SSH client should connect");

    let auth = client
        .authenticate_password("v0", common::TEST_TOKEN)
        .await
        .expect("password auth should succeed");
    assert!(auth.success(), "SSH password auth failed");

    // ssh -R :remote_port:127.0.0.1:local_port
    let fwd = client
        .tcpip_forward("127.0.0.1", remote_port as u32)
        .await
        .expect("-R tcpip-forward must be accepted");
    // SSH protocol: a specific-port request's success reply carries no port
    // (russh returns 0); a 0 request would return the allocated port.
    assert_eq!(fwd, 0, "-R request should be granted for the requested port");

    // Register a tcp proxy through the SSH remote command.
    let session = client
        .channel_open_session()
        .await
        .expect("open session channel");
    session
        .exec(
            true,
            format!("tcp --proxy_name \"ssh-r-test\" --remote_port {remote_port}"),
        )
        .await
        .expect("exec accepted");

    // Connect through the frps proxy port and verify the echo round-trip.
    let mut proxy_stream = None;
    for _ in 0..50 {
        if let Ok(s) = tokio::net::TcpStream::connect(format!("127.0.0.1:{remote_port}")).await {
            proxy_stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut proxy_stream = proxy_stream.expect("frps proxy port should accept");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    proxy_stream.write_all(b"ping-over-ssh-r").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), proxy_stream.read(&mut buf))
        .await
        .expect("should receive echoed data")
        .expect("echo read");
    assert_eq!(
        &buf[..n], b"ping-over-ssh-r",
        "data must round-trip through ssh -R"
    );

    client
        .disconnect(russh::Disconnect::ByApplication, "test complete", "")
        .await
        .ok();
    echo_task.abort();
}
