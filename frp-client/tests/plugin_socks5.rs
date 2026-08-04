//! Integration tests for the `socks5` plugin: full CONNECT forwarding through
//! the plugin to a local TCP backend, with and without username/password auth.
//!
//! Go frp compat: Socks5ProxyPlugin.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use frp_core::config::PluginConfig;

const SOCKS5_VERSION: u8 = 5;
const AUTH_NO_AUTH: u8 = 0;
const AUTH_USER_PASS: u8 = 2;
const USERPASS_VERSION: u8 = 1;
const CMD_CONNECT: u8 = 1;
const ATYP_IPV4: u8 = 1;

/// Start a TCP echo backend on an ephemeral port.
async fn start_echo_backend() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Full SOCKS5 client: negotiate auth, CONNECT to `target`, return the stream.
async fn socks5_connect(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    user: Option<(&str, &str)>,
) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    match user {
        None => {
            s.write_all(&[SOCKS5_VERSION, 1, AUTH_NO_AUTH])
                .await
                .unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, AUTH_NO_AUTH], "no-auth method");
        }
        Some((u, p)) => {
            s.write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
                .await
                .unwrap();
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [SOCKS5_VERSION, AUTH_USER_PASS], "user-pass method");
            // RFC 1929 sub-negotiation
            let u = u.as_bytes();
            let p = p.as_bytes();
            let mut sub = vec![USERPASS_VERSION, u.len() as u8];
            sub.extend_from_slice(u);
            sub.push(p.len() as u8);
            sub.extend_from_slice(p);
            s.write_all(&sub).await.unwrap();
            let mut status = [0u8; 2];
            s.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [USERPASS_VERSION, 0], "auth must succeed");
        }
    }
    // CONNECT request, IPv4 target
    let ip = target.ip();
    let ipv4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 target"),
    };
    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, 0, ATYP_IPV4];
    req.extend_from_slice(&ipv4.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    // Reply: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2) = 10 bytes
    let mut resp = [0u8; 10];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], SOCKS5_VERSION);
    assert_eq!(resp[1], 0, "CONNECT should succeed, got REP {}", resp[1]);
    s
}

#[tokio::test]
async fn test_socks5_plugin_connect_no_auth() {
    let backend = start_echo_backend().await;
    let cfg = PluginConfig {
        plugin_type: "socks5".into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");
    let mut s = socks5_connect(handle.local_addr, backend, None).await;
    s.write_all(b"hello-via-socks5").await.unwrap();
    // read_exact: a single read() may return a partial echo; loop until the
    // full payload arrives (echo backend satisfies this).
    let mut buf = vec![0u8; b"hello-via-socks5".len()];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(buf, b"hello-via-socks5", "echo through socks5");
}

#[tokio::test]
async fn test_socks5_plugin_connect_with_auth() {
    let backend = start_echo_backend().await;
    let cfg = PluginConfig {
        plugin_type: "socks5".into(),
        username: "alice".into(),
        password: "s3cret".into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");
    let mut s = socks5_connect(handle.local_addr, backend, Some(("alice", "s3cret"))).await;
    s.write_all(b"authed-data").await.unwrap();
    let mut buf = vec![0u8; b"authed-data".len()];
    tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(buf, b"authed-data", "echo through authenticated socks5");
}

#[tokio::test]
async fn test_socks5_plugin_rejects_wrong_password() {
    let cfg = PluginConfig {
        plugin_type: "socks5".into(),
        username: "alice".into(),
        password: "s3cret".into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_socks5_proxy(&cfg)
        .await
        .expect("start socks5 plugin");

    let mut s = TcpStream::connect(handle.local_addr).await.unwrap();
    s.write_all(&[SOCKS5_VERSION, 1, AUTH_USER_PASS])
        .await
        .unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [SOCKS5_VERSION, AUTH_USER_PASS]);

    // Wrong password: RFC 1929 sub-negotiation must reply with status != 0.
    let u = b"alice";
    let p = b"wrong";
    let mut sub = vec![USERPASS_VERSION, u.len() as u8];
    sub.extend_from_slice(u);
    sub.push(p.len() as u8);
    sub.extend_from_slice(p);
    s.write_all(&sub).await.unwrap();
    let mut status = [0u8; 2];
    s.read_exact(&mut status).await.unwrap();
    assert_eq!(status[0], USERPASS_VERSION);
    assert_ne!(status[1], 0, "wrong password must be rejected");
}
