//! Integration tests for upstream proxy URL support (Go golib parity):
//! - `http://user:pass@host:port` sends Proxy-Authorization: Basic on CONNECT.
//! - `socks5://` requires an IP target; `socks5h://` sends the hostname to
//!   the proxy (remote DNS, ATYP 0x03) and supports RFC 1929 user/pass auth.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use frp_core::transport::{dial_server, DialOptions};

fn opts(proxy_url: String, server_port: u16) -> DialOptions {
    DialOptions {
        server_addr: "proxy-target.example".to_string(),
        server_port,
        proxy_url: Some(proxy_url),
        ..Default::default()
    }
}

/// HTTP CONNECT proxy mock: verifies Basic auth, replies 200, echoes tunnel bytes.
#[tokio::test]
async fn http_proxy_sends_basic_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_task = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("proxy accept");
        let mut buf = vec![0u8; 4096];
        let n = conn.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(
            req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            "CONNECT must carry Basic auth for user:pass, got: {req}"
        );
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        // Echo tunnel bytes back.
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let mut dial_opts = opts(format!("http://user:pass@{proxy_addr}"), 7000);
    dial_opts.server_addr = "127.0.0.1".to_string();
    let mut io = dial_server(&dial_opts).await.expect("dial via http proxy");
    io.write_all(b"ping-through-proxy").await.unwrap();
    let mut resp = vec![0u8; 64];
    let n = io.read(&mut resp).await.unwrap();
    assert_eq!(&resp[..n], b"ping-through-proxy");
    proxy_task.await.unwrap();
}

/// SOCKS5h mock: expects no-auth method selection, then a domain ATYP 0x03
/// CONNECT for the hostname (remote DNS), replies success, echoes bytes.
#[tokio::test]
async fn socks5h_sends_domain_and_supports_user_pass_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_task = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("proxy accept");
        // Method negotiation: client offers [0x05, 0x02, 0x00, 0x02] → pick 0x02.
        let mut methods = [0u8; 4];
        conn.read_exact(&mut methods).await.unwrap();
        assert_eq!(methods[0], 0x05);
        assert_eq!(methods[1], 0x02, "expected 2 offered methods");
        conn.write_all(&[0x05, 0x02]).await.unwrap();

        // RFC 1929 user/pass.
        let mut ver = [0u8; 1];
        conn.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 0x01);
        let mut ulen = [0u8; 1];
        conn.read_exact(&mut ulen).await.unwrap();
        let mut user = vec![0u8; ulen[0] as usize];
        conn.read_exact(&mut user).await.unwrap();
        let mut plen = [0u8; 1];
        conn.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        conn.read_exact(&mut pass).await.unwrap();
        assert_eq!(user, b"user");
        assert_eq!(pass, b"pass");
        conn.write_all(&[0x01, 0x00]).await.unwrap();

        // CONNECT request: [5,1,0, 0x03, len, domain, port(2)].
        let mut head = [0u8; 3];
        conn.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05);
        assert_eq!(head[1], 0x01);
        assert_eq!(head[2], 0x00);
        let mut atyp = [0u8; 1];
        conn.read_exact(&mut atyp).await.unwrap();
        assert_eq!(atyp[0], 0x03, "socks5h must use domain ATYP");
        let mut dlen = [0u8; 1];
        conn.read_exact(&mut dlen).await.unwrap();
        let mut domain = vec![0u8; dlen[0] as usize];
        conn.read_exact(&mut domain).await.unwrap();
        assert_eq!(domain, b"127.0.0.1");
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).await.unwrap();
        assert_eq!(u16::from_be_bytes(port), 7000);

        // Reply success with IPv4 bind address.
        conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // Echo tunnel bytes.
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let mut dial_opts = opts(format!("socks5h://user:pass@{proxy_addr}"), 7000);
    dial_opts.server_addr = "127.0.0.1".to_string();
    let mut io = dial_server(&dial_opts).await.expect("dial via socks5h proxy");
    io.write_all(b"tunnel-ok").await.unwrap();
    let mut resp = vec![0u8; 64];
    let n = io.read(&mut resp).await.unwrap();
    assert_eq!(&resp[..n], b"tunnel-ok");
    proxy_task.await.unwrap();
}

/// Plain socks5 keeps the existing IP-only target contract (local DNS).
#[tokio::test]
async fn socks5_requires_ip_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_task = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.expect("proxy accept");
        let mut methods = [0u8; 3];
        conn.read_exact(&mut methods).await.unwrap();
        conn.write_all(&[0x05, 0x00]).await.unwrap();
        // No CONNECT expected — the client must fail before sending one.
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_millis(500), conn.read(&mut buf))
            .await
            .unwrap_or_else(|_| Ok(0))
            .unwrap();
        assert_eq!(n, 0, "socks5 must reject a hostname target before CONNECT");
    });

    // Hostname target (localhost resolves locally) with plain socks5 → the
    // proxy branch requires an IP and must fail.
    let mut dial_opts = opts(format!("socks5://{proxy_addr}"), 7000);
    dial_opts.server_addr = "localhost".to_string();
    let err = dial_server(&dial_opts).await.expect_err("socks5 hostname must fail");
    assert!(
        err.to_string().contains("socks5h"),
        "unexpected error: {err}"
    );
    proxy_task.await.unwrap();
}
