//! Audit-fix regression tests for server vhost/bridge findings:
//! - duplicate Host headers are rejected with 400 (RFC 7230 §5.4 — Go frp's
//!   net/http server rejects them the same way)
//! - the vhost head read has a single total deadline (slow-drip slowloris
//!   must not stretch the head to 4096 × timeout)
//! - Authorization carried in the body (after \r\n\r\n) must not
//!   authenticate the request
//! - a fragmented TLS ClientHello (short SNI-peek read) is replayed intact,
//!   so the TLS handshake still succeeds

mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{allocate_port, login_with_test_token, start_test_server, test_auth_cfg};
use frp_core::config::ServerConfig;
use frp_core::msg::{self, FrpMessage, NewProxy};
use frp_core::protocol::{read_msg_v1, write_msg_v1};

fn http_proxy(
    name: &str,
    domains: Vec<String>,
    http_user: Option<&str>,
    http_pwd: Option<&str>,
) -> NewProxy {
    NewProxy {
        proxy_name: name.into(),
        proxy_type: "http".into(),
        sk: None,
        use_encryption: None,
        use_compression: None,
        group: None,
        group_key: None,
        local_str: Some("127.0.0.1:8080".into()),
        remote_port: Some(0),
        custom_domains: Some(domains),
        subdomain: None,
        locations: None,
        http_user: http_user.map(String::from),
        http_pwd: http_pwd.map(String::from),
        host_header_rewrite: None,
        headers: None,
        response_headers: None,
        route_by_http_user: None,
        allow_users: None,
        bandwidth_limit: None,
        bandwidth_limit_mode: None,
        annotations: None,
        metas: None,
        multiplexer: None,
        virtual_net: None,
        proxy_protocol_version: None,
        advertise_subnet: None,
        vnet_ip: None,
        vnet_netmask: None,
        vnet_mtu: None,
    }
}

fn https_proxy(name: &str, domains: Vec<String>) -> NewProxy {
    NewProxy {
        proxy_type: "https".into(),
        ..http_proxy(name, domains, None, None)
    }
}

/// Login as the provider and register `np`; returns the provider conn and run_id.
async fn register_proxy(
    addr: SocketAddr,
    np: FrpMessage,
) -> (frp_core::transport::IoStream, String) {
    let (mut provider, resp) = login_with_test_token(addr).await.expect("provider login");
    let run_id = resp.run_id.expect("run_id");
    write_msg_v1(&mut provider, &np)
        .await
        .expect("send NewProxy");
    match read_msg_v1(&mut provider).await.expect("NewProxyResp") {
        FrpMessage::NewProxyResp(ref r) => {
            assert!(r.error.is_none(), "registration failed: {:?}", r.error);
        }
        other => panic!("expected NewProxyResp, got {:?}", other.v1_type_byte()),
    }
    (provider, run_id)
}

/// Open a work conn that pools on the server.
async fn pool_work_conn(addr: SocketAddr, run_id: &str) -> tokio::net::TcpStream {
    let mut work_conn = tokio::net::TcpStream::connect(addr)
        .await
        .expect("work conn");
    write_msg_v1(
        &mut work_conn,
        &FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.into()),
            timestamp: None,
            privilege_key: None,
        }),
    )
    .await
    .expect("send NewWorkConn");
    work_conn
}

fn vhost_pair() -> (SocketAddr, SocketAddr, ServerConfig) {
    let bind_port = allocate_port();
    let vhost_port = allocate_port();
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port,
        vhost_http_port: vhost_port,
        auth: test_auth_cfg(),
        ..Default::default()
    };
    (
        format!("127.0.0.1:{}", bind_port).parse().unwrap(),
        format!("127.0.0.1:{}", vhost_port).parse().unwrap(),
        cfg,
    )
}

/// Assert the server answers `expect_prefix` and that no StartWorkConn is
/// written to the pooled work conn within a short window (the request must
/// not be forwarded).
async fn assert_rejected_and_not_forwarded(
    client: &mut tokio::net::TcpStream,
    work_conn: &mut tokio::net::TcpStream,
    expect_prefix: &str,
) {
    let mut resp = vec![0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut resp))
        .await
        .expect("server must answer within 2s")
        .expect("read response");
    let text = String::from_utf8_lossy(&resp[..n]);
    assert!(
        text.starts_with(expect_prefix),
        "expected {expect_prefix:?}, got: {text:?}"
    );
    let swc = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        read_msg_v1(work_conn),
    )
    .await;
    assert!(
        swc.is_err(),
        "rejected request must not reach a backend (StartWorkConn sent)"
    );
}

// ---------------------------------------------------------------
// Finding 3: duplicate Host headers → 400
// ---------------------------------------------------------------

#[tokio::test]
async fn test_vhost_rejects_duplicate_host_headers() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "dup-host",
            vec!["app.example.com".into()],
            None,
            None,
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: app.example.com\r\n\
              Host: evil.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    // RFC 7230 §5.4: multiple Host headers are invalid → 400 (Go frp's
    // net/http server rejects with 400 too).
    assert_rejected_and_not_forwarded(&mut client, &mut work_conn, "HTTP/1.1 400").await;
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// Finding 4: vhost head read has a single total deadline
// ---------------------------------------------------------------

#[tokio::test]
async fn test_vhost_head_total_deadline_caps_slow_drip() {
    let (_addr, vhost_addr, mut cfg) = vhost_pair();
    // 1s total deadline for the whole head.
    cfg.vhost_http_timeout = 1;
    let (_handle, _) = start_test_server(cfg).await;
    // No proxy needed: the 400-on-incomplete-head path runs before routing.

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // Partial head, no terminator yet.
    client
        .write_all(b"GET / HTTP/1.1\r\n")
        .await
        .expect("send partial head");
    // Drip one byte every 150ms: each individual read is well inside the 1s
    // per-read window, so the OLD per-read timeout never fired; the total
    // deadline must still cut the head off after ~1s.
    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let drip = tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            if client_wr.write_all(b"a").await.is_err() {
                break;
            }
        }
    });

    let mut resp = vec![0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client_rd.read(&mut resp))
        .await
        .expect("server must cut the head off within the total deadline")
        .expect("read response");
    let text = String::from_utf8_lossy(&resp[..n]);
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "incomplete head must be rejected with 400, got: {text:?}"
    );
    let _ = drip.await;
}

// ---------------------------------------------------------------
// Finding 5: body bytes after \r\n\r\n must not authenticate
// ---------------------------------------------------------------

#[tokio::test]
async fn test_vhost_body_cannot_carry_authorization() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "auth-proxy",
            vec!["auth.example.com".into()],
            Some("user"),
            Some("pass"),
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // The Authorization header is smuggled into the BODY (after \r\n\r\n).
    // "dXNlcjpwYXNz" = base64("user:pass"). Only the head up to the first
    // \r\n\r\n may be parsed, so this must NOT authenticate.
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: auth.example.com\r\n\
              \r\n\
              authorization: Basic dXNlcjpwYXNz",
        )
        .await
        .expect("send request");

    assert_rejected_and_not_forwarded(&mut client, &mut work_conn, "HTTP/1.1 401").await;
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// Finding 2: fragmented TLS ClientHello — short SNI-peek reads must be
// replayed, not discarded
// ---------------------------------------------------------------

/// TLS certificate verifier that accepts any certificate (the server uses
/// an auto-generated self-signed cert).
#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[tokio::test]
async fn test_tls_sni_peek_short_read_replays_bytes() {
    // The rustls crypto provider must be installed for this test binary
    // (the server installs it for its own acceptors, but be explicit).
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let (addr, _vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    // Register an HTTPS proxy so the main-port accept path arms the SNI
    // peek (https_proxy_count > 0).
    let (_provider, _run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(https_proxy(
            "sni-app",
            vec!["app.example.com".into()],
        ))),
    )
    .await;

    // Build a real rustls client and split-write its ClientHello so the
    // server's SNI-peek read returns a short (< 43 byte) chunk: the first
    // 17 bytes arrive alone (7 consumed by magic detection + 10 for the
    // peek), the rest only after a pause. The peeked bytes must be
    // replayed for the TLS handshake to succeed.
    let server_name = "app.example.com".try_into().expect("server name");
    let client_cfg = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    );
    let mut conn =
        tokio_rustls::rustls::ClientConnection::new(client_cfg, server_name).expect("client conn");
    // The ClientHello is the conn's first outbound TLS record.
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).expect("client hello bytes");
    assert!(
        hello.len() > 43,
        "real ClientHello must exceed the peek threshold"
    );

    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(&hello[..17]).await.expect("hello part 1");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    sock.write_all(&hello[17..]).await.expect("hello part 2");

    // Manual TLS driver (rustls 0.23): `read_tls`/`write_tls` move the
    // encrypted bytes; `reader()`/`writer()` expose plaintext.
    let mut rd = [0u8; 8192];
    async fn flush_outbound(
        conn: &mut tokio_rustls::rustls::ClientConnection,
        sock: &mut tokio::net::TcpStream,
    ) {
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out).expect("tls out");
            if out.is_empty() {
                break;
            }
            sock.write_all(&out).await.expect("tls write");
        }
    }
    while conn.is_handshaking() {
        flush_outbound(&mut conn, &mut sock).await;
        let n = sock.read(&mut rd).await.expect("tls read");
        assert!(
            n > 0,
            "server closed during TLS handshake — ClientHello bytes were not replayed"
        );
        conn.read_tls(&mut &rd[..n]).expect("read_tls");
        conn.process_new_packets().expect("process tls");
    }

    // Send a V1 Login over the TLS connection; the server must answer with
    // a plaintext LoginResp (CFB wrapping starts after LoginResp).
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token("test-token", ts);
    let login = FrpMessage::Login(Box::new(msg::Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("sni-short-read-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(ts),
        privilege_key: Some(key),
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));
    let mut frame = Vec::new();
    write_msg_v1(&mut frame, &login)
        .await
        .expect("serialize login");
    conn.writer()
        .write_all(&frame)
        .expect("tls plaintext write");
    flush_outbound(&mut conn, &mut sock).await;

    // Read the LoginResp frame (V1 framing: 1-byte type + 8-byte BE length).
    let mut plain = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let n = sock.read(&mut rd).await.expect("read");
            assert!(n > 0, "server closed before LoginResp");
            conn.read_tls(&mut &rd[..n]).expect("read_tls");
            conn.process_new_packets().expect("process tls");
            flush_outbound(&mut conn, &mut sock).await;
            let mut buf = [0u8; 8192];
            loop {
                match conn.reader().read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => plain.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            if !plain.is_empty() {
                break;
            }
        }
    })
    .await
    .expect("LoginResp within 5s");

    assert!(plain.len() >= 9, "LoginResp frame too short: {plain:?}");
    let frame_len = u64::from_be_bytes(plain[1..9].try_into().unwrap()) as usize;
    assert!(
        plain.len() >= 9 + frame_len,
        "LoginResp frame truncated: {plain:?}"
    );
    let payload = &plain[9..9 + frame_len];
    let parsed: serde_json::Value =
        serde_json::from_slice(payload).expect("LoginResp must be valid JSON");
    assert!(
        parsed.get("run_id").is_some(),
        "LoginResp must carry run_id: {payload:?}"
    );
    assert!(
        parsed.get("error").is_none_or(|e| e.is_null()),
        "login must succeed: {payload:?}"
    );
    drop(sock);
    drop(_provider);
}
