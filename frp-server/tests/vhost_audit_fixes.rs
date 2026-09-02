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

/// Read raw bytes until the end of the HTTP/1.1 request head (`\r\n\r\n`).
/// Returns the head plus any body bytes that arrived with it.
async fn read_forwarded_head(work_conn: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return buf;
        }
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            work_conn.read(&mut chunk),
        )
        .await
        .expect("timeout reading forwarded request")
        .expect("read forwarded request");
        assert!(n > 0, "unexpected EOF while reading request head");
        buf.extend_from_slice(&chunk[..n]);
    }
}

// ---------------------------------------------------------------
// HTTP Basic Auth matrix (positive path + rejection variants)
// ---------------------------------------------------------------

/// Correct Basic credentials must be forwarded to the provider: the work
/// conn receives StartWorkConn and the request head (with the
/// Authorization header intact).
#[tokio::test]
async fn test_vhost_basic_auth_correct_credentials_forwarded() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "auth-pos",
            vec!["pos.example.com".into()],
            Some("user"),
            Some("pass"),
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // base64("user:pass") = dXNlcjpwYXNz
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: pos.example.com\r\n\
              Authorization: Basic dXNlcjpwYXNz\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    // The request must be dispatched: StartWorkConn on the work conn…
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
    // …and the head forwarded with the Authorization header intact.
    let head = read_forwarded_head(&mut work_conn).await;
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("GET / HTTP/1.1\r\n"), "head: {text}");
    assert!(
        text.contains("Authorization: Basic dXNlcjpwYXNz\r\n"),
        "Authorization must be forwarded intact, head: {text}"
    );
    drop(client);
}

/// Wrong password, wrong username, and a missing Authorization header must
/// all yield 401 and never reach a backend.
#[tokio::test]
async fn test_vhost_basic_auth_rejects_bad_or_missing_credentials() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "auth-matrix",
            vec!["matrix.example.com".into()],
            Some("user"),
            Some("pass"),
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    // base64("user:wrong") = dXNlcjp3cm9uZw==
    let wrong_pwd = b"dXNlcjp3cm9uZw==";
    // base64("evil:pass") = ZXZpbDpwYXNz
    let wrong_user = b"ZXZpbDpwYXNz";

    for (label, auth_line) in [
        (
            "wrong password",
            Some(format!(
                "Authorization: Basic {}\r\n",
                String::from_utf8_lossy(wrong_pwd)
            )),
        ),
        (
            "wrong username",
            Some(format!(
                "Authorization: Basic {}\r\n",
                String::from_utf8_lossy(wrong_user)
            )),
        ),
        ("missing header", None),
    ] {
        let mut client = tokio::net::TcpStream::connect(vhost_addr)
            .await
            .expect("vhost connect");
        let mut request = format!(
            "GET / HTTP/1.1\r\nHost: matrix.example.com\r\n{}",
            auth_line.unwrap_or_default()
        );
        request.push_str("\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        assert_rejected_and_not_forwarded(&mut client, &mut work_conn, "HTTP/1.1 401").await;
        drop(client);
        println!("{label}: 401 verified");
    }
    drop(_provider);
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

// ---------------------------------------------------------------
// Round-15: X-Forwarded-For is appended even when the proxy configures
// response headers
// ---------------------------------------------------------------

/// The X-Forwarded-For append must run UNCONDITIONALLY (Go's Rewrite hook
/// always calls SetXForwarded — a configured header list is not a gate).
/// Round-14 regression shape: the old combined request/response header
/// injection skipped the XFF append whenever response-header config was
/// present; this test pins the current behavior with `response_headers`
/// set on the proxy.
#[tokio::test]
async fn test_vhost_xff_appended_with_response_headers_configured() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let mut np = http_proxy("xff-resp", vec!["xff.example.com".into()], None, None);
    let mut response_headers = std::collections::HashMap::new();
    response_headers.insert("X-Backend-Resp".into(), "yes".into());
    np.response_headers = Some(response_headers);
    let (_provider, run_id) = register_proxy(addr, FrpMessage::NewProxy(Box::new(np))).await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // No X-Forwarded-For in the request.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: xff.example.com\r\n\r\n")
        .await
        .expect("send request");

    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
    let head = read_forwarded_head(&mut work_conn).await;
    let text = String::from_utf8_lossy(&head);
    assert!(
        text.contains("X-Forwarded-For: 127.0.0.1\r\n"),
        "XFF must be appended despite response_headers config, head: {text}"
    );
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// Round-15: a request that opens with a blank line is malformed → 400
// ---------------------------------------------------------------

/// Go readRequest parity: a head whose FIRST line is empty (the request
/// opens with `\r\n`) is "malformed HTTP request" → 400 — the request must
/// not be routed or forwarded to any backend.
#[tokio::test]
async fn test_vhost_blank_first_line_400() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "blank-line",
            vec!["blank.example.com".into()],
            None,
            None,
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // The request line is empty — the head starts with a bare CRLF.
    client
        .write_all(
            b"\r\n\
              GET / HTTP/1.1\r\n\
              Host: blank.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send request");

    assert_rejected_and_not_forwarded(&mut client, &mut work_conn, "HTTP/1.1 400").await;
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// T1: HTTP/1.1 vhost oversized-head 431 (h2c had coverage; the
// HTTP/1.1 branch of the 4096-byte head cap had none)
// ---------------------------------------------------------------

/// A head that fills the 4096-byte cap without a `\r\n\r\n` terminator must
/// be answered with 431 Request Header Fields Too Large and must NOT be
/// forwarded to a backend (forwarding a truncated head makes the backend
/// block on the rest, tying up a work-conn slot — the DoS the 431 exists to
/// prevent). The h2c 431 path was already pinned in vhost_h2c.rs; this pins
/// the HTTP/1.1 branch (vhost.rs handle_http1_request cap check).
#[tokio::test]
async fn test_vhost_http1_oversized_head_431_not_forwarded() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "oversized-head",
            vec!["big.example.com".into()],
            None,
            None,
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // > 4096 bytes of header bytes with NO \r\n\r\n terminator. Sent in one
    // write; the server's sniff read may grab any prefix of it, but the head
    // loop must stop at 4096 and answer 431 regardless of segmentation.
    let mut head = Vec::with_capacity(6000);
    head.extend_from_slice(b"GET / HTTP/1.1\r\nHost: big.example.com\r\n");
    while head.len() < 5000 {
        head.extend_from_slice(b"X-Junk: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    client.write_all(&head).await.expect("send oversized head");

    assert_rejected_and_not_forwarded(&mut client, &mut work_conn, "HTTP/1.1 431").await;
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// T2: response_headers injection e2e (the injector chain had no
// e2e — a break in it would only surface via the compat Go binary)
// ---------------------------------------------------------------

/// A vhost HTTP proxy configured with `response_headers` must inject them
/// into the backend's response head before it reaches the client: the client
/// sees the backend status line + the injected header + the body, while the
/// raw response on the work conn carries none. Exercises the full chain:
/// vhost accept → bridge → ResponseHeaderInjector → client socket.
#[tokio::test]
async fn test_vhost_response_headers_injected_end_to_end() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let mut np = http_proxy("resp-headers", vec!["resp.example.com".into()], None, None);
    let mut response_headers = std::collections::HashMap::new();
    response_headers.insert("X-Backend-Resp".into(), "injected".into());
    np.response_headers = Some(response_headers);
    let (_provider, run_id) = register_proxy(addr, FrpMessage::NewProxy(Box::new(np))).await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: resp.example.com\r\n\r\n")
        .await
        .expect("send request");

    // The head is forwarded to the backend…
    match read_msg_v1(&mut work_conn).await.expect("StartWorkConn") {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
    let head = read_forwarded_head(&mut work_conn).await;
    assert!(
        String::from_utf8_lossy(&head).starts_with("GET / HTTP/1.1\r\n"),
        "request head must reach the backend"
    );

    // …and the backend answers WITHOUT the injected header on the raw conn.
    let backend_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    work_conn
        .write_all(backend_resp)
        .await
        .expect("backend response");

    // The client must see the response WITH the injected header.
    let mut resp = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("response within 5s")
            .expect("read response");
        resp.extend_from_slice(&chunk[..n]);
        if resp.len() >= backend_resp.len() {
            break;
        }
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "backend status line first, got: {text:?}"
    );
    assert!(
        text.contains("X-Backend-Resp: injected\r\n"),
        "injected header missing from client response: {text:?}"
    );
    assert!(
        text.contains("\r\n\r\nhello"),
        "body must follow the (injected) head: {text:?}"
    );
    drop(client);
    drop(_provider);
}
