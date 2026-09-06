//! Audit-fix regression tests for server vhost/bridge findings:
//! - duplicate Host headers are rejected with 400 (RFC 7230 §5.4 — Go frp's
//!   net/http server rejects them the same way)
//! - the vhost head read has a single total deadline (slow-drip slowloris
//!   must not stretch the head to 4096 × timeout)
//! - Authorization carried in the body (after \r\n\r\n) must not
//!   authenticate the request
//! - a fragmented TLS ClientHello (short SNI-peek read) is replayed intact,
//!   so the TLS handshake still succeeds
//! - an unterminated (truncated) request head — head-deadline expiry or
//!   mid-head close — is never parsed or forwarded: the connection closes
//!   with no response bytes (audit round 8 F7)

mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{
    allocate_port, login_with_test_token, read_until_eof, start_test_server, test_auth_cfg,
    GO_404_NOT_FOUND_RESPONSE,
};
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

/// Read the StartWorkConn for a dispatched user conn from a pooled work
/// conn. This harness reads its provider conn only for the NewProxyResp, so
/// it cannot answer the server's ReqWorkConn: if the user-conn dispatch
/// beats the pool registration, the conn lands on the server's pending
/// queue and the pooled conn would stay silent until the 90s heartbeat
/// kill. When the current conn stays silent for 2s, a fresh pool conn is
/// opened — the pending queue pops on the next NewWorkConn and the
/// StartWorkConn arrives on that conn — and the read moves to it. Returns
/// the conn that actually carried the frame.
async fn take_start_work_conn(
    addr: SocketAddr,
    run_id: &str,
    mut work_conn: tokio::net::TcpStream,
) -> (tokio::net::TcpStream, Box<msg::StartWorkConn>) {
    for attempt in 0..12 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            read_msg_v1(&mut work_conn),
        )
        .await
        {
            Ok(Ok(FrpMessage::StartWorkConn(swc))) => return (work_conn, swc),
            Ok(Ok(other)) => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
            Ok(Err(e)) => panic!("StartWorkConn read failed: {e:?}"),
            Err(_elapsed) => {
                // Dispatch raced the pool registration and queued the user
                // conn as pending; answer it with a fresh pool conn.
                work_conn = pool_work_conn(addr, run_id).await;
            }
        }
    }
    panic!("StartWorkConn never arrived after 12 pooled conns")
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
    // No proxy needed: the incomplete-head close runs before routing.

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

    // The deadline must release the connection with NO response bytes —
    // audit-round-8 F7: an unterminated head is never parsed, so nothing is
    // answered, and Go net/http parity for a mid-head timeout is a silent
    // close (net/http conn.serve: a read-timeout error is an
    // isCommonNetReadError → "return // don't reply"). The OLD code parsed
    // the truncated head after the deadline and happened to answer 400 only
    // because this particular head lacked a Host header — with a Host it
    // would have been forwarded (the F7 bug). EOF and RST are both valid
    // releases (RST when drip bytes are still buffered unread at the close).
    let mut resp = vec![0u8; 512];
    match tokio::time::timeout(std::time::Duration::from_secs(3), client_rd.read(&mut resp)).await {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!(
            "incomplete head must be closed with NO response, got {n} bytes: {:?}",
            String::from_utf8_lossy(&resp[..n])
        ),
        Err(_) => panic!("server must cut the head off within the total deadline"),
    }
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

// ---------------------------------------------------------------
// Audit-r7: Go NotFoundResponse parity + textproto EOL heads
// ---------------------------------------------------------------

/// Audit-r7 FIX 3: an HTTP GET whose Host matches no registered vhost route
/// is answered with frp-rs's fixed-shape NotFoundResponse — the raw Go
/// `NotFoundResponse` (pkg/util/http/http.go) written direct: a 92-byte head
/// (Content-Length: 489, Content-Type: text/html, Server: frp/0.71.0) plus
/// the 489-byte builtin HTML body = 581 bytes, then close. The old Rust
/// answer (a bare 404 with `Content-Length: 0`, no body) diverged. Note:
/// this pins the pre-built fixed shape, not a live Go byte capture — Go's
/// own GET route-miss additionally passes through net/http's server layer
/// (Date header etc.), which this raw write omits by design (same as the
/// CONNECT path).
#[tokio::test]
async fn test_vhost_get_route_miss_go_not_found_response() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    // Register a proxy so the vhost router is live; query an UNKNOWN host.
    let (_provider, _run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "known-only",
            vec!["known.example.com".into()],
            None,
            None,
        ))),
    )
    .await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: missing.example.com\r\n\r\n")
        .await
        .expect("send request");

    let bytes = read_until_eof(&mut client).await;
    assert_eq!(
        bytes,
        GO_404_NOT_FOUND_RESPONSE.as_bytes(),
        "expected the Go NotFoundResponse (581 bytes), got: {}",
        String::from_utf8_lossy(&bytes)
    );
    drop(client);
}

/// Audit-r7 FIX 1/2: a GET whose head uses bare-LF header lines with a CRLF
/// blank line is legal Go textproto — it must be routed promptly (the old
/// `\r\n\r\n`-window scan never terminated: the head only stalled until the
/// read deadline) and forwarded re-encoded CRLF (Go net/http Request.Write
/// parity — the injected X-Forwarded-* chain must not sit behind bare-LF
/// lines).
#[tokio::test]
async fn test_vhost_get_bare_lf_head_routed_canonical_crlf() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "lf-get",
            vec!["lfget.example.com".into()],
            None,
            None,
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // LF-only header lines + CRLF blank line: contains neither \r\n\r\n nor
    // \n\n (the textproto head_end helper's motivating shape).
    client
        .write_all(b"GET / HTTP/1.1\nHost: lfget.example.com\n\r\n")
        .await
        .expect("send bare-LF request");

    // The request must be dispatched promptly (3s — the old window scan
    // stalled until the ~60s head deadline).
    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_msg_v1(&mut work_conn),
    )
    .await
    .expect("timeout: the bare-LF head never terminated")
    .expect("read StartWorkConn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
    let head = read_forwarded_head(&mut work_conn).await;
    assert_eq!(
        head,
        b"GET / HTTP/1.1\r\n\
          Host: lfget.example.com\r\n\
          X-Forwarded-For: 127.0.0.1\r\n\
          X-Forwarded-Host: lfget.example.com\r\n\
          X-Forwarded-Proto: http\r\n\
          \r\n",
        "the mixed-EOL head must be re-encoded CRLF (Go Request.Write parity), got: {}",
        String::from_utf8_lossy(&head)
    );
    drop(client);
}

/// Audit-r7 FIX 1/2: a CONNECT whose request line is LF-terminated while its
/// Host line + blank are CRLF (mixed EOL) is legal Go textproto — it must
/// route (bypassing host_header_rewrite / X-Forwarded-* like every CONNECT)
/// with the head re-encoded CRLF at the backend.
#[tokio::test]
async fn test_vhost_connect_mixed_eol_head_routed_canonical_crlf() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    // Configure rewrite + injection on the route: the CONNECT must bypass
    // both (Go connectHandler forwards req.Write RAW) yet still be
    // canonicalized to CRLF.
    let mut np = http_proxy(
        "tunnel-conn",
        vec!["tunnel-mix.example.com".into()],
        None,
        None,
    );
    np.host_header_rewrite = Some("backend.internal".into());
    np.headers = Some(std::collections::HashMap::from([(
        "X-Injected".to_string(),
        "no".to_string(),
    )]));
    let (_provider, run_id) = register_proxy(addr, FrpMessage::NewProxy(Box::new(np))).await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"CONNECT tunnel-mix.example.com:443 HTTP/1.1\n\
              Host: tunnel-mix.example.com:443\r\n\
              \r\n",
        )
        .await
        .expect("send mixed-EOL CONNECT");

    match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        read_msg_v1(&mut work_conn),
    )
    .await
    .expect("timeout: the mixed-EOL CONNECT never terminated")
    .expect("read StartWorkConn")
    {
        FrpMessage::StartWorkConn(swc) => {
            assert!(swc.error.is_none(), "StartWorkConn error: {:?}", swc.error);
        }
        other => panic!("expected StartWorkConn, got {:?}", other.v1_type_byte()),
    }
    let head = read_forwarded_head(&mut work_conn).await;
    assert_eq!(
        head,
        b"CONNECT tunnel-mix.example.com:443 HTTP/1.1\r\n\
          Host: tunnel-mix.example.com:443\r\n\
          \r\n",
        "CONNECT must bypass rewrite/injection but re-encode the head CRLF, got: {}",
        String::from_utf8_lossy(&head)
    );
    // No line ending may be a bare LF: every '\n' must be preceded by '\r'.
    // (A "\nH" window check would false-positive on the canonical "\r\nH" —
    // the discriminator is the byte before the '\n'.)
    let mut prev_cr = false;
    let bare_lf = head.iter().any(|&b| {
        let bare = b == b'\n' && !prev_cr;
        prev_cr = b == b'\r';
        bare
    });
    assert!(
        !bare_lf,
        "no bare-LF line may survive the re-encode: {}",
        String::from_utf8_lossy(&head)
    );
    drop(client);
}

/// Audit-r7 FIX 5 guard (Go dedicated-listener semantics): a CONNECT to an
/// http_user-protected vhost route WITHOUT credentials must answer a SINGLE
/// 407 — NO preceding 200. The successHook 200-then-407 order belongs to
/// the tcpmux shared listener only; the vhost HTTP dedicated listener 407s
/// directly. Shape = Go `checkRouteAuthByRequest` + `http.Error` render
/// (pkg/util/vhost/http.go:272-274): fixed fields Content-Length: 30 /
/// Content-Type: text/plain; charset=utf-8 / Proxy-Authenticate (realm
/// "Restricted") / X-Content-Type-Options: nosniff + the StatusText body
/// with Go's trailing '\n' (round-3 review — the old bare 3-line 407
/// matched neither the fixed shape nor Go's fields).
#[tokio::test]
async fn test_vhost_connect_auth_route_no_creds_single_407_http_error_shape() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, _run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "auth-conn",
            vec!["auconn.example.com".into()],
            Some("user"),
            Some("pass"),
        ))),
    )
    .await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"CONNECT auconn.example.com:443 HTTP/1.1\r\n\
              Host: auconn.example.com:443\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT without credentials");

    let bytes = read_until_eof(&mut client).await;
    assert_eq!(
        bytes,
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
          Content-Length: 30\r\n\
          Content-Type: text/plain; charset=utf-8\r\n\
          Proxy-Authenticate: Basic realm=\"Restricted\"\r\n\
          X-Content-Type-Options: nosniff\r\n\
          \r\n\
          Proxy Authentication Required\n",
        "vhost CONNECT auth failure must be a single 407 http.Error render (no preceding 200), got: {}",
        String::from_utf8_lossy(&bytes)
    );
    drop(client);
}

// ---------------------------------------------------------------
// F7 (audit round 8): an unterminated (truncated) request head — deadline
// expiry or mid-head close with fewer than 4096 bytes buffered — must never
// be parsed and forwarded. Forwarding a head that lacks its blank-line
// terminator leaves the backend blocked waiting for the rest of the head,
// pinning a work-conn slot indefinitely (attacker: partial head then
// silence). Go's vhost http.Server never dispatches an unterminated head:
// mid-head timeout and EOF are both isCommonNetReadError cases that net/
// http answers with NO response bytes (silent close); only the 4096-cap
// analog of Go's errTooLarge answers (431).
// ---------------------------------------------------------------

/// A partial request head — valid request line and headers but NO closing
/// blank line — followed by the client half-closing (FIN) must not be
/// dispatched to a backend, and the client connection must be closed with
/// no response bytes. Pre-fix the head-read loop broke on EOF and the
/// truncated head was routed and forwarded as-is (the parse reads only up
/// to head_end or the buffered length, so a valid request line + Host was
/// enough to dispatch).
#[tokio::test]
async fn test_vhost_partial_head_then_eof_not_forwarded() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let (_provider, run_id) = register_proxy(
        addr,
        FrpMessage::NewProxy(Box::new(http_proxy(
            "f7-partial-head",
            vec!["f7.example.com".into()],
            None,
            None,
        ))),
    )
    .await;
    let mut work_conn = pool_work_conn(addr, &run_id).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    // Valid request line + headers — but the head never ends: no blank line
    // is sent, then the write side half-closes (FIN), exactly like an
    // attacker that sends a partial head and goes away.
    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: f7.example.com\r\n\
              User-Agent: partial-head-no-terminator\r\n",
        )
        .await
        .expect("send partial head");
    client.shutdown().await.expect("half-close the write side");

    // The unterminated head must not be dispatched: no StartWorkConn may
    // reach the pooled work conn (the only way this vhost proxy contacts a
    // backend).
    let swc = tokio::time::timeout(
        std::time::Duration::from_millis(800),
        read_msg_v1(&mut work_conn),
    )
    .await;
    assert!(
        swc.is_err(),
        "unterminated head must not be forwarded (StartWorkConn reached a backend)"
    );

    // ...and the client connection must be closed (clean EOF) rather than
    // held open by the server waiting for a backend exchange that never
    // happens.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("server must close the conn after an unterminated head")
        .expect("read from closed conn");
    assert_eq!(
        n,
        0,
        "server must send NO response bytes for an unterminated head, got: {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    drop(client);
    drop(_provider);
}

// ---------------------------------------------------------------
// Round-13 (F1#2): response-header injector gates
// ---------------------------------------------------------------

/// Round-13 (F1#2): a CONNECT tunnel routed on an http proxy that HAS
/// `response_headers` configured must pass the backend's response to the
/// tunnel user byte-exact — Go's connectHandler joins raw and
/// ModifyResponse never runs (pkg/util/vhost/http.go:282-285). RED pre-fix:
/// the bridge injector armed on every `proxy_type == "http"` response
/// regardless of request method and spliced configured headers into the
/// tunnel stream.
#[tokio::test]
async fn test_vhost_connect_response_headers_not_injected_into_tunnel() {
    let (addr, vhost_addr, cfg) = vhost_pair();
    let (_handle, _) = start_test_server(cfg).await;

    let mut np = http_proxy(
        "tunnel-rh",
        vec!["tunnel-rh.example.com".into()],
        None,
        None,
    );
    np.response_headers = Some(std::collections::HashMap::from([(
        "X-Backend-Resp".to_string(),
        "injected".to_string(),
    )]));
    let (_provider, run_id) = register_proxy(addr, FrpMessage::NewProxy(Box::new(np))).await;

    let mut client = tokio::net::TcpStream::connect(vhost_addr)
        .await
        .expect("vhost connect");
    client
        .write_all(
            b"CONNECT tunnel-rh.example.com:443 HTTP/1.1\r\n\
              Host: tunnel-rh.example.com\r\n\
              \r\n",
        )
        .await
        .expect("send CONNECT");

    let work_conn = pool_work_conn(addr, &run_id).await;
    let (mut work_conn, swc) = take_start_work_conn(addr, &run_id, work_conn).await;
    assert!(swc.error.is_none(), "{:?}", swc.error);

    // The CONNECT head reaches the backend raw (request-side parity is
    // pinned by test_vhost_http_connect_forwards_raw; this test pins the
    // RESPONSE direction).
    let head = read_forwarded_head(&mut work_conn).await;
    assert!(
        String::from_utf8_lossy(&head).starts_with("CONNECT tunnel-rh.example.com:443"),
        "CONNECT head must reach the backend, got: {:?}",
        String::from_utf8_lossy(&head)
    );

    // Backend answers the tunnel the way an upstream HTTP proxy does: a
    // response head followed by opaque tunnel bytes. response_headers is
    // configured on this route — nothing may be spliced in.
    let backend_bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nTUNNEL-DATA-1";
    work_conn
        .write_all(backend_bytes)
        .await
        .expect("backend response");

    let mut resp = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut chunk))
            .await
            .expect("tunnel response within 5s")
            .expect("read tunnel response");
        resp.extend_from_slice(&chunk[..n]);
        if resp.len() >= backend_bytes.len() {
            break;
        }
    }
    assert_eq!(
        &resp[..],
        backend_bytes,
        "CONNECT tunnel bytes must reach the user byte-exact (no response_headers injection)"
    );
    drop(client);
    drop(_provider);
}

/// Round-13 (F1#2): `response_headers` declared on an https proxy must
/// never run the injector — Go drops the field at config time
/// (HTTPSProxyConfig in pkg/config/v1/proxy.go has no ResponseHeaders), and
/// the https leg carries opaque TLS anyway. RED pre-fix: the bridge
/// injector's `starts_with("http")` gate armed on https legs and buffered
/// the TLS backend's handshake flight waiting for an HTTP head boundary
/// that never comes — the TLS handshake starved and the tunnel never
/// established. The pin: a full rustls handshake through the https leg
/// (backend = real rustls server on the pooled work conn) plus a plaintext
/// echo.
#[tokio::test]
async fn test_https_declared_response_headers_tls_handshake_completes() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let (addr, _vhost_addr, mut cfg) = vhost_pair();
    // HTTPS proxies route on the dedicated vhost HTTPS listener (main-port
    // SNI sniff was removed for Go parity) — without a vhost_https_port the
    // SNI route has no listener and the dispatch never fires.
    let https_port = allocate_port();
    cfg.vhost_https_port = https_port;
    let https_addr: SocketAddr = format!("127.0.0.1:{https_port}")
        .parse()
        .expect("https addr");
    let (_handle, _) = start_test_server(cfg).await;

    // An https proxy with response_headers declared on the wire (Go would
    // silently drop it at config load; frp-rs stores it but the bridge gate
    // must never apply it).
    let mut np = https_proxy("tls-rh", vec!["tls-rh.example.com".into()]);
    np.response_headers = Some(std::collections::HashMap::from([(
        "X-Injected".to_string(),
        "yes".to_string(),
    )]));
    let (_provider, run_id) = register_proxy(addr, FrpMessage::NewProxy(Box::new(np))).await;

    // Client side (NoVerify) handshakes through the SNI https route on the
    // vhost HTTPS port; the backend side is a real rustls server answering
    // from the pooled work conn.
    let client_cfg = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    );
    let server_name: tokio_rustls::rustls::pki_types::ServerName<'static> =
        "tls-rh.example.com".try_into().expect("server name");
    let addr_for_task = https_addr;
    let client_task = tokio::spawn(async move {
        let raw = tokio::net::TcpStream::connect(addr_for_task)
            .await
            .expect("connect to vhost https route");
        tokio_rustls::TlsConnector::from(client_cfg)
            .connect(server_name, raw)
            .await
    });

    let work_conn = pool_work_conn(addr, &run_id).await;
    let (work_conn, swc) = take_start_work_conn(addr, &run_id, work_conn).await;
    assert!(swc.error.is_none(), "{:?}", swc.error);
    // Round-12 B1: ONLY type=http legs drop the dst pair — https legs
    // keep the real server-side local addr (Go handleUserTCPConnection
    // proxy.go:288). The https leg here must carry it: the frpc
    // PROXY-header fallback (127.0.0.1:0) is for http legs alone.
    assert_eq!(
        swc.dst_addr.as_deref(),
        Some("127.0.0.1"),
        "https leg must report the accept socket's local addr as dst: {:?}",
        swc.dst_addr
    );
    assert!(
        swc.dst_port.is_some_and(|p| p != 0),
        "https leg dst_port must be the real accept port: {:?}",
        swc.dst_port
    );
    let mut backend_tls = tokio_rustls::TlsAcceptor::from(Arc::new(
        frp_core::transport::generate_self_signed_tls_config().expect("self-signed TLS config"),
    ))
    .accept(work_conn)
    .await
    .expect(
        "backend TLS handshake must complete — the https leg must relay raw TLS, \
         not buffer it in an injector looking for an HTTP head",
    );
    let mut client_tls = client_task
        .await
        .expect("client task")
        .expect("client TLS handshake must complete");

    // Plaintext echo through the tunnel: the TLS records flow intact.
    client_tls.write_all(b"ping").await.expect("client write");
    let mut echo = [0u8; 4];
    backend_tls
        .read_exact(&mut echo)
        .await
        .expect("backend read");
    assert_eq!(&echo, b"ping", "backend must receive client plaintext");
    backend_tls.write_all(b"pong").await.expect("backend write");
    client_tls.read_exact(&mut echo).await.expect("client read");
    assert_eq!(&echo, b"pong", "client must receive backend plaintext");

    drop(client_tls);
    drop(backend_tls);
    drop(_provider);
}
