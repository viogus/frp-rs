//! Integration tests for the HTTP bridge plugins (http2http/http2https/
//! https2http/https2https): request header injection and backend TLS policy.
//!
//! Go frp compat:
//! - `requestHeaders` injected with Set semantics (http_common.go
//!   rewriteHTTPPluginRequest).
//! - http2https/https2https connect to the HTTPS backend with
//!   InsecureSkipVerify (http2https.go:45, https2https.go:45).

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use frp_core::config::PluginConfig;
use frp_core::transport::IoStream;

fn plugin_cfg(plugin_type: &str, local_addr: String) -> PluginConfig {
    PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr,
        ..Default::default()
    }
}

/// Start a plaintext HTTP backend that captures the first request head and
/// replies 200 with a small body.
async fn start_capture_backend() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await;
        }
    });
    (addr, rx)
}

#[tokio::test]
async fn test_http2http_injects_request_headers() {
    let (backend_addr, rx) = start_capture_backend().await;
    let backend_addr = backend_addr.to_string();

    let mut cfg = plugin_cfg("http2http", backend_addr);
    cfg.request_headers = HashMap::from([
        ("X-Injected".to_string(), "from-config".to_string()),
        // Set semantics: overrides the same header from the client.
        ("X-Override".to_string(), "new-value".to_string()),
    ]);

    let handle = frp_client::plugin::start_http2http_plugin(&cfg)
        .await
        .expect("start http2http plugin");
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
    client
        .write_all(
            b"GET /test HTTP/1.1\r\n\
              Host: original.local\r\n\
              X-Override: old-value\r\n\
              \r\n",
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let req = rx.await.expect("backend captured request");
    assert!(
        req.contains("X-Injected: from-config"),
        "injected header missing: {req}"
    );
    assert!(
        req.contains("X-Override: new-value"),
        "configured header must override client value: {req}"
    );
    assert!(
        !req.contains("X-Override: old-value"),
        "client header must be replaced, not duplicated: {req}"
    );
}

/// http2https backend connects with InsecureSkipVerify: a self-signed TLS
/// backend must be accepted.
#[tokio::test]
#[cfg(feature = "tls")]
async fn test_http2https_accepts_self_signed_backend() {
    use std::sync::Arc;

    // Self-signed TLS backend that captures the request and replies 200.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let server_cfg = frp_core::transport::generate_self_signed_tls_config().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = vec![0u8; 8192];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = tls
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            }
        }
    });

    let cfg = plugin_cfg("http2https", backend_addr.to_string());
    let handle = frp_client::plugin::start_http2https_plugin(&cfg)
        .await
        .expect("start http2https plugin");
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
    client
        .write_all(b"GET /secure HTTP/1.1\r\nHost: backend.local\r\n\r\n")
        .await
        .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.0 200 OK"),
        "self-signed backend must be accepted (InsecureSkipVerify): {:?}",
        resp
    );

    let req = rx.await.expect("backend captured request");
    assert!(
        req.contains("GET /secure HTTP/1.0"),
        "unexpected forwarded request: {req}"
    );
    assert!(req.contains("Host: backend.local"), "got: {req}");
}

/// https2https backend connects with InsecureSkipVerify. Uses a real
/// TLS client on the tunnel side (rustls with a self-signed server cert).
#[tokio::test]
#[cfg(feature = "tls")]
async fn test_https2https_accepts_self_signed_backend() {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    // Self-signed backend.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let backend_cfg = frp_core::transport::generate_self_signed_tls_config().unwrap();
    let backend_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(backend_cfg));

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = backend_acceptor.accept(tcp).await {
                let mut buf = vec![0u8; 8192];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = tls
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await;
            }
        }
    });

    // Plugin listener certs: write the generated PEM pair to temp files.
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    // Generate a self-signed cert/key with rcgen (dev-dependency) and
    // write them as PEM (DER + base64 wrapping; rcgen 0.13 has no pem()).
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    let wrap_pem = |label: &str, der: &[u8]| -> String {
        let b64 = frp_core::base64::encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    };
    std::fs::write(&cert_path, wrap_pem("CERTIFICATE", cert.der())).unwrap();
    std::fs::write(
        &key_path,
        wrap_pem("PRIVATE KEY", &key_pair.serialize_der()),
    )
    .unwrap();

    let mut cfg = plugin_cfg("https2https", backend_addr.to_string());
    cfg.crt_file = cert_path.to_str().unwrap().to_string();
    cfg.key_file = key_path.to_str().unwrap().to_string();

    let handle = frp_client::plugin::start_https2https_plugin(&cfg)
        .await
        .expect("start https2https plugin");

    // Tunnel-side TLS client that skips verification (plugin cert is self-signed).
    let connector = frp_core::transport::build_tls_connector_skip_verify(None, None, None, false)
        .expect("tls connector");
    let tcp = TcpStream::connect(handle.local_addr).await.unwrap();
    let server_name = ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("tunnel tls connect");
    tls.write_all(b"GET /both HTTP/1.1\r\nHost: secure.local\r\n\r\n")
        .await
        .unwrap();
    // The plugin drops the connection after forwarding; rustls may report
    // UnexpectedEof instead of a clean close_notify — tolerate it.
    let mut resp = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
        }
    }
    assert!(
        resp.starts_with(b"HTTP/1.0 200 OK"),
        "self-signed backend must be accepted: {:?}",
        resp
    );

    let req = rx.await.expect("backend captured request");
    assert!(req.contains("GET /both HTTP/1.0"), "got: {req}");

    // IoStream import kept for API-surface sanity (tunnel side uses raw TLS).
    let _ = IoStream::Tcp;
}

/// Read one HTTP request from the backend side: the head plus exactly
/// `Content-Length` body bytes. A backend that waits for the full request
/// before responding is exactly what the plugin must satisfy — this helper
/// models that (Go-style) backend behavior.
async fn read_full_cl_request(conn: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head_end = end + 4;
            let head = String::from_utf8_lossy(&buf[..head_end]);
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse().ok())
                })
                .unwrap_or(0);
            while buf.len() < head_end + content_length {
                let n = conn.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return buf;
        }
        let n = conn.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Read one HTTP request with a chunked body from the backend side, stopping
/// at the terminating `0\r\n\r\n` (trailer-free chunked body).
async fn read_full_chunked_request(conn: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if buf.ends_with(b"0\r\n\r\n") {
            return buf;
        }
        let n = conn.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// POST with a Content-Length body far larger than one TCP read through the
/// shared HTTP/1.1 forward path (http2http): the backend must receive the
/// head plus the FULL body before it can answer. Regression test for the
/// audit finding where only the bytes that arrived with the head were
/// forwarded and the backend hung forever.
#[tokio::test]
async fn test_http2http_post_body_streams() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let req = read_full_cl_request(&mut conn).await;
            let _ = tx.send(req);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http2http".into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http2http_plugin(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    // The plugin's header read loop uses 512-byte chunks and stops at the
    // first \r\n\r\n, so at most ~511 body bytes can arrive with the head —
    // the rest must be drained from the stream.
    let body = vec![b'x'; 256 * 1024];
    client
        .write_all(
            format!(
                "POST /upload HTTP/1.1\r\nHost: original\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.write_all(&body).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded: request body was not fully forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    assert!(
        captured.starts_with(b"POST /upload HTTP/1.0"),
        "unexpected forwarded request: {}",
        String::from_utf8_lossy(&captured[..head_end])
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "backend must receive the full request body"
    );
}

/// POST with a chunked body through the shared forward path: the client's
/// chunk framing must reach the backend verbatim, with `Transfer-Encoding:
/// chunked` re-added to the head (the original is stripped as hop-by-hop).
#[tokio::test]
async fn test_http2http_post_body_chunked() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let req = read_full_chunked_request(&mut conn).await;
            let _ = tx.send(req);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http2http".into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http2http_plugin(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    client
        .write_all(b"POST /upload HTTP/1.1\r\nHost: original\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await
        .unwrap();
    client.write_all(body).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("chunked request body was not fully forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        head.contains("Transfer-Encoding: chunked"),
        "chunked framing must be re-added to the head: {head}"
    );
    assert!(
        !head.to_lowercase().contains("content-length"),
        "no Content-Length on a chunked request: {head}"
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "client chunk framing must be forwarded verbatim"
    );
}

/// http_proxy plugin: a POST with a body larger than one read must be fully
/// forwarded to the backend before the response is relayed (Go
/// http.DefaultTransport streams the body; forwarding only the bytes that
/// arrived with the head stalls the backend).
#[tokio::test]
async fn test_http_proxy_post_body_streams() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let req = read_full_cl_request(&mut conn).await;
            let _ = tx.send(req);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http_proxy".into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http_proxy(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let body = vec![b'p'; 128 * 1024];
    client
        .write_all(
            format!(
                "POST http://{backend_addr}/upload HTTP/1.1\r\nHost: ignored\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.write_all(&body).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded: request body was not fully forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        captured.starts_with(b"POST /upload HTTP/1.0"),
        "absolute-form URL must be rewritten to origin-form: {head}"
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "backend must receive the full request body"
    );
}

/// A chunked request that ALSO carries `Content-Length` must be forwarded
/// with `Transfer-Encoding: chunked` only — Content-Length is dropped
/// (RFC 7230 §3.3.3: chunked wins; Go's http.Server deletes CL when
/// Transfer-Encoding is chunked, and forwarding the ambiguous pair is
/// request-smuggling shaped). Covers both the shared forward path
/// (http2http) and the http_proxy path's own head builder.
async fn assert_chunked_with_cl_strips_content_length(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let req = read_full_chunked_request(&mut conn).await;
            let _ = tx.send(req);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let req_line = match plugin_type {
        "http_proxy" => format!("POST http://{backend_addr}/upload HTTP/1.1\r\n"),
        _ => "POST /upload HTTP/1.1\r\n".to_string(),
    };
    client
        .write_all(
            format!(
                "{req_line}Host: original\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    client.write_all(body).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("chunked request with Content-Length was not forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        head.to_lowercase().contains("transfer-encoding: chunked"),
        "chunked framing must be re-added to the head: {head}"
    );
    assert!(
        !head.to_lowercase().contains("content-length"),
        "Content-Length must be stripped when chunked (RFC 7230 §3.3.3): {head}"
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "client chunk framing must be forwarded verbatim"
    );
}

/// Both-framing-headers regression test through the shared forward path
/// (http2http).
#[tokio::test]
async fn test_http2http_chunked_with_cl_strips_content_length() {
    assert_chunked_with_cl_strips_content_length("http2http").await;
}

/// Both-framing-headers regression test through the http_proxy head builder.
#[tokio::test]
async fn test_http_proxy_chunked_with_cl_strips_content_length() {
    assert_chunked_with_cl_strips_content_length("http_proxy").await;
}

/// A backend that answers without reading the full request body (e.g.
/// nginx's 413 client_max_body_size) must not cause the client connection
/// to be dropped: a body-forward error is logged at debug and the early
/// response is still relayed (Go's Transport delivers early responses).
///
/// The client sends head + 1 KiB, then half-closes its write side; the
/// backend reads what it needs, answers 413 and closes cleanly. The
/// plugin's body forward hits "connection closed before full body" — a
/// clean FIN close, so the 413 survives in the plugin's receive buffer and
/// the relay delivers it. Pre-fix the `?` propagated the error and the
/// client saw the connection dropped before any response.
#[tokio::test]
async fn test_http2http_early_response_relayed() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            // Read the head and the ~1 KiB body the client sent, then answer
            // 413 WITHOUT reading the rest and close. Everything received so
            // far was consumed, so the close is a clean FIN (no RST): the
            // 413 stays readable in the plugin's receive buffer.
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            while total < 1024 {
                let n = conn.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
            }
            let _ = conn
                .write_all(b"HTTP/1.0 413 Payload Too Large\r\nContent-Length: 21\r\n\r\npayload too large")
                .await;
            // drop: close without reading the rest of the body
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http2http".into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http2http_plugin(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let total = 256 * 1024;
    client
        .write_all(
            format!("POST /up HTTP/1.1\r\nHost: h\r\nContent-Length: {total}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    client.write_all(&vec![b'x'; 1024]).await.unwrap();
    // Half-close the write side: the plugin's body forward then errors with
    // "connection closed before full body" — the early-response case.
    client.shutdown().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("early response was not relayed after body-forward error (regression)")
    .unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.0 413"),
        "client must receive the early 413, got: {:?}",
        String::from_utf8_lossy(&resp[..resp.len().min(80)])
    );
}

/// A request carrying hop-by-hop headers must be forwarded WITHOUT them
/// (RFC 2616 §13.5.1; Go parity: removeProxyHeaders strips Proxy-Connection
/// and ReverseProxy's hopHeaders include Keep-Alive). Covers both strip
/// lists: the shared http2http forward path (`read_request_and_build_forward`)
/// and the http_proxy head builder. The forwarder adds its own
/// `Connection: close` — that is expected and not asserted here.
async fn assert_strips_hop_by_hop_extension_headers(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("GET http://{backend_addr}/hop HTTP/1.1\r\n"),
        _ => "GET /hop HTTP/1.1\r\n".to_string(),
    };
    client
        .write_all(
            format!(
                "{req_line}Host: original\r\n\
                 Proxy-Connection: keep-alive\r\n\
                 Keep-Alive: timeout=5, max=100\r\n\
                 Connection: keep-alive\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let head = rx.await.expect("backend captured request").to_lowercase();
    // Connection: close is added by the forwarder itself — only verify
    // the two hop-by-hop headers that were missing pre-fix were stripped.
    for stripped in ["proxy-connection:", "keep-alive:"] {
        assert!(
            !head.contains(stripped),
            "hop-by-hop header {stripped} must be stripped from the forwarded request: {head}"
        );
    }
}

/// Shared http2http forward path strips Proxy-Connection and Keep-Alive.
#[tokio::test]
async fn test_http2http_strips_proxy_connection_and_keep_alive() {
    assert_strips_hop_by_hop_extension_headers("http2http").await;
}

/// http_proxy head builder strips Proxy-Connection and Keep-Alive.
#[tokio::test]
async fn test_http_proxy_strips_proxy_connection_and_keep_alive() {
    assert_strips_hop_by_hop_extension_headers("http_proxy").await;
}

/// A request carrying `Expect: 100-continue` must be forwarded WITHOUT it:
/// the plugin never relays the interim 100-continue response, and a strict
/// client that gates its body-send on it would deadlock against the body
/// read. Stripping the header makes the client send the body immediately
/// (RFC 7231 §5.1.1). Covers both strip lists: the shared http2http forward
/// path (`read_request_and_build_forward`) and the http_proxy head builder.
async fn assert_strips_expect_header(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("GET http://{backend_addr}/expect HTTP/1.1\r\n"),
        _ => "GET /expect HTTP/1.1\r\n".to_string(),
    };
    client
        .write_all(format!("{req_line}Host: original\r\nExpect: 100-continue\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let head = rx.await.expect("backend captured request").to_lowercase();
    assert!(
        !head.contains("expect:"),
        "Expect must be stripped from the forwarded request: {head}"
    );
}

/// Shared http2http forward path strips Expect: 100-continue.
#[tokio::test]
async fn test_http2http_strips_expect_header() {
    assert_strips_expect_header("http2http").await;
}

/// http_proxy head builder strips Expect: 100-continue.
#[tokio::test]
async fn test_http_proxy_strips_expect_header() {
    assert_strips_expect_header("http_proxy").await;
}

/// Duplicate identical Content-Length values must collapse to a single
/// forwarded line (RFC 7230 §3.3.2: "reject or replace with a single
/// value") — forwarding both keeps the request-smuggling shape alive for
/// any backend honoring the second copy.
async fn assert_duplicate_identical_cl_collapses(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let req = read_full_cl_request(&mut conn).await;
            let _ = tx.send(req);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("POST http://{backend_addr}/up HTTP/1.1\r\n"),
        _ => "POST /up HTTP/1.1\r\n".to_string(),
    };
    let body = b"hello"; // 5 bytes, matching both duplicate CL values
    client
        .write_all(
            format!("{req_line}Host: original\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    client.write_all(body).await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert_eq!(
        head.to_lowercase().matches("content-length:").count(),
        1,
        "duplicate identical Content-Length must collapse to one line: {head}"
    );
    assert!(
        head.contains("Content-Length: 5"),
        "the collapsed Content-Length line is missing: {head}"
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "backend must receive the full body"
    );
}

/// Duplicate identical Content-Length collapses on the shared http2http path.
#[tokio::test]
async fn test_http2http_duplicate_identical_cl_collapses() {
    assert_duplicate_identical_cl_collapses("http2http").await;
}

/// Duplicate identical Content-Length collapses in the http_proxy builder.
#[tokio::test]
async fn test_http_proxy_duplicate_identical_cl_collapses() {
    assert_duplicate_identical_cl_collapses("http_proxy").await;
}

/// Conflicting duplicate Content-Length values make the request framing
/// invalid (RFC 7230 §3.3.2): the plugin must reject — close the connection
/// without forwarding anything to the backend and without sending a 400 —
/// instead of forwarding both values (a backend honoring the second would
/// desync, request-smuggling shaped).
async fn assert_conflicting_cl_rejects(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    // The backend must receive NO bytes: the http2http path rejects before
    // dialing (no accept at all); the http_proxy path dials before
    // rejecting, so the connection may be accepted and then closed with 0
    // bytes. Either way nothing may be forwarded.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match tokio::time::timeout(std::time::Duration::from_secs(3), backend.accept()).await {
            Ok(Ok((mut conn, _))) => {
                let mut buf = vec![0u8; 1024];
                let _ = tx.send(Some(conn.read(&mut buf).await.unwrap_or(0)));
            }
            Ok(Err(_)) | Err(_) => {
                let _ = tx.send(None);
            }
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("POST http://{backend_addr}/up HTTP/1.1\r\n"),
        _ => "POST /up HTTP/1.1\r\n".to_string(),
    };
    // Conflicting Content-Length values; no body bytes are sent — the
    // rejection is header-driven, so the plugin closes cleanly (no RST from
    // unread data).
    client
        .write_all(
            format!("{req_line}Host: original\r\nContent-Length: 5\r\nContent-Length: 100\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    // The plugin must close the connection without writing any response.
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("conflicting Content-Length must be rejected: connection not closed (regression)")
    .unwrap();
    assert!(
        resp.is_empty(),
        "no response must be sent on a rejected request, got: {:?}",
        String::from_utf8_lossy(&resp[..resp.len().min(80)])
    );
    let forwarded = rx.await.expect("backend task finished");
    assert!(
        forwarded == Some(0) || forwarded.is_none(),
        "backend must receive no bytes on a rejected request, got: {forwarded:?}"
    );
}

/// Conflicting Content-Length is rejected on the shared http2http path.
#[tokio::test]
async fn test_http2http_conflicting_cl_rejects() {
    assert_conflicting_cl_rejects("http2http").await;
}

/// Conflicting Content-Length is rejected by the http_proxy head builder.
#[tokio::test]
async fn test_http_proxy_conflicting_cl_rejects() {
    assert_conflicting_cl_rejects("http_proxy").await;
}

/// `Content-Length: 5, 5` (list form, single line) is rejected: Go's
/// `parseContentLength` (`strconv.ParseUint`) accepts no comma, so net/http
/// answers 400 (audit round-8 F9 — the old code summed the parts into a
/// single `Content-Length: 10` and forwarded the whole body; Go frp never
/// did, probed against the Go v0.71.0-era stdlib, go1.25.12). Rejection is
/// header-driven, so no body bytes are sent and the plugin closes cleanly.
/// `chunked` also exercises the Transfer-Encoding: chunked arm: Go probes
/// the CL values even when chunked wins the framing (chunked + "5, 5"
/// still 400s — a chunked-skip that accepted garbage CL under chunked and
/// forwarded the request would not).
async fn assert_list_form_cl_rejects(plugin_type: &str, chunked: bool) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    // The backend must receive NO bytes: the http2http path rejects before
    // dialing (no accept at all); the http_proxy path dials before
    // rejecting, so the connection may be accepted and then closed with 0
    // bytes. Either way nothing may be forwarded.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match tokio::time::timeout(std::time::Duration::from_secs(3), backend.accept()).await {
            Ok(Ok((mut conn, _))) => {
                let mut buf = vec![0u8; 1024];
                let _ = tx.send(Some(conn.read(&mut buf).await.unwrap_or(0)));
            }
            Ok(Err(_)) | Err(_) => {
                let _ = tx.send(None);
            }
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("POST http://{backend_addr}/sum HTTP/1.1\r\n"),
        _ => "POST /sum HTTP/1.1\r\n".to_string(),
    };
    let extra_te = if chunked {
        "Transfer-Encoding: chunked\r\n"
    } else {
        ""
    };
    client
        .write_all(
            format!("{req_line}Host: original\r\n{extra_te}Content-Length: 5, 5\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    // The plugin must close the connection without writing any response.
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("list-form Content-Length must be rejected: connection not closed (regression)")
    .unwrap();
    assert!(
        resp.is_empty(),
        "no response must be sent on a rejected request, got: {:?}",
        String::from_utf8_lossy(&resp[..resp.len().min(80)])
    );
    let forwarded = rx.await.expect("backend task finished");
    assert!(
        forwarded == Some(0) || forwarded.is_none(),
        "backend must receive no bytes on a rejected request, got: {forwarded:?}"
    );
}

/// List-form Content-Length is rejected on the shared http2http path.
#[tokio::test]
async fn test_http2http_list_form_cl_rejects() {
    assert_list_form_cl_rejects("http2http", false).await;
}

/// List-form Content-Length is rejected by the http_proxy head builder.
#[tokio::test]
async fn test_http_proxy_list_form_cl_rejects() {
    assert_list_form_cl_rejects("http_proxy", false).await;
}

/// List-form Content-Length is rejected under chunked too (Go probes CL
/// values even when chunked wins the framing) — shared http2http path.
#[tokio::test]
async fn test_http2http_list_form_cl_rejects_chunked() {
    assert_list_form_cl_rejects("http2http", true).await;
}

/// List-form Content-Length is rejected under chunked too (Go probes CL
/// values even when chunked wins the framing) — http_proxy head builder.
#[tokio::test]
async fn test_http_proxy_list_form_cl_rejects_chunked() {
    assert_list_form_cl_rejects("http_proxy", true).await;
}
/// A HEAD request carries no body even when the head declares a
/// Content-Length (RFC 7230 §3.3.2): the plugin must not block reading a
/// body the client will never send — pre-fix the response relay stalled
/// until the client closed — while still forwarding the Content-Length
/// header so the backend knows the response framing.
async fn assert_head_with_cl_relays_response(plugin_type: &str) {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            // HEAD has no body: read the head only, then answer.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                let n = conn.read(&mut tmp).await.unwrap_or(0);
                if n == 0 {
                    let _ = tx.send(buf);
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let _ = tx.send(buf);
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr: backend_addr.to_string(),
        ..Default::default()
    };
    let handle = match plugin_type {
        "http_proxy" => frp_client::plugin::start_http_proxy(&cfg).await,
        _ => frp_client::plugin::start_http2http_plugin(&cfg).await,
    };
    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    let req_line = match plugin_type {
        "http_proxy" => format!("HEAD http://{backend_addr}/head HTTP/1.1\r\n"),
        _ => "HEAD /head HTTP/1.1\r\n".to_string(),
    };
    // Content-Length: 100 with NO body — the correct wire behavior for HEAD.
    client
        .write_all(format!("{req_line}Host: original\r\nContent-Length: 100\r\n\r\n").as_bytes())
        .await
        .unwrap();

    // The response must be relayed promptly — pre-fix the body forward
    // blocked reading 100 bytes that never arrive and the relay hung.
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("HEAD request with Content-Length stalled the response relay (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let head = String::from_utf8_lossy(&rx.await.expect("backend captured request")).to_lowercase();
    assert!(
        head.contains("content-length: 100"),
        "Content-Length must be kept in the forwarded head: {head}"
    );
}

/// HEAD with Content-Length relays the response promptly on http2http.
#[tokio::test]
async fn test_http2http_head_with_cl_relays_response() {
    assert_head_with_cl_relays_response("http2http").await;
}

/// HEAD with Content-Length relays the response promptly via http_proxy.
#[tokio::test]
async fn test_http_proxy_head_with_cl_relays_response() {
    assert_head_with_cl_relays_response("http_proxy").await;
}

/// A header line containing a lone `\r` (malformed client — `lines()` splits
/// only on `\n`, so the CR would survive into the forwarded request as an
/// injected request line, request-smuggling shaped) must be sanitized before
/// forwarding. Go's http.Server rejects control chars in headers, so Go frp
/// is immune; the http_proxy head builder must filter CR/LF per line like the
/// shared forward path (`read_request_and_build_forward`) does.
#[tokio::test]
async fn test_http_proxy_sanitizes_embedded_cr_in_header_line() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http_proxy".into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http_proxy(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();

    // The lone \r inside the header value is not followed by \n, so it does
    // not terminate the head — pre-fix it would be forwarded verbatim.
    client
        .write_all(
            format!(
                "GET http://{backend_addr}/inj HTTP/1.1\r\n\
                 Host: original\r\n\
                 X-Evil: foo\rGET /admin HTTP/1.1\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("backend never responded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let head = rx.await.expect("backend captured request");
    assert!(
        head.contains("X-Evil: fooGET /admin HTTP/1.1"),
        "embedded CR must be stripped — the injected request line must not survive: {head}"
    );
    assert!(
        !head.contains("foo\rGET"),
        "raw CR must not reach the backend: {head}"
    );
}
/// R5 e2e: configured X-Forwarded-For + an inbound XFF from the client must
/// produce EXACTLY ONE X-Forwarded-For line at the backend (Go Header.Set
/// replace semantics). The no-peer http2http path pre-fix emitted the
/// configured value twice plus the inbound chain (unit-pinned in
/// plugin/mod.rs; this pins it on the wire).
#[tokio::test]
async fn test_http2http_single_xff_line_with_configured_value() {
    let (backend_addr, rx) = start_capture_backend().await;

    let mut cfg = plugin_cfg("http2http", backend_addr.to_string());
    cfg.request_headers = HashMap::from([("X-Forwarded-For".to_string(), "cfg-value".to_string())]);

    let handle = frp_client::plugin::start_http2http_plugin(&cfg)
        .await
        .expect("start http2http plugin");
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
    client
        .write_all(
            b"GET /xff HTTP/1.1\r\n\
              Host: h.local\r\n\
              X-Forwarded-For: 1.2.3.4\r\n\
              \r\n",
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    client.read_to_end(&mut resp).await.unwrap();
    assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "got: {:?}", resp);

    let req = rx.await.expect("backend captured request");
    let xff_count = req
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:"))
        .count();
    assert_eq!(
        xff_count, 1,
        "exactly one X-Forwarded-For line must reach the backend, got {xff_count}: {req}"
    );
    assert!(
        req.contains("X-Forwarded-For: cfg-value"),
        "configured value must be the emitted line: {req}"
    );
    assert!(
        !req.contains("1.2.3.4"),
        "inbound chain must not leak alongside the configured value: {req}"
    );
}

/// http_proxy plugin auth-failure wire arms, probe-verified byte-for-byte
/// against Go frp v0.71.0:
/// - CONNECT fails (handleConnectReq → getBadResponse): status TEXT
///   "Not authorized" (Go's custom Status, not the standard reason) +
///   `Connection: close` + `Proxy-Authenticate: Basic` (no realm).
/// - plain-request fails (net/http ServeHTTP): standard status text, no
///   Connection header, same bare Basic. (Go keeps the conn reusable; the
///   frp-rs plugin serves one request per tunnel conn and closes after.)
#[tokio::test]
async fn test_http_proxy_auth_fail_wire_arms() {
    let mut cfg = plugin_cfg("http_proxy", "127.0.0.1:1".into());
    cfg.http_user = "u1".into();
    cfg.http_password = "p1".into();
    let handle = frp_client::plugin::start_http_proxy(&cfg)
        .await
        .expect("start http_proxy plugin");

    // CONNECT + wrong creds (base64("u1:zz") = dTE6eno=).
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    c.write_all(
        b"CONNECT example.com:443 HTTP/1.1\r\n\
          Host: example.com:443\r\n\
          Proxy-Authorization: Basic dTE6eno=\r\n\
          \r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 407 Not authorized\r\n")
            && text.contains("Connection: close\r\n")
            && text.contains("Proxy-Authenticate: Basic\r\n")
            && !text.contains("realm"),
        "CONNECT arm (Go getBadResponse), got: {text:?}"
    );

    // Plain GET + wrong creds: standard status text, no Connection header.
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    c.write_all(
        b"GET http://example.com/ HTTP/1.1\r\n\
          Host: example.com\r\n\
          Proxy-Authorization: Basic dTE6eno=\r\n\
          \r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n")
            && text.contains("Proxy-Authenticate: Basic\r\n")
            && !text.contains("Connection:")
            && !text.contains("realm"),
        "plain arm (Go ServeHTTP), got: {text:?}"
    );
}

/// Successful CONNECT through the http_proxy plugin: the FIRST bytes the
/// user socket receives must be byte-exactly `HTTP/1.1 200 OK\r\n\r\n` —
/// Go frp answers CONNECT with reason phrase "200 OK" (http_proxy.go:188
/// `resp.Status = "200 OK"`), not the conventional "200 Connection
/// Established" — and only tunneled backend bytes may follow it. T10 pin:
/// the phrase precedes the tunnel data on the wire.
#[tokio::test]
async fn test_http_proxy_connect_success_phrase_exact() {
    // Echo backend: whatever the tunnel carries in arrives back out, so the
    // test can prove relay data flows AFTER the phrase.
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let mut buf = [0u8; 64];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    let cfg = PluginConfig {
        plugin_type: "http_proxy".into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_http_proxy(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            return;
        }
    };
    let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
    client
        .write_all(
            format!("CONNECT {backend_addr} HTTP/1.1\r\nHost: {backend_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let phrase = b"HTTP/1.1 200 OK\r\n\r\n";
    // TCP may deliver the phrase in pieces — accumulate until it is whole.
    let mut got = Vec::new();
    let mut chunk = [0u8; 64];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while got.len() < phrase.len() {
            let n = client.read(&mut chunk).await.expect("read");
            assert!(n > 0, "plugin closed before the CONNECT success phrase");
            got.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("CONNECT success phrase never arrived");
    assert!(
        got.starts_with(phrase),
        "first bytes must be byte-exactly the Go \"200 OK\" phrase, got: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert!(
        !got[phrase.len()..].starts_with(b"HTTP/1.1"),
        "nothing may precede the phrase on the wire: {:?}",
        String::from_utf8_lossy(&got)
    );

    // Tunnel is live: a round trip through the CONNECT tunnel must echo.
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_exact(&mut echoed),
    )
    .await
    .expect("tunneled round trip never completed")
    .expect("read_exact");
    assert_eq!(&echoed, b"ping", "echo backend via CONNECT tunnel");
}

/// http_proxy auth-fail arm must close the connection after the 407 (T8):
/// the handler writes its response and returns, so the dropped socket ends
/// the conn — a client that receives the 407 and then stays silent (never
/// closes, never sends again) must observe EOF on its own. An unbounded
/// read-after-response would park the task + fd on that silent client (Go
/// http.Server closes too — write-and-close). The read_to_end in the
/// wire-arm test above would HANG CI rather than assert on a regression;
/// this pin puts an explicit deadline on the EOF.
#[tokio::test]
async fn test_http_proxy_auth_fail_closes_conn_promptly() {
    let mut cfg = plugin_cfg("http_proxy", "127.0.0.1:1".into());
    cfg.http_user = "u1".into();
    cfg.http_password = "p1".into();
    let handle = frp_client::plugin::start_http_proxy(&cfg)
        .await
        .expect("start http_proxy plugin");

    // CONNECT + wrong creds (base64("u1:zz") = dTE6eno=): read the 407,
    // then stay silent without closing the socket.
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    c.write_all(
        b"CONNECT example.com:443 HTTP/1.1\r\n\
          Host: example.com:443\r\n\
          Proxy-Authorization: Basic dTE6eno=\r\n\
          \r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        c.read_to_end(&mut resp),
    )
    .await
    .expect("plugin must close the conn after the 407 — no read-after-response may park on a silent client")
    .expect("read_to_end");
    assert!(
        resp.starts_with(b"HTTP/1.1 407 Not authorized\r\n"),
        "got: {:?}",
        String::from_utf8_lossy(&resp)
    );
}
