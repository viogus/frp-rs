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
    let connector = frp_core::transport::build_tls_connector_skip_verify(None, None, None)
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
