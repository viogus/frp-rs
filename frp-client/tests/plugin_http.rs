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
        // B1: the shared forward path (plugin/mod.rs
        // read_request_and_build_forward) speaks HTTP/1.1 — Go's
        // http.DefaultTransport never writes HTTP/1.0.
        req.contains("GET /secure HTTP/1.1"),
        "unexpected forwarded request: {req}"
    );
    assert!(!req.contains("HTTP/1.0"), "HTTP/1.0 leaks: {req}");
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
    // B1: shared forward path speaks HTTP/1.1 (Go http.DefaultTransport
    // parity — ReverseProxy outbound leg of https2https).
    assert!(req.contains("GET /both HTTP/1.1"), "got: {req}");
    assert!(!req.contains("HTTP/1.0"), "HTTP/1.0 leaks: {req}");

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
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        // B1: the shared forward path (plugin/mod.rs
        // read_request_and_build_forward) speaks HTTP/1.1 — Go's
        // http.DefaultTransport never writes HTTP/1.0.
        captured.starts_with(b"POST /upload HTTP/1.1"),
        "unexpected forwarded request: {head}"
    );
    assert!(
        !head.contains("HTTP/1.0"),
        "no HTTP/1.0 anywhere in the outbound head: {head}"
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

/// B1 twin for the SHARED forward path (http2http → plugin/mod.rs
/// read_request_and_build_forward): a chunked POST must leave the plugin on
/// an HTTP/1.1 request line (Go http.DefaultTransport — the ReverseProxy
/// outbound leg — never writes HTTP/1.0) with `Transfer-Encoding: chunked`
/// re-added and `Connection: close` terminating the head. Chunked framing is
/// the canary: it is HTTP/1.1-only, so an HTTP/1.0-speaking origin saw
/// neither TE nor CL and silently dropped the upload body. RED on the
/// HTTP/1.0 request line (both the request-line assert and the
/// no-HTTP/1.0 scan fail).
#[tokio::test]
async fn test_http2http_chunked_post_head_is_http11() {
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
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

    let body = b"5\r\nhello\r\n0\r\n\r\n";
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
    .expect("backend never responded: chunked body was not fully forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        captured.starts_with(b"POST /upload HTTP/1.1\r\n"),
        "outbound request line must be HTTP/1.1 (Go http.DefaultTransport parity): {head}"
    );
    assert!(
        !head.contains("HTTP/1.0"),
        "no HTTP/1.0 anywhere in the outbound head: {head}"
    );
    assert!(
        head.contains("Transfer-Encoding: chunked\r\n"),
        "chunked framing must be re-added after the hop-by-hop strip: {head}"
    );
    assert!(
        head.ends_with("Connection: close\r\n\r\n"),
        "head must end with the Connection: close terminator: {head}"
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
        // B1: the outbound request line is HTTP/1.1 (Go http.DefaultTransport
        // never writes HTTP/1.0). The absolute-form URL is rewritten to
        // origin-form at the same time.
        captured.starts_with(b"POST /upload HTTP/1.1"),
        "absolute-form URL must be rewritten to origin-form on an HTTP/1.1 request line: {head}"
    );
    assert!(
        !head.contains("HTTP/1.0"),
        "no HTTP/1.0 anywhere in the outbound head: {head}"
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

    // The backend must receive NO bytes: both paths reject in the head
    // classification, before any dial (the round-17 readRequest error
    // classes render on the http_proxy face; the http2http face closes),
    // so the accept below never fires or sees an empty read. Either way
    // nothing may be forwarded.
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

    // Round-17: the http_proxy face (Go conn.serve model) renders the
    // no-detail 400 for a readRequest error — fixLength's
    // conflicting-Content-Length rejection — before any dial; the
    // operator-local http2http face keeps the established silent-close
    // divergence (Err-to-bare-close policy).
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("conflicting Content-Length must be rejected: connection not closed (regression)")
    .unwrap();
    if plugin_type == "http_proxy" {
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "the http_proxy face must render Go's 400 for a conflicting \
             Content-Length (readRequest error), got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    } else {
        assert!(
            resp.is_empty(),
            "no response must be sent on a rejected request, got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }
    let forwarded = rx.await.expect("backend task finished");
    // F8: Some(0) would mean the plugin DIALED the backend and closed
    // without bytes — both faces reject in the head classification BEFORE
    // any dial, so the backend accept must never fire at all.
    assert!(
        forwarded.is_none(),
        "backend must receive NO connection on a rejected request, got: {forwarded:?}"
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

    // The backend must receive NO bytes: both paths reject in the head
    // classification, before any dial (the round-17 readRequest error
    // classes render on the http_proxy face; the http2http face closes),
    // so the accept below never fires or sees an empty read. Either way
    // nothing may be forwarded.
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

    // The plugin must reject the request: the http_proxy face renders
    // Go's no-detail 400 (parseContentLength readRequest error — a
    // comma list is one token to ParseUint, go1.25 has no readRequest
    // comma split); the operator-local http2http face closes silently.
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("list-form Content-Length must be rejected: connection not closed (regression)")
    .unwrap();
    if plugin_type == "http_proxy" {
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
            "the http_proxy face must render Go's 400 for a list-form \
             Content-Length (readRequest error), got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    } else {
        assert!(
            resp.is_empty(),
            "no response must be sent on a rejected request, got: {:?}",
            String::from_utf8_lossy(&resp[..resp.len().min(80)])
        );
    }
    let forwarded = rx.await.expect("backend task finished");
    // F8: Some(0) would mean the plugin DIALED the backend and closed
    // without bytes — both faces reject in the head classification BEFORE
    // any dial, so the backend accept must never fire at all.
    assert!(
        forwarded.is_none(),
        "backend must receive NO connection on a rejected request, got: {forwarded:?}"
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

/// A header value containing a lone `\r` (malformed client — not followed by
/// `\n`, so it stays inside the stored value where Go textproto's
/// validHeaderFieldValue rejects the CTL byte) is a readRequest error on the
/// Go http.Server face: the http_proxy head builder must reject the head
/// (400 render, no dial) rather than forward it. Go never sanitizes control
/// chars — the pre-round-17 "strip CR per line and forward" behavior was a
/// frp-rs invention (request-smuggling shaped if the CR had reached the
/// backend).
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

    // The backend must never see this head: the rejected request renders
    // before any dial, so the accept only fires on a regression — a
    // 3-second bound keeps the assertion from hanging either way.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match tokio::time::timeout(std::time::Duration::from_secs(3), backend.accept()).await {
            Ok(Ok((mut conn, _))) => {
                let mut buf = vec![0u8; 8192];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            }
            Ok(Err(_)) | Err(_) => {
                let _ = tx.send(String::new());
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

    // The lone \r inside the header value is not followed by \n, so it
    // does not terminate the head — it stays INSIDE the stored value, where
    // Go textproto's validHeaderFieldValue rejects the CTL byte: a
    // readRequest error, answered by the conn.serve 400 on this face. RED
    // on round-16 code: the CR was stripped and the head forwarded (a
    // frp-rs invention — Go never sanitizes, it errors).
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
    .expect("connection not closed on the rejected head (regression)")
    .unwrap();
    assert_eq!(
        resp,
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
        "an embedded CR in a header value is a readRequest error → Go's \
         400 render, got: {:?}",
        String::from_utf8_lossy(&resp[..resp.len().min(80)])
    );

    let forwarded = rx.await.expect("backend task finished");
    assert!(
        forwarded.is_empty(),
        "backend must receive no bytes on a rejected request, got: {forwarded:?}"
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

/// Round-18 LOW pin: a SP/HTAB-bearing `Proxy-Authorization ` field name
/// never canonicalizes in Go's textproto reader (reader.go:742-765 —
/// CanonicalMIMEHeaderKey bails on any non-token byte, issue 34540), so
/// `req.Header.Get("Proxy-Authorization")` (http_proxy.go:143) misses the
/// row and the CONNECT face answers 407 — even when the value holds VALID
/// credentials. The old walker trimmed trailing SP/HTAB off the name, so the
/// spaced row matched and authenticated. A spaced row is a SEPARATE key, not
/// a malformed head: the walk must skip it and keep scanning, so a later
/// canonical row still authenticates (second half below).
#[tokio::test]
async fn test_http_proxy_spaced_proxy_authorization_name_is_not_credentials() {
    let mut cfg = plugin_cfg("http_proxy", "127.0.0.1:1".into());
    cfg.http_user = "u1".into();
    cfg.http_password = "p1".into();
    let handle = frp_client::plugin::start_http_proxy(&cfg)
        .await
        .expect("start http_proxy plugin");

    // Valid creds (base64("u1:p1") = dTE6cDE=) under a spaced name → 407,
    // exactly as if no credentials were sent. RED pre-fix: the row matched,
    // the plugin dialed example.com:443 and its dial failure rendered the
    // bare Go 400 — never the 407.
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    c.write_all(
        b"CONNECT example.com:443 HTTP/1.1\r\n\
          Host: example.com:443\r\n\
          Proxy-Authorization : Basic dTE6cDE=\r\n\
          \r\n",
    )
    .await
    .unwrap();
    let mut resp = Vec::new();
    c.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 407 Not authorized\r\n"),
        "a spaced Proxy-Authorization name is not credentials (Go Header.Get misses the row), got: {text:?}"
    );

    // Second half: the spaced row is its own key — a LATER canonical row
    // still authenticates and the CONNECT tunnels (Go's Get reads the
    // canonical key; last-wins/truncation would answer 407 instead).
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
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    c.write_all(
        format!(
            "CONNECT {backend_addr} HTTP/1.1\r\n\
             Host: {backend_addr}\r\n\
             Proxy-Authorization : Basic Z2FyYmFnZQ==\r\n\
             Proxy-Authorization: Basic dTE6cDE=\r\n\
             \r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let phrase = b"HTTP/1.1 200 OK\r\n\r\n";
    let mut got = Vec::new();
    let mut chunk = [0u8; 64];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while got.len() < phrase.len() {
            let n = c.read(&mut chunk).await.expect("read");
            assert!(n > 0, "plugin closed before the CONNECT success phrase");
            got.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("CONNECT success phrase never arrived");
    assert!(
        got.starts_with(phrase),
        "the later canonical row must authenticate the tunnel, got: {:?}",
        String::from_utf8_lossy(&got)
    );
    c.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        c.read_exact(&mut echoed),
    )
    .await
    .expect("tunneled round trip never completed")
    .expect("read_exact");
    assert_eq!(&echoed, b"ping", "echo backend via CONNECT tunnel");
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

/// B1 e2e: a chunked POST through the http_proxy path must leave the plugin
/// on an HTTP/1.1 request line (Go http.DefaultTransport never writes
/// HTTP/1.0) with `Transfer-Encoding: chunked` re-added and
/// `Connection: close` terminating the head. Chunked framing is the canary:
/// it is HTTP/1.1-only, so an HTTP/1.0-speaking origin saw neither TE nor
/// CL and silently dropped the upload body. RED on the HTTP/1.0 request
/// line (both the request-line assert and the no-HTTP/1.0 scan fail).
#[tokio::test]
async fn test_http_proxy_chunked_post_head_is_http11() {
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
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

    let body = b"5\r\nhello\r\n0\r\n\r\n";
    client
        .write_all(
            format!(
                "POST http://{backend_addr}/upload HTTP/1.1\r\n\
                 Host: original\r\n\
                 Transfer-Encoding: chunked\r\n\r\n"
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
    .expect("backend never responded: chunked body was not fully forwarded (regression)")
    .unwrap();
    assert!(resp.starts_with(b"HTTP/1.1 200 OK"), "got: {:?}", resp);

    let captured = rx.await.expect("backend captured request");
    let head_end = captured
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("forwarded request must end its head with CRLFCRLF")
        + 4;
    let head = String::from_utf8_lossy(&captured[..head_end]);
    assert!(
        captured.starts_with(b"POST /upload HTTP/1.1\r\n"),
        "outbound request line must be HTTP/1.1 (Go http.DefaultTransport parity): {head}"
    );
    assert!(
        !head.contains("HTTP/1.0"),
        "no HTTP/1.0 anywhere in the outbound head: {head}"
    );
    assert!(
        head.contains("Transfer-Encoding: chunked\r\n"),
        "chunked framing must be re-added after the hop-by-hop strip: {head}"
    );
    assert!(
        head.ends_with("Connection: close\r\n\r\n"),
        "head must end with the Connection: close terminator: {head}"
    );
    assert_eq!(
        &captured[head_end..],
        body.as_slice(),
        "client chunk framing must be forwarded verbatim"
    );
}

/// B2 (Go http_proxy.go HTTPHandler parity): a backend dial failure on the
/// plain path answers `500 Internal Server Error` with the dial error as a
/// text/plain body — NOT a silent zero-byte close (a refused backend was
/// indistinguishable from a vanished proxy). Shape probed against Go frp
/// v0.71.0: CT → X-CTO → (Go's Date, omitted here like every frp-rs manual
/// response writer) → real Content-Length → Connection: close, body = dial
/// error Display + '\n' (Go fmt.Fprintln). RED: zero-byte close → first
/// assert fails on the empty response.
#[tokio::test]
async fn test_http_proxy_plain_dial_failure_answers_500() {
    // A port that refuses: bind then drop the listener.
    let refused = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let refused_addr = refused.local_addr().unwrap();
    drop(refused);

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
            format!("GET http://{refused_addr}/ HTTP/1.1\r\nHost: {refused_addr}\r\n\r\n")
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
    .expect("no response before the conn closed")
    .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "dial failure must answer 500 with the error body, got: {text:?}"
    );
    let head_end = text.find("\r\n\r\n").expect("head terminator");
    let (head, body) = (&text[..head_end], &resp[head_end + 4..]);
    let ct = head
        .find("Content-Type: text/plain; charset=utf-8\r\n")
        .expect("Content-Type present");
    let xcto = head
        .find("X-Content-Type-Options: nosniff\r\n")
        .expect("X-CTO present");
    assert!(
        ct < xcto,
        "Go http.Error header order (CT before X-CTO): {text:?}"
    );
    assert!(
        !head.contains("Date:"),
        "no Date header (frp-rs policy): {text:?}"
    );
    assert!(
        // `head` is sliced before the blank-line terminator, so the LAST
        // header ("Connection: close") carries no trailing CRLF there —
        // match the header-terminating sequence in the full response.
        text.contains("Connection: close\r\n\r\n"),
        "single-request conn always closes: {text:?}"
    );
    assert!(
        String::from_utf8_lossy(body).contains("Connection refused"),
        "body must carry the dial error text: {text:?}"
    );
    assert!(
        String::from_utf8_lossy(body).ends_with('\n'),
        "body ends with newline (Go fmt.Fprintln): {text:?}"
    );
    let cl = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .expect("Content-Length present")
        .split_once(':')
        .unwrap()
        .1
        .trim()
        .parse::<usize>()
        .unwrap();
    assert_eq!(cl, body.len(), "real Content-Length: {text:?}");
}

/// B3 (Go http_proxy.go handleConnectReq parity): a CONNECT dial failure
/// answers byte-exactly `HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n
/// \r\n`. Probed against Go frp v0.71.0: the raw http.Response{StatusCode:
/// 400}.Write carries NO Connection header (Connection: close belongs to
/// the 407 getBadResponse arm only) and no body. RED: a spurious
/// `Connection: close` line fails the byte-exact compare.
#[tokio::test]
async fn test_http_proxy_connect_dial_failure_400_exact() {
    let refused = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let refused_addr = refused.local_addr().unwrap();
    drop(refused);

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
            format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: {refused_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("no response before the conn closed")
    .unwrap();
    assert_eq!(
        resp.as_slice(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        "Go raw 400 response, byte-exact (no Connection header, no body)"
    );
}

/// B4 (Go net/http parseRequestLine parity): the request line splits on
/// literal SPACE only (two `Cut(line, " ")`), so a tab-joined
/// "GET\tURL\tHTTP/1.1" is malformed. The response depends on the arm:
/// this is the PLAIN (non-CONNECT) arm, where the head lands in the
/// plugin's http.Server and the server renders its own error BEFORE the
/// handler runs — go1.25 conn.serve answers the malformed line with the
/// raw `400 Bad Request` render (src/net/http/server.go, readRequest error
/// switch: `errorHeaders` = Content-Type: text/plain + Connection: close,
/// bytes written straight to the conn, so NO Date header) and then drops
/// the conn. frp-rs's plain arm mirrors that render byte-exact
/// (GO_400_RENDER). The old split_whitespace collapsed every whitespace
/// run, so tab-joined tokens parsed and the request was dialed and
/// forwarded. (The CONNECT arm is the SILENT one: there Go reads the
/// request directly via ReadRequest in the plugin Handle and closes on its
/// error — no http.Server in the path.) RED: the request is forwarded,
/// the backend answers 200, and the render assert fails.
#[tokio::test]
async fn test_http_proxy_tab_joined_request_line_rejected() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, mut rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let _ = tx.send(());
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
    client
        .write_all(format!("GET\thttp://{backend_addr}/\tHTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("plugin must close the conn after rendering the Go 400")
    .unwrap();
    assert_eq!(
        resp.as_slice(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request",
        "tab-joined request line must render Go's http.Server conn.serve \
         400 byte-exact (no Date header — raw write), got: {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        rx.try_recv().is_err(),
        "the malformed request must never reach the backend"
    );
}

/// Round-9 review finding: the inbound version gate rejected HTTP/1.2
/// (exact-match 4-token list) while Go ParseHTTPVersion (go1.25) accepts
/// any 8-char single-digit "HTTP/X.Y" — a HTTP/1.2 request line passes the
/// frps vhost front (major 1, Go http1ServerSupportsRequest) and Go's
/// plugin arms serve it. The old gate silently closed conns that Go
/// forwards. RED on the old gate: the connection dies with zero bytes and
/// the backend never sees the request.
#[tokio::test]
async fn test_http_proxy_http12_request_line_forwarded() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();

    let (tx, mut rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = backend.accept().await {
            let _ = tx.send(());
            let mut head = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = conn.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&chunk[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // Outbound always speaks HTTP/1.1 (Go DefaultTransport parity).
            assert!(
                String::from_utf8_lossy(&head).starts_with("GET / HTTP/1.1\r\n"),
                "forwarded head must be HTTP/1.1: {:?}",
                String::from_utf8_lossy(&head)
            );
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
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
    client
        .write_all(format!("GET http://{backend_addr}/ HTTP/1.2\r\nHost: h\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("HTTP/1.2 request must be served, not silently closed")
    .unwrap();
    assert!(
        String::from_utf8_lossy(&resp).contains("200 OK"),
        "HTTP/1.2 request must be forwarded (Go serves parseable 1.x): {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        rx.try_recv().is_ok(),
        "the HTTP/1.2 request must reach the backend"
    );
}

/// Round-17 audit F10 (F2 pin matrix): on the http_proxy CONNECT face —
/// Go frp http_proxy.go sniffs the method and calls package
/// http.ReadRequest DIRECTLY, with NO http.Server in the path — every
/// readRequest error class closes the conn with ZERO bytes (the handler
/// has no response writer for a head it never parsed; probe vs go1.25.12
/// modeB: dup-Host / TE / CL / CTL-value / escape / raw-byte CONNECT
/// heads all answer 0 bytes). The plain face renders the same classes;
/// the CONNECT face must stay silent.
#[tokio::test]
async fn test_http_proxy_connect_readrequest_error_classes_close_silently() {
    let refused = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let refused_addr = refused.local_addr().unwrap();
    drop(refused);

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

    // One fresh conn per row against the same plugin listener.
    let silent_rows: Vec<Vec<u8>> = [
        // dup Host (fires before TE/CL, at every version).
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
        // Case-folded dup (one canonical key, two entries).
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: a\r\nHOST: b\r\n\r\n"),
        // dup Host under a parseable HTTP/2.0 (dup precedes any version
        // question — still silent here).
        format!("CONNECT {refused_addr} HTTP/2.0\r\nHost: a\r\nHost: b\r\n\r\n"),
        // Transfer-Encoding: not a single "chunked".
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"),
        // dup Transfer-Encoding lines.
        format!(
            "CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        // Content-Length parse failures.
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"),
        format!(
            "CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
        ),
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\n"),
        format!(
            "CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999999\r\n\r\n"
        ),
        // textproto read shapes (CTL value, colonless line).
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nX-A: ok\x01bad\r\n\r\n"),
        format!("CONNECT {refused_addr} HTTP/1.1\r\nNoColonHere\r\n\r\n"),
        // CTL in the authority.
        format!("CONNECT {refused_addr}\x01 HTTP/1.1\r\nHost: x\r\n\r\n"),
        // Host-mode %-escapes: well-formed decode to an ASCII byte is an
        // error outside the RFC 6874 %25 carve-out; malformed %zz too.
        "CONNECT h%41st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h%5Est:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h%2Fst:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h%31st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h%zzt:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h%2:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        // Raw non-safe ASCII in the authority (F6).
        "CONNECT h^st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h|st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h{st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h st:80 HTTP/1.1\r\nHost: x\r\n\r\n".to_string(),
        // Unparseable version token / missing token.
        "CONNECT h:80 HTTP/1.10\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h:80 HTTP/1.1.1\r\nHost: x\r\n\r\n".to_string(),
        "CONNECT h:80\r\n\r\n".to_string(),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect();

    for row in &silent_rows {
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        client.write_all(row).await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut resp),
        )
        .await
        .expect("conn must close on a CONNECT readRequest error (regression)")
        .unwrap();
        assert!(
            resp.is_empty(),
            "CONNECT face readRequest error must close with ZERO bytes, \
             got {} bytes for head: {:?}",
            resp.len(),
            String::from_utf8_lossy(&row[..row.len().min(90)])
        );
    }
}

/// Round-17 audit F10: readRequest-clean CONNECT heads on the CONNECT
/// face are SERVED at every parseable version and land in the dial
/// failure 400 arm when the target refuses — byte-exact Go raw response
/// `HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n` (no Connection
/// header; probe vs go1.25.12: clean CONNECT HTTP/2.0 and HTTP/1.9 heads
/// answer the same 400 as HTTP/1.1; the CONNECT face has NO version gate
/// — package http.ReadRequest knows nothing of http1ServerSupportsRequest
/// — and NO conn gates, so a no-Host, space-in-name, or chunked-TE head
/// is served too).
#[tokio::test]
async fn test_http_proxy_connect_clean_heads_answer_dial_400() {
    let refused = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let refused_addr = refused.local_addr().unwrap();
    drop(refused);

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

    let served_rows: Vec<Vec<u8>> = [
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: {refused_addr}\r\n\r\n"),
        // Parseable non-1.x versions: served, dial fails.
        format!("CONNECT {refused_addr} HTTP/2.0\r\nHost: x\r\n\r\n"),
        format!("CONNECT {refused_addr} HTTP/1.9\r\nHost: x\r\n\r\n"),
        format!("CONNECT {refused_addr} HTTP/0.9\r\nHost: x\r\n\r\n"),
        // No Host: the missing-Host conn gate is server-side only.
        format!("CONNECT {refused_addr} HTTP/1.1\r\n\r\n"),
        // SPACE in a header name survives ReadMIMEHeader; only the
        // server-side invalid-name gate catches it — not present here.
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nBad Name: y\r\n\r\n"),
        // Single legal chunked TE + valid CL: framing parses clean.
        format!(
            "CONNECT {refused_addr} HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
        ),
        // Empty Host value is legal on this face either way.
        format!("CONNECT {refused_addr} HTTP/1.1\r\nHost: \r\n\r\n"),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect();

    for row in &served_rows {
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        client.write_all(row).await.unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_to_end(&mut resp),
        )
        .await
        .expect("conn must close after the dial-failure 400")
        .unwrap();
        assert_eq!(
            resp.as_slice(),
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
            "clean CONNECT head to a refused target must answer Go's raw \
             dial 400 (no Connection header), got {} bytes for head: {:?}",
            resp.len(),
            String::from_utf8_lossy(&row[..row.len().min(90)])
        );
    }
}

/// Round-17 audit F4: tunnel data a client pipelines in the SAME TCP
/// segment as the CONNECT head must reach the backend — the head read
/// loop stops at the terminator but its last chunk can carry bytes past
/// it, and Go's tee drains exactly those over-read bytes to the remote
/// before relaying fresh client bytes. The old path dropped the tail: the
/// backend never saw the client's early bytes and the echo lost them.
#[tokio::test]
async fn test_http_proxy_connect_pipelined_tail_reaches_backend() {
    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();
    // Echo backend.
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
    // Head AND pipelined tunnel data in one write: the read loop's first
    // chunk carries both, so the tail is over-read into the head buffer.
    client
        .write_all(
            format!("CONNECT {backend_addr} HTTP/1.1\r\nHost: {backend_addr}\r\n\r\nearly-")
                .as_bytes(),
        )
        .await
        .unwrap();

    let phrase = b"HTTP/1.1 200 OK\r\n\r\n";
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
    assert!(got.starts_with(phrase), "got: {:?}", got);

    // Bytes past the phrase may already include the echoed tail (the
    // plugin queues the phrase, flushes the tail to the backend, and the
    // backend's echo can arrive before the client's next read) — carry
    // them over instead of discarding.
    let mut rest: Vec<u8> = if got.len() > phrase.len() {
        got[phrase.len()..].to_vec()
    } else {
        Vec::new()
    };
    let mut chunk = [0u8; 16];
    while rest.len() < 6 {
        let n = client.read(&mut chunk).await.expect("read");
        assert!(n > 0, "plugin closed before the pipelined tail echoed");
        rest.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(
        &rest[..6],
        b"early-",
        "pipelined tail must reach the backend and echo back FIRST"
    );

    // A second payload after the tunnel is live; the backend's echo order
    // (tail bytes before later bytes) proves the plugin flushed the tail
    // before relaying anything fresh.
    client.write_all(b"late").await.unwrap();
    while rest.len() < 10 {
        let n = client.read(&mut chunk).await.expect("read");
        assert!(n > 0, "plugin closed before the later payload echoed");
        rest.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(
        &rest[..10],
        b"early-late",
        "echo must arrive in tunnel order: pipelined tail, then late payload"
    );
}

/// Round-17 audit F9: the plugin head read must clamp to Go's
/// `initialReadLimitSize` = MaxHeaderBytes (1 MiB) + 4096 bufio slop —
/// 1,049,600 bytes exactly. A TERMINATED head whose terminator ends at
/// byte 1,049,600 serves (dial fails against the refused target → 500);
/// one byte more errors with Go's 431 render. RED on the pre-fix loop
/// (unclamped 4 KiB chunks served terminated heads up to ~1 MiB + 8192,
/// so the 1,049,601-byte head answered 500 instead of 431).
#[tokio::test]
async fn test_http_proxy_read_limit_exact_boundary_rows() {
    let refused = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let refused_addr = refused.local_addr().unwrap();
    drop(refused);

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

    let limit = 1024 * 1024 + 4096;

    // Row 1: terminator ends AT the limit — must be served.
    let mut head: Vec<u8> =
        format!("GET http://{refused_addr}/ HTTP/1.1\r\nHost: x\r\nX-Big: ").into_bytes();
    head.resize(limit - 4, b'A');
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), limit, "row 1 head must total exactly the limit");

    let client = TcpStream::connect(handle.local_addr).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    tokio::spawn(async move {
        let _ = wr.write_all(&head).await;
    });
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        rd.read_to_end(&mut resp),
    )
    .await
    .expect("no response before the conn closed")
    .unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
        "head terminated exactly AT the 1,049,600 boundary must SERVE \
         (dial-failure 500), got {} bytes: {:?}",
        resp.len(),
        &text[..text.len().min(80)]
    );

    // Row 2: one byte past the limit — Go 431 render, byte-exact.
    let mut head: Vec<u8> =
        format!("GET http://{refused_addr}/ HTTP/1.1\r\nHost: x\r\nX-Big: ").into_bytes();
    head.resize(limit - 3, b'A');
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), limit + 1, "row 2 head must total limit + 1");

    let client = TcpStream::connect(handle.local_addr).await.unwrap();
    let (mut rd, mut wr) = tokio::io::split(client);
    tokio::spawn(async move {
        let _ = wr.write_all(&head).await;
        // Half-close: the plugin's bounded drain then sees EOF the moment
        // it has consumed the 1 over-cap byte, so its close sends a clean
        // FIN instead of burning the full 250 ms drain wait.
        let _ = wr.shutdown().await;
    });
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        rd.read_to_end(&mut resp),
    )
    .await
    .expect("no response before the conn closed")
    .unwrap();
    assert_eq!(
        resp.as_slice(),
        b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n431 Request Header Fields Too Large",
        "one byte past the boundary must render Go's 431 byte-exact \
         (was served 500 pre-fix), got {} bytes",
        resp.len()
    );
}

/// Round-18 audit G4 (R1 LOW regression pin): a LOWERCASE `connect` method
/// token must NOT tunnel. Go http_proxy.go sniffs the CONNECT face with an
/// EqualFold 7-byte compare, but the request-line gate is EXACT-case
/// (package http.ReadRequest, request.go:1118 `justAuthority`):
/// `connect host:port` parses as absolute-form-ish (Scheme "connect",
/// Opaque "host:port") with URL.Host == "" — and Go frp dials
/// `r.URL.Host` unconditionally, so `net.Dial("tcp", "")` fails and the
/// request answers the bare 47-byte dial 400 with the backend NEVER
/// reached. The pre-fix (round-17) code dialed the verbatim target for any
/// EqualFold-CONNECT method, so a lowercase connect to a LIVE backend
/// established a tunnel instead of failing — RED here. (Target is a live
/// capture backend, not a refused port, so the pre-fix tunnel path really
/// differs: a refused target would answer the same 400 both ways and the
/// pin would be vacuous.)
#[tokio::test]
async fn test_http_proxy_lowercase_connect_answers_dial_400_never_reaches_backend() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let backend = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping test: cannot bind (sandboxed): {e}");
            return;
        }
    };
    let backend_addr = backend.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (a1, c1) = (accepted.clone(), captured.clone());
    tokio::spawn(async move {
        // Keep accepting for the whole test; a tunnel dial lands here.
        while let Ok((mut conn, _)) = backend.accept().await {
            a1.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 1024];
            let _ = conn.read(&mut buf).await;
            c1.lock().unwrap().extend_from_slice(&buf);
            // Never reply: a tunneled client would hang/EOF with
            // zero bytes — not the 400 this pin demands.
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
            format!("connect {backend_addr} HTTP/1.1\r\nHost: {backend_addr}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut resp),
    )
    .await
    .expect("conn must close after the dial-failure 400")
    .unwrap();
    assert_eq!(
        resp.as_slice(),
        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
        "lowercase connect must answer Go's byte-exact dial 400, got {} bytes: {:?}",
        resp.len(),
        String::from_utf8_lossy(&resp)
    );

    // Let any (wrong) tunnel dial land before asserting the backend saw
    // nothing. Post-fix the plugin never dials (empty target), so this is
    // deterministic; the pre-fix tunnel path fails the 400 assert above
    // regardless.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "backend must receive ZERO connections (no tunnel dial)"
    );
    assert!(
        captured.lock().unwrap().is_empty(),
        "backend must receive ZERO bytes"
    );
}
