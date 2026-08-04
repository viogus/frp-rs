//! Integration tests for the https2http/https2https plugin HTTP/2 path
//! (enableHTTP2 / ALPN h2): h2 request → HTTP/1.1 backend forwarding, header
//! injection + host rewrite, 502 on unreachable backend, and the
//! `enable_http2 = false` ALPN restriction.
//!
//! Go frp compat: `enableHTTP2` (default true) controls ALPN h2 on the
//! inbound TLS listener of https2http/https2https only; outbound to the
//! backend is always HTTP/1.1 (Go http.Server + httputil.ReverseProxy).

#![cfg(feature = "tls")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use frp_core::config::PluginConfig;

fn plugin_cfg(plugin_type: &str, local_addr: String) -> PluginConfig {
    PluginConfig {
        plugin_type: plugin_type.into(),
        local_addr,
        ..Default::default()
    }
}

/// Generate a self-signed cert/key pair with rcgen (dev-dependency) and write
/// them as PEM files. Returns (cert_path, key_path, cert_der).
fn write_plugin_cert(dir: &tempfile::TempDir) -> (PathBuf, PathBuf, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let wrap_pem = |label: &str, der: &[u8]| -> String {
        let b64 = data_encoding::BASE64.encode(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    };
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, wrap_pem("CERTIFICATE", cert.der())).unwrap();
    std::fs::write(
        &key_path,
        wrap_pem("PRIVATE KEY", &key_pair.serialize_der()),
    )
    .unwrap();
    (cert_path, key_path, cert.der().to_vec())
}

/// Build a rustls client connector that trusts `cert_der` and offers the given
/// ALPN protocols.
fn client_connector(cert_der: &[u8], alpn: &[&[u8]]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates([rustls::pki_types::CertificateDer::from(cert_der.to_vec())]);
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// Build a rustls client connector that trusts `cert_der` and offers ALPN h2.
fn h2_client_connector(cert_der: &[u8]) -> tokio_rustls::TlsConnector {
    client_connector(cert_der, &[b"h2"])
}

/// Start a plaintext HTTP/1.1 backend that captures the first request head and
/// replies 200 with a small body.
async fn start_capture_backend() -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let n = tokio::io::AsyncReadExt::read(&mut conn, &mut buf)
                .await
                .unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = conn
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await;
            let _ = conn.flush().await;
        }
    });
    (addr, rx)
}

/// One h2 GET through the plugin. Returns (status, body).
async fn h2_get(
    plugin_addr: std::net::SocketAddr,
    connector: &tokio_rustls::TlsConnector,
    host: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    let tcp = TcpStream::connect(plugin_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut send_request, connection) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = http::Request::builder()
        .method("GET")
        .uri(format!("https://{host}{path}"));
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let request = builder.body(()).unwrap();
    let (response, _) = send_request.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(Ok(chunk)) = body.data().await {
        data.extend_from_slice(&chunk);
    }
    (status, String::from_utf8_lossy(&data).to_string())
}

async fn start_https2http_with_cert(
    backend_addr: String,
    enable_http2: Option<bool>,
    request_headers: HashMap<String, String>,
    host_rewrite: &str,
) -> (frp_client::plugin::PluginHandle, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert_der) = write_plugin_cert(&dir);
    let mut cfg = plugin_cfg("https2http", backend_addr);
    cfg.crt_file = cert_path.to_str().unwrap().to_string();
    cfg.key_file = key_path.to_str().unwrap().to_string();
    cfg.enable_http2 = enable_http2;
    cfg.request_headers = request_headers;
    cfg.host_header_rewrite = host_rewrite.to_string();
    let handle = frp_client::plugin::start_https2http_plugin(&cfg)
        .await
        .expect("start https2http plugin");
    // Keep the tempdir alive for the plugin's certificate lifetime.
    std::mem::forget(dir);
    (handle, cert_der)
}

#[tokio::test]
async fn test_https2http_h2_forwards_to_http1_backend() {
    let (backend_addr, rx) = start_capture_backend().await;
    let (_handle, cert_der) =
        start_https2http_with_cert(backend_addr.to_string(), None, HashMap::new(), "").await;
    let plugin_addr = _handle.local_addr;
    let connector = h2_client_connector(&cert_der);

    let (status, body) = h2_get(plugin_addr, &connector, "example.com", "/hello", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello");

    // The backend must have seen a plain HTTP/1.1 request head (Go ReverseProxy
    // forwards h2 inbound as HTTP/1.1 outbound).
    let req = rx.await.expect("backend captured request");
    assert!(req.starts_with("GET /hello HTTP/1.1"), "got: {req}");
    assert!(req.contains("Host: example.com"), "got: {req}");
}

#[tokio::test]
async fn test_https2http_h2_injects_headers_and_rewrites_host() {
    let (backend_addr, rx) = start_capture_backend().await;
    let (_handle, cert_der) = start_https2http_with_cert(
        backend_addr.to_string(),
        None,
        HashMap::from([
            ("X-Injected".to_string(), "from-config".to_string()),
            ("X-Override".to_string(), "new-value".to_string()),
        ]),
        "rewritten.local",
    )
    .await;
    let connector = h2_client_connector(&cert_der);
    let plugin_addr = _handle.local_addr;

    let (status, _) = h2_get(
        plugin_addr,
        &connector,
        "original.local",
        "/x",
        &[("x-override", "client-value")],
    )
    .await;
    assert_eq!(status, 200);

    let req = rx.await.expect("backend captured request");
    // Host rewritten from :authority.
    assert!(req.contains("Host: rewritten.local"), "got: {req}");
    // Injected header present.
    assert!(req.contains("X-Injected: from-config"), "got: {req}");
    // Config Set semantics beat the client's header.
    assert!(req.contains("X-Override: new-value"), "got: {req}");
    assert!(!req.contains("client-value"), "got: {req}");
    // h2 pseudo/connection headers must not leak.
    assert!(!req.contains(":authority"), "got: {req}");
    assert!(!req.contains(":path"), "got: {req}");
}

/// Start a TLS (self-signed) HTTP/1.1 backend that captures the request head
/// and replies with the given raw response bytes.
async fn start_tls_capture_backend(
    resp: &'static [u8],
) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = frp_core::transport::generate_self_signed_tls_config().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut buf = vec![0u8; 8192];
                let n = tokio::io::AsyncReadExt::read(&mut tls, &mut buf)
                    .await
                    .unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = tls.write_all(resp).await;
                let _ = tls.flush().await;
            }
        }
    });
    (addr, rx)
}

#[tokio::test]
async fn test_https2https_h2_forwards_to_tls_backend() {
    // Self-signed TLS backend answering with a chunked body (exercises the
    // chunked → h2 DATA decoding path).
    let chunked_resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let (backend_addr, rx) = start_tls_capture_backend(chunked_resp).await;

    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path, cert_der) = write_plugin_cert(&dir);
    let mut cfg = plugin_cfg("https2https", backend_addr.to_string());
    cfg.crt_file = cert_path.to_str().unwrap().to_string();
    cfg.key_file = key_path.to_str().unwrap().to_string();
    let handle = frp_client::plugin::start_https2https_plugin(&cfg)
        .await
        .expect("start https2https plugin");
    std::mem::forget(dir);

    let connector = h2_client_connector(&cert_der);
    let (status, body) = h2_get(handle.local_addr, &connector, "example.com", "/tls", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello world", "chunked backend body must be decoded");

    // The TLS backend saw a plain HTTP/1.1 request.
    let req = rx.await.expect("backend captured request");
    assert!(req.starts_with("GET /tls HTTP/1.1"), "got: {req}");
    assert!(req.contains("Host: example.com"), "got: {req}");
}

#[tokio::test]
async fn test_https2http_h2_streams_chunked_response() {
    // Plaintext backend answering chunked (https2http h2 path).
    let chunked_resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let _ = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
            let _ = conn.write_all(chunked_resp).await;
            let _ = conn.flush().await;
        }
    });

    let (handle, cert_der) =
        start_https2http_with_cert(backend_addr.to_string(), None, HashMap::new(), "").await;
    let connector = h2_client_connector(&cert_der);
    let (status, body) = h2_get(
        handle.local_addr,
        &connector,
        "example.com",
        "/chunked",
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, "hello world", "chunked backend body must be decoded");
}

#[tokio::test]
async fn test_https2http_h2_502_when_backend_down() {
    // No backend: bind a port and drop it so connect fails.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let (_handle, cert_der) =
        start_https2http_with_cert(dead_addr.to_string(), None, HashMap::new(), "").await;
    let plugin_addr = _handle.local_addr;
    let connector = h2_client_connector(&cert_der);
    let (status, _) = h2_get(plugin_addr, &connector, "example.com", "/", &[]).await;
    assert_eq!(
        status, 502,
        "unreachable backend must answer 502 (Go ErrorHandler)"
    );
}

#[tokio::test]
async fn test_https2http_enable_http2_false_blocks_h2() {
    let (backend_addr, _rx) = start_capture_backend().await;
    let (_handle, cert_der) =
        start_https2http_with_cert(backend_addr.to_string(), Some(false), HashMap::new(), "").await;
    let plugin_addr = _handle.local_addr;
    let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();

    // 1) An h2-only client must fail the handshake: the server advertises only
    //    http/1.1, so there is no common ALPN protocol (Go behaves the same —
    //    empty TLSNextProto leaves the client without an h2 path).
    let tcp = TcpStream::connect(plugin_addr).await.unwrap();
    let err = h2_client_connector(&cert_der)
        .connect(server_name.clone(), tcp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("NoApplicationProtocol")
            || err.to_string().contains("no application protocol"),
        "expected ALPN failure, got: {err}"
    );

    // 2) A client offering h2 + http/1.1 negotiates http/1.1 (graceful
    //    fallback, matching Go's client-side ALPN behavior).
    let tcp = TcpStream::connect(plugin_addr).await.unwrap();
    let dual = client_connector(&cert_der, &[b"h2", b"http/1.1"]);
    let tls = dual
        .connect(server_name, tcp)
        .await
        .expect("dual-protocol client must connect");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice()),
        "enable_http2=false must negotiate http/1.1"
    );
}
