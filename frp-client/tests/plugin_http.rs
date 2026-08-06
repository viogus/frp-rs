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
use tokio::net::TcpStream;

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
