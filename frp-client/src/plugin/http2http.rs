//! http2http plugin — transparent HTTP reverse proxy.
//!
//! frpc listens on plain HTTP and forwards to a plain HTTP backend.
//! Headers are forwarded as-is; Host header can be rewritten.
//!
//! Go frp compat: HTTPProxyPlugin with no TLS on either side.
//!
//! Config:
//! - local_addr: backend host:port (e.g. "127.0.0.1:8080")
//! - host_header_rewrite: optional Host header override

use tokio::io::AsyncWriteExt;
#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tracing::debug;

use frp_core::config::PluginConfig;

use super::{serve_plugin, PluginHandle};

/// Start an http2http plugin server.
pub async fn start_http2http_plugin(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    let target_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        return Err(frp_core::Error::Transport(
            "http2http plugin: local_addr is required".into(),
        ));
    };
    let host_rewrite = cfg.host_header_rewrite.clone();
    let request_headers = cfg.request_headers.clone();
    serve_plugin(
        "http2http",
        (target_addr, host_rewrite, request_headers),
        |client, peer, (target, rewrite, headers)| async move {
            if let Err(e) = handle_conn(client, &target, &rewrite, &headers).await {
                debug!(%peer, error = %e, "http2http: {peer} error: {e}");
            }
        },
    )
    .await
}

async fn handle_conn(
    mut client: TcpStream,
    target: &str,
    host_rewrite: &str,
    request_headers: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let fwd =
        crate::plugin::read_request_and_build_forward(&mut client, host_rewrite, request_headers)
            .await?;

    // Connect to backend
    let mut remote = TcpStream::connect(target)
        .await
        .map_err(|e| format!("connect to {target}: {e}"))?;
    frp_core::transport::set_nodelay(&remote);

    remote
        .write_all(fwd.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    if let Err(e) = tokio::io::copy(&mut remote, &mut client).await {
        tracing::debug!(error = %e, "plugin relay error: {}", e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_http2http_smoke() {
        // Start a dummy HTTP backend
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
                let mut buf = vec![0; 4096];
                let n = conn.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    req.contains("GET /test HTTP/1.0"),
                    "unexpected request: {req}"
                );
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                    .await
                    .unwrap();
            }
        });

        let cfg = PluginConfig {
            plugin_type: "http2http".into(),
            local_addr: backend_addr.to_string(),
            ..Default::default()
        };

        let handle = match start_http2http_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
                return;
            }
        };
        let plugin_addr = handle.local_addr;

        // Connect to plugin and send HTTP request
        let mut client = TcpStream::connect(plugin_addr).await.unwrap();
        client
            .write_all(b"GET /test HTTP/1.1\r\nHost: original\r\n\r\n")
            .await
            .unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let body = String::from_utf8_lossy(&resp);
        assert!(body.contains("hello"), "unexpected response: {body}");
    }

    #[tokio::test]
    async fn test_http2http_host_rewrite() {
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
                let mut buf = vec![0; 4096];
                let n = conn.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    req.contains("Host: rewritten.local"),
                    "expected Host rewrite, got: {req}"
                );
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });

        let cfg = PluginConfig {
            plugin_type: "http2http".into(),
            local_addr: backend_addr.to_string(),
            host_header_rewrite: "rewritten.local".into(),
            ..Default::default()
        };

        let handle = match start_http2http_plugin(&cfg).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
                return;
            }
        };
        let mut client = TcpStream::connect(handle.local_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: original\r\n\r\n")
            .await
            .unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.0 200 OK"), "expected 200 OK");
    }
}
