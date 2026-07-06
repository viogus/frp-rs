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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

use super::PluginHandle;

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

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("http2http plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("http2http plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "http2http plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((client, peer)) => {
                            let target = target_addr.clone();
                            let rewrite = host_rewrite.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_conn(client, &target, &rewrite).await {
                                    debug!(peer = %peer, error = %e, "http2http: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "http2http plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("http2http plugin shutting down");
                    break;
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

async fn handle_conn(
    mut client: TcpStream,
    target: &str,
    host_rewrite: &str,
) -> Result<(), String> {
    // Read HTTP headers in chunks until \r\n\r\n
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = client.read(&mut chunk).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if buf.len() > 65536 {
            return Err("request headers too large".into());
        }
    }

    // Split buffer on first \r\n\r\n to separate headers from any pre-read body data.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(buf.len());
    let headers_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = headers_str.lines();

    // Parse request line: METHOD URL HTTP/1.x
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let path = parts[1];

    // Connect to backend
    let mut remote = TcpStream::connect(target)
        .await
        .map_err(|e| format!("connect to {target}: {e}"))?;

    // Build forwarded request with optional Host rewrite
    let mut fwd = format!("{method} {path} HTTP/1.0\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if !host_rewrite.is_empty() && line.to_lowercase().starts_with("host:") {
            fwd.push_str(&format!("Host: {host_rewrite}\r\n"));
        } else {
            fwd.push_str(line);
            fwd.push_str("\r\n");
        }
    }
    fwd.push_str("Connection: close\r\n\r\n");

    remote
        .write_all(fwd.as_bytes())
        .await
        .map_err(|e| format!("write forward request: {e}"))?;

    // Copy response back to client
    let _ = tokio::io::copy(&mut remote, &mut client).await;
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
                assert!(req.contains("GET /test HTTP/1.0"), "unexpected request: {req}");
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello").await.unwrap();
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
                assert!(req.contains("Host: rewritten.local"), "expected Host rewrite, got: {req}");
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
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
