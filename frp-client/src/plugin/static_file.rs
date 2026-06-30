use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use frp_core::config::PluginConfig;

use super::{PluginHandle, urlencoding_decode};
use super::http::HttpProxyAuth;

// ---------------------------------------------------------------
// static_file plugin
// ---------------------------------------------------------------

/// Start a static file serving plugin.
///
/// Serves files from `local_path` directory over HTTP.
/// Supports optional basic auth (`http_user` / `http_password`)
/// and URL prefix stripping (`strip_prefix`).
pub async fn start_static_file_proxy(cfg: &PluginConfig) -> Result<PluginHandle, frp_core::Error> {
    if cfg.local_path.is_empty() {
        return Err(frp_core::Error::Config(
            "static_file plugin requires local_path".into()
        ));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        frp_core::Error::Transport(format!("static_file plugin: bind: {e}"))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("static_file plugin: local_addr: {e}"))
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let auth = HttpProxyAuth::from_config(cfg);
    let local_path = cfg.local_path.clone();
    let strip_prefix: Option<String> = if cfg.strip_prefix.is_empty() {
        None
    } else {
        Some(cfg.strip_prefix.trim_matches('/').to_string())
    };

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "static_file plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            let a = auth.clone();
                            let lp = local_path.clone();
                            let sp = strip_prefix.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_static_file_conn(stream, a, &lp, sp.as_deref()).await
                                {
                                    debug!(peer = %peer, error = %e, "static_file: {peer} error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "static_file plugin accept error: {e}");
                            break;
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    debug!("static_file plugin shutting down");
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

async fn handle_static_file_conn(
    mut client: TcpStream,
    auth: HttpProxyAuth,
    local_path: &str,
    strip_prefix: Option<&str>,
) -> Result<(), String> {
    // Read HTTP request headers (reuse pattern from http_proxy)
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        client.read_exact(&mut byte).await.map_err(|e| format!("read: {e}"))?;
        buf.push(byte[0]);
        if buf.len() > 3
            && buf[buf.len() - 4] == b'\r'
            && buf[buf.len() - 3] == b'\n'
            && buf[buf.len() - 2] == b'\r'
            && buf[buf.len() - 1] == b'\n'
        {
            break;
        }
        if buf.len() > 65536 {
            return Err("request too large".into());
        }
    }

    let headers_str = String::from_utf8_lossy(&buf);
    let mut lines = headers_str.lines();

    // Parse request line
    let request_line = lines.next().ok_or("empty request")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad request line: {request_line}"));
    }
    let method = parts[0];
    let url_path = parts[1];

    if method != "GET" {
        let resp = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err(format!("method not allowed: {method}"));
    }

    // Check auth (Authorization header with Basic scheme)
    let mut authorization = String::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("authorization") {
                authorization = value.trim().to_string();
            }
        }
    }

    if !auth.check(&authorization) {
        let resp = b"HTTP/1.1 401 Unauthorized\r\n\
                       WWW-Authenticate: Basic realm=\"frp\"\r\n\
                       Content-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err("auth failed".into());
    }

    // Decode URL and strip prefix to get relative filesystem path
    let rel_path = resolve_static_path(url_path, strip_prefix)?;

    // Sanitize: reject path traversal
    if rel_path.contains("..") {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(resp).await;
        return Err("path traversal rejected".into());
    }

    // Build full filesystem path
    let mut full_path = std::path::PathBuf::from(local_path);
    if !rel_path.is_empty() {
        full_path = full_path.join(&rel_path);
    }

    // If directory, try index.html
    if full_path.is_dir() {
        full_path = full_path.join("index.html");
    }

    // Read and serve file
    let content = match std::fs::read(&full_path) {
        Ok(data) => data,
        Err(_) => {
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = client.write_all(resp).await;
            return Err(format!("file not found: {}", full_path.display()));
        }
    };

    let mime = mime_from_path(&full_path);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    );
    client.write_all(resp.as_bytes()).await.map_err(|e| format!("write headers: {e}"))?;
    client.write_all(&content).await.map_err(|e| format!("write body: {e}"))?;

    Ok(())
}

/// Resolve a URL path to a relative filesystem path, with optional prefix stripping.
/// Returns a relative path (no leading `/`) or empty string for root.
fn resolve_static_path(url_path: &str, strip_prefix: Option<&str>) -> Result<String, String> {
    // URL-decode
    let decoded = urlencoding_decode(url_path);

    let stripped = if let Some(prefix) = strip_prefix {
        let prefix_slash = format!("/{prefix}");
        match decoded.strip_prefix(&prefix_slash) {
            Some(rest) => rest,
            None => {
                return Err(format!("prefix '{}' not found in path '{}'", prefix, decoded));
            }
        }
    } else {
        &decoded
    };

    // Convert to relative path: strip leading /, empty string for root
    let trimmed = stripped.trim_start_matches('/');
    Ok(trimmed.to_string())
}

/// Detect MIME type from file extension.
fn mime_from_path(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("wasm") => "application/wasm",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_static_path_no_prefix() {
        assert_eq!(resolve_static_path("/", None).unwrap(), "");
        assert_eq!(resolve_static_path("/index.html", None).unwrap(), "index.html");
        assert_eq!(resolve_static_path("/css/style.css", None).unwrap(), "css/style.css");
        assert_eq!(resolve_static_path("/a/b/c.html", None).unwrap(), "a/b/c.html");
    }

    #[test]
    fn test_resolve_static_path_with_prefix() {
        let sp = Some("static");
        assert_eq!(resolve_static_path("/static/", sp).unwrap(), "");
        assert_eq!(resolve_static_path("/static/index.html", sp).unwrap(), "index.html");
        assert_eq!(resolve_static_path("/static/css/style.css", sp).unwrap(), "css/style.css");
    }

    #[test]
    fn test_resolve_static_path_prefix_mismatch() {
        assert!(resolve_static_path("/other/file.html", Some("static")).is_err());
        assert!(resolve_static_path("/", Some("static")).is_err());
    }

    #[test]
    fn test_mime_from_path() {
        use std::path::Path;
        assert_eq!(mime_from_path(Path::new("index.html")), "text/html; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("style.css")), "text/css; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("app.js")), "application/javascript; charset=utf-8");
        assert_eq!(mime_from_path(Path::new("image.png")), "image/png");
        assert_eq!(mime_from_path(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(mime_from_path(Path::new("unknown.xyz")), "application/octet-stream");
    }

    #[test]
    fn test_resolve_static_path_rejects_traversal() {
        // resolve_static_path itself doesn't reject .. — caller does.
        // Verify that .. passes through (caller's responsibility to check).
        assert_eq!(resolve_static_path("/../etc/passwd", None).unwrap(), "../etc/passwd");
    }
}
