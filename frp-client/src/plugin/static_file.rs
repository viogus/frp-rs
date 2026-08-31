use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::debug;

use frp_core::config::PluginConfig;

use super::http::HttpProxyAuth;
use super::{serve_plugin, urlencoding_decode, PluginHandle};

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
            "static_file plugin requires local_path".into(),
        ));
    }
    let auth = HttpProxyAuth::from_config(cfg);
    let local_path = cfg.local_path.clone();
    let strip_prefix: Option<String> = if cfg.strip_prefix.is_empty() {
        None
    } else {
        Some(cfg.strip_prefix.trim_matches('/').to_string())
    };
    // The base directory is canonicalized PER REQUEST inside
    // `handle_static_file_conn` (see the audit-F comment there) — a startup
    // cache went stale when a base-dir symlink retargeted after startup
    // (versioned deploys like /var/www/current), 403ing every file
    // (round-17 review LOW).
    let state = (auth, local_path, strip_prefix);
    serve_plugin(
        "static_file",
        state,
        |stream, peer, (a, lp, sp)| async move {
            if let Err(e) = handle_static_file_conn(stream, a, &lp, sp.as_deref()).await {
                debug!(%peer, error = %e, "static_file: {peer} error: {e}");
            }
        },
    )
    .await
}

async fn handle_static_file_conn(
    mut client: TcpStream,
    auth: HttpProxyAuth,
    local_path: &str,
    strip_prefix: Option<&str>,
) -> Result<(), String> {
    // Read HTTP request headers in chunks until \r\n\r\n. Stop at the FIRST
    // \r\n\r\n anywhere in the buffer (not only at its end): a pipelined or
    // body-carrying request may follow the head terminator with more bytes,
    // and the tail-only check would read past it into the next request until
    // the 64 KiB cap.
    // Go parity: http.Server ReadHeaderTimeout (60s) — one absolute deadline
    // over the whole header read, so a slowloris "trickle" cannot park the
    // task + fd + plugin listener slot indefinitely.
    let buf = tokio::time::timeout(Duration::from_secs(60), async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = client
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed".into());
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 65536 {
                return Err("request too large".into());
            }
        }
        Ok::<Vec<u8>, String>(buf)
    })
    .await
    .map_err(|_| "read headers timed out".to_string())??;

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
        let resp =
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
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
        // Go frp compat: 200ms delay to slow brute-force attacks.
        sleep(Duration::from_millis(200)).await;
        let resp = b"HTTP/1.1 401 Unauthorized\r\n\
                       WWW-Authenticate: Basic realm=\"frp\"\r\n\
                       Content-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("auth failed".into());
    }

    // Decode URL and strip prefix to get relative filesystem path
    let rel_path = resolve_static_path(url_path, strip_prefix)?;

    // Sanitize: reject path traversal (component-level check).
    // Reject empty path components (//), current-dir (.), and parent-dir (..).
    if !validate_rel_path(&rel_path) {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
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

    // Defense-in-depth: canonicalize the base directory, then open the file
    // and verify via the ALREADY-OPENED handle that it stays within the base.
    // The verification must resolve the open fd's inode, not re-resolve the
    // path: re-canonicalizing the path after open() lets a symlink swap
    // between the two make the check disagree with the opened inode (TOCTOU).
    // Round-17 audit F: the base is canonicalized per request — a startup
    // cache went stale when a base-dir symlink retargeted (versioned deploys)
    // and 403'd every file (round-17 review LOW). Go's http.FileServer
    // canonicalizes per request too; the cost is a short path walk per
    // request, not per byte.
    let base = std::fs::canonicalize(local_path)
        .map_err(|e| format!("failed to resolve base directory '{}': {e}", local_path))?;

    // Open the file first, then check the canonical path on the open handle.
    let file = match std::fs::File::open(&full_path) {
        Ok(f) => f,
        Err(_) => {
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            if let Err(e) = client.write_all(resp).await {
                tracing::debug!(error = %e, "plugin relay error: {}", e);
            }
            return Err(format!("file not found: {}", full_path.display()));
        }
    };

    // Linux: canonicalize via /proc/self/fd/<fd> — the fd symlink resolves to
    // the inode the handle is pinned to, closing the TOCTOU window (a symlink
    // swap after open() cannot change what the fd points at).
    #[cfg(target_os = "linux")]
    let resolved = {
        use std::os::unix::io::AsRawFd;
        std::fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| format!("failed to resolve path: {e}"))?
    };
    // Non-Linux: no /proc/self/fd — re-canonicalize the path. The residual
    // race (a symlink swap between open() and canonicalize() making the
    // check disagree with the opened inode) is accepted here; the check
    // remains defense-in-depth on top of the component-level path validation.
    #[cfg(not(target_os = "linux"))]
    let resolved =
        std::fs::canonicalize(&full_path).map_err(|e| format!("failed to resolve path: {e}"))?;
    if !resolved.starts_with(&base) {
        let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if let Err(e) = client.write_all(resp).await {
            tracing::debug!(error = %e, "plugin relay error: {}", e);
        }
        return Err("path traversal rejected".into());
    }

    // Stream the file body in bounded chunks instead of buffering it whole:
    // the old path blocked the async task on std::fs::read_to_end and
    // truncated at 64 MiB (Content-Length then lied). Go's http.FileServer
    // streams the file — so do we, from the already-open, inode-verified
    // handle (tokio::fs::File wraps the same fd; position is still 0).
    let mut file = tokio::fs::File::from_std(file);
    let size = file
        .metadata()
        .await
        .map_err(|e| format!("failed to stat file: {e}"))?
        .len();

    let mime = mime_from_path(&full_path);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n"
    );
    client
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("write headers: {e}"))?;

    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut chunk)
            .await
            .map_err(|e| format!("failed to read file: {e}"))?;
        if n == 0 {
            break;
        }
        client
            .write_all(&chunk[..n])
            .await
            .map_err(|e| format!("write body: {e}"))?;
    }

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
                return Err(format!(
                    "prefix '{}' not found in path '{}'",
                    prefix, decoded
                ));
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

/// Validate a relative path for path traversal attempts.
/// Returns true if the path is safe to use (no empty components, no `.`, no `..`).
fn validate_rel_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    !path
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_static_path_no_prefix() {
        assert_eq!(resolve_static_path("/", None).unwrap(), "");
        assert_eq!(
            resolve_static_path("/index.html", None).unwrap(),
            "index.html"
        );
        assert_eq!(
            resolve_static_path("/css/style.css", None).unwrap(),
            "css/style.css"
        );
        assert_eq!(
            resolve_static_path("/a/b/c.html", None).unwrap(),
            "a/b/c.html"
        );
    }

    #[test]
    fn test_resolve_static_path_with_prefix() {
        let sp = Some("static");
        assert_eq!(resolve_static_path("/static/", sp).unwrap(), "");
        assert_eq!(
            resolve_static_path("/static/index.html", sp).unwrap(),
            "index.html"
        );
        assert_eq!(
            resolve_static_path("/static/css/style.css", sp).unwrap(),
            "css/style.css"
        );
    }

    #[test]
    fn test_resolve_static_path_prefix_mismatch() {
        assert!(resolve_static_path("/other/file.html", Some("static")).is_err());
        assert!(resolve_static_path("/", Some("static")).is_err());
    }

    #[test]
    fn test_mime_from_path() {
        use std::path::Path;
        assert_eq!(
            mime_from_path(Path::new("index.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            mime_from_path(Path::new("style.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            mime_from_path(Path::new("app.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_from_path(Path::new("image.png")), "image/png");
        assert_eq!(mime_from_path(Path::new("photo.jpg")), "image/jpeg");
        assert_eq!(
            mime_from_path(Path::new("unknown.xyz")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_resolve_static_path_rejects_traversal() {
        // resolve_static_path itself doesn't reject .. — caller does.
        // Verify that .. passes through (caller's responsibility to check).
        assert_eq!(
            resolve_static_path("/../etc/passwd", None).unwrap(),
            "../etc/passwd"
        );
    }

    #[test]
    fn test_validate_rel_path_rejects_traversal() {
        assert!(!validate_rel_path(".."));
        assert!(!validate_rel_path("../etc/passwd"));
        assert!(!validate_rel_path("foo/../../bar"));
        assert!(!validate_rel_path("."));
        assert!(!validate_rel_path("./config"));
        assert!(!validate_rel_path("foo/./bar"));
        assert!(!validate_rel_path("foo//bar"));
        assert!(!validate_rel_path("foo///bar"));
        // urlencoding_decode would decode %2F to /, which would produce
        // an empty component and be rejected
        assert!(!validate_rel_path("foo//bar"));
    }

    #[test]
    fn test_validate_rel_path_allows_normal() {
        assert!(validate_rel_path(""));
        assert!(validate_rel_path("index.html"));
        assert!(validate_rel_path("css/style.css"));
        assert!(validate_rel_path("a/b/c.html"));
        assert!(validate_rel_path("file.with..dots"));
        assert!(validate_rel_path("something..test"));
    }
}
