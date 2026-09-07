//! Integration tests for the `static_file` plugin: serves files over HTTP
//! with optional basic auth, 404 handling, and path-traversal rejection.
//!
//! Go frp compat: StaticFilePlugin.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use frp_core::config::PluginConfig;

/// Create a temp dir containing `index.html`, return the dir path.
/// Monotonic counter so parallel tests never collide on temp dir names
/// (SystemTime::now() nanos can be identical across quick consecutive calls).
static DIR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir_with_index(content: &str) -> PathBuf {
    let seq = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frp-rs-static-{}-{}-{}",
        std::process::id(),
        nanos,
        seq
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), content).unwrap();
    dir
}

fn b64(s: &str) -> String {
    frp_core::base64::encode(s.as_bytes())
}

/// Send a raw HTTP request and return (status_code, body).
/// Reads until EOF — the static_file responses carry `Connection: close`, so
/// EOF is the body end. Read the full body so the caller can assert on it.
async fn http_req(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    user: Option<(&str, &str)>,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = match user {
        Some((u, p)) => format!("Authorization: Basic {}\r\n", b64(&format!("{u}:{p}"))),
        None => String::new(),
    };
    let req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n");
    s.write_all(req.as_bytes()).await.unwrap();

    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), s.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => raw.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                eprintln!("http_get read error: {e}");
                break;
            }
            Err(_) => {
                eprintln!("http_get read timeout (server did not close)");
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .map(|s| s.parse().unwrap_or(0))
        .unwrap_or(0);
    if status == 0 {
        eprintln!("http_req raw bytes: {:?}", &raw[..raw.len().min(256)]);
    }
    (status, text)
}

/// Send a raw HTTP GET and return (status_code, body).
async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    user: Option<(&str, &str)>,
) -> (u16, String) {
    http_req(addr, "GET", path, user).await
}

#[tokio::test]
async fn test_static_file_plugin_serves_index() {
    let dir = temp_dir_with_index("hello-static");
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");
    let (status, body) = http_get(handle.local_addr, "/", None).await;
    assert_eq!(status, 200, "GET / should serve index.html: {body}");
    assert!(body.contains("hello-static"), "body mismatch: {body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_static_file_plugin_auth() {
    let dir = temp_dir_with_index("secret-file");
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        http_user: "admin".into(),
        http_password: "s3cret".into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");

    // No credentials → 401 (server adds a 200ms anti-brute-force delay).
    // Wire parity probe vs Go v0.71.0 (pkg/util/net/http.go:45-59
    // NewHTTPAuthMiddleware): realm "Restricted", text/plain body
    // "Unauthorized\n" (http.Error), no Connection header.
    let (status, body) = http_get(handle.local_addr, "/", None).await;
    assert_eq!(status, 401, "missing auth must be rejected");
    assert!(
        body.starts_with("HTTP/1.1 401 Unauthorized\r\n")
            && body.contains("WWW-Authenticate: Basic realm=\"Restricted\"\r\n")
            && body.contains("Content-Type: text/plain; charset=utf-8\r\n")
            && body.ends_with("\r\n\r\nUnauthorized\n"),
        "Go-parity 401 wire, got: {body:?}"
    );

    // Correct credentials → 200.
    let (status, body) = http_get(handle.local_addr, "/", Some(("admin", "s3cret"))).await;
    assert_eq!(status, 200, "valid auth must succeed: {body}");
    assert!(body.contains("secret-file"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_static_file_plugin_missing_file_404() {
    let dir = temp_dir_with_index("x");
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");
    let (status, body) = http_get(handle.local_addr, "/nope.html", None).await;
    assert_eq!(status, 404, "missing file must 404");
    assert!(
        body.contains("404 page not found\n"),
        "Go http.Error 404-page body (not a bare CL:0 head), got: {body:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_static_file_plugin_rejects_path_traversal() {
    let dir = temp_dir_with_index("y");
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");
    let (status, _) = http_get(handle.local_addr, "/../etc/passwd", None).await;
    // Go FileServer parity: the FileServer chain (fileHandler → serveFile
    // → http.Dir.Open, src/net/http/fs.go) passes `path.Clean("/../etc/
    // passwd")` = "/etc/passwd" to Dir.Open, which joins inside the root —
    // the ".." never escapes, so a non-existent cleaned path is a plain
    // 404. (The containsDotDot 400 arm lives only in the ServeFile/
    // ServeFileFS helpers, NOT in the FileServer handler this plugin
    // uses.) Probe vs go1.25.12 FileServer: /../etc/passwd and
    // /sub/../../etc/passwd both answer 404 Not Found. The old 403 pin
    // predates the anchored path.Clean (".." clamped at root instead of
    // rejected outright).
    assert_eq!(status, 404, "path traversal must 404 like Go FileServer");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_static_file_plugin_head_is_405() {
    let dir = temp_dir_with_index("head-body");
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");

    // gorilla Methods("GET") matches the raw request method exactly — HEAD
    // is NOT rewritten onto the GET route (round-13-era claim was false;
    // mux_test.go:2643 pins it), so HEAD answers the bare 405
    // methodNotAllowedHandler render before any auth or file I/O.
    let (status, body) = http_req(handle.local_addr, "HEAD", "/", None).await;
    assert_eq!(status, 405, "HEAD must be a route-method miss: {body}");
    assert!(
        body.starts_with(
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        "bare 405 render, got: {body:?}"
    );

    // POST: same gate, on a valid file path too.
    let (status, body) = http_req(handle.local_addr, "POST", "/index.html", None).await;
    assert_eq!(status, 405, "POST must be a route-method miss: {body}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_static_file_plugin_dir_listing() {
    // Root keeps an index.html (temp_dir_with_index) — the listing is
    // exercised on a subdirectory that has none.
    let dir = temp_dir_with_index("root-body");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/alpha.txt"), b"a").unwrap();
    std::fs::write(dir.join("sub/beta.txt"), b"b").unwrap();
    std::fs::create_dir(dir.join("sub/leaf")).unwrap();
    let cfg = PluginConfig {
        plugin_type: "static_file".into(),
        local_path: dir.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = frp_client::plugin::start_static_file_proxy(&cfg)
        .await
        .expect("start static_file plugin");

    // GET on a dir without index.html → 200 dirList page (Go fs.go
    // dirList parity): text/html, byte-wise sorted <pre> anchors, dirs
    // "/"-suffixed.
    let (status, body) = http_get(handle.local_addr, "/sub/", None).await;
    assert_eq!(status, 200, "dir without index must list: {body}");
    assert!(
        body.contains("Content-Type: text/html; charset=utf-8\r\n"),
        "listing is html: {body}"
    );
    let t = body.as_str();
    let alpha = t
        .find("<a href=\"alpha.txt\">alpha.txt</a>")
        .unwrap_or_else(|| panic!("alpha anchor missing: {t}"));
    let beta = t
        .find("<a href=\"beta.txt\">beta.txt</a>")
        .unwrap_or_else(|| panic!("beta anchor missing: {t}"));
    let leaf = t
        .find("<a href=\"leaf/\">leaf/</a>")
        .unwrap_or_else(|| panic!("leaf anchor missing: {t}"));
    assert!(alpha < beta && beta < leaf, "byte-wise sorted listing: {t}");
    assert!(t.ends_with("</pre>\n"), "dirList closes the pre block: {t}");

    // The slash-less dir still redirects BEFORE any listing (FileServer
    // localRedirect parity).
    let (status, body) = http_get(handle.local_addr, "/sub", None).await;
    assert_eq!(status, 301, "slash-less dir must redirect: {body}");
    assert!(
        body.contains("Location: sub/\r\n"),
        "relative Location, got: {body:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
