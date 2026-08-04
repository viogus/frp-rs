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
    data_encoding::BASE64.encode(s.as_bytes())
}

/// Send a raw HTTP GET and return (status_code, body).
/// Reads until EOF — the static_file responses carry `Connection: close`, so
/// EOF is the body end. Read the full body so the caller can assert on it.
async fn http_get(
    addr: std::net::SocketAddr,
    path: &str,
    user: Option<(&str, &str)>,
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let auth = match user {
        Some((u, p)) => format!("Authorization: Basic {}\r\n", b64(&format!("{u}:{p}"))),
        None => String::new(),
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}\r\n");
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
        eprintln!("http_get raw bytes: {:?}", &raw[..raw.len().min(256)]);
    }
    (status, text)
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
    let (status, _) = http_get(handle.local_addr, "/", None).await;
    assert_eq!(status, 401, "missing auth must be rejected");

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
    let (status, _) = http_get(handle.local_addr, "/nope.html", None).await;
    assert_eq!(status, 404, "missing file must 404");
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
    assert_eq!(status, 403, "path traversal must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}
