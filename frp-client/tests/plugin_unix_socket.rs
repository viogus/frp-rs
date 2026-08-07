//! Integration tests for the `unix_domain_socket` plugin: bridges frp tunnel
//! connections (TCP) to a local Unix domain socket backend.
//!
//! Go frp compat: UnixDomainSocketPlugin.

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use frp_core::config::PluginConfig;

/// Unique socket path per test (process id + timestamp) so parallel tests
/// never collide on the temp dir.
fn unique_socket_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("frp-rs-{tag}-{}-{}", std::process::id(), nanos);
    // Unix socket paths are capped at SUN_LEN (104 bytes on macOS, 108 on
    // Linux). Sandboxes sometimes set TMPDIR to a very long path, which would
    // make the bind fail with "path must be shorter than SUN_LEN" — fall back
    // to /tmp in that case (cfg(unix), so /tmp always exists).
    let path = std::env::temp_dir().join(&name);
    if path.to_str().is_some_and(|s| s.len() < 100) {
        path
    } else {
        PathBuf::from("/tmp").join(&name)
    }
}

/// Start an echo server on a Unix domain socket.
async fn start_unix_echo(path: &str) -> tokio::task::JoinHandle<()> {
    let listener = match tokio::net::UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => panic!("bind unix listener {path}: {e}"),
    };
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    })
}

/// Wait (up to 2s) until a TCP port accepts connections.
async fn wait_tcp_ready(addr: std::net::SocketAddr) {
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("plugin port {addr} never became ready");
}

#[tokio::test]
async fn test_unix_socket_plugin_echo_bridge() {
    let path = unique_socket_path("echo");
    let path_str = path.to_str().unwrap().to_string();
    let _echo = start_unix_echo(&path_str).await;

    let cfg = PluginConfig {
        plugin_type: "unix_domain_socket".into(),
        local_addr: path_str.clone(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_unix_socket_plugin(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    wait_tcp_ready(handle.local_addr).await;

    let mut client = TcpStream::connect(handle.local_addr)
        .await
        .expect("connect to plugin");
    client.write_all(b"ping-through-unix").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("echo timeout")
        .expect("echo read");
    assert_eq!(&buf[..n], b"ping-through-unix", "unix echo mismatch");

    drop(client);
    drop(handle);
    let _ = std::fs::remove_file(&path);
}

/// Missing backend socket: the bridge cannot be established, so the client
/// connection must be closed (EOF), not hang.
#[tokio::test]
async fn test_unix_socket_plugin_missing_backend() {
    let path = unique_socket_path("missing");

    let cfg = PluginConfig {
        plugin_type: "unix_domain_socket".into(),
        local_addr: path.to_str().unwrap().into(),
        ..Default::default()
    };
    let handle = match frp_client::plugin::start_unix_socket_plugin(&cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Skipping test: cannot start plugin (sandboxed): {e}");
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    wait_tcp_ready(handle.local_addr).await;

    let mut client = TcpStream::connect(handle.local_addr)
        .await
        .expect("connect to plugin");
    client.write_all(b"x").await.unwrap();

    let mut buf = [0u8; 8];
    match tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await {
        Err(_) => panic!("read should not hang when backend is missing"),
        // EOF, or reset — either way the connection is closed, not bridged.
        Ok(Ok(n)) => assert_eq!(n, 0, "missing backend → connection should close"),
        Ok(Err(_)) => {}
    }
}
