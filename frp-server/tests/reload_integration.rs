//! Integration tests for configuration reload (SIGUSR1).
//!
//! These tests verify that frpc correctly handles SIGUSR1 by reloading
//! its proxy configuration and sending CloseProxy/NewProxy messages to frps.

#[cfg(unix)]
mod unix_tests {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{LazyLock, Mutex};
    use std::time::Duration;

    /// Resolve binary path for a workspace member.
    /// Prefers `<NAME>_BIN` env var (e.g. `FRPS_BIN`), then `CARGO_BIN_EXE_<name>`
    /// (set by Cargo), then `./frps`/`./frpc` in current dir (downloaded release),
    /// then falls back to constructing the path from the workspace root.
    fn workspace_bin(name: &str) -> PathBuf {
        // 1. <NAME>_BIN env var (pre-built release binary)
        let env_key = format!("{}_BIN", name.to_uppercase().replace('-', "_"));
        if let Ok(path) = std::env::var(&env_key) {
            let p = PathBuf::from(&path);
            if p.exists() {
                return p;
            }
        }
        // 2. CARGO_BIN_EXE_<name> (set by Cargo)
        let cargo_env_key = format!("CARGO_BIN_EXE_{}", name.to_uppercase().replace('-', "_"));
        if let Ok(path) = std::env::var(&cargo_env_key) {
            let p = PathBuf::from(&path);
            if p.exists() {
                return p;
            }
        }
        // 3. ../<name> in workspace root (downloaded release)
        let local = PathBuf::from(format!("../{}", name));
        if local.is_file() {
            return local;
        }
        // 4. Fallback: construct path relative to the workspace root.
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap();
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        workspace_root.join("target").join(profile).join(name)
    }

    /// Start a TCP echo server on `port` in a background thread.
    /// Returns a `JoinHandle` and a shutdown signal sender.
    /// The echo server accepts connections, reads up to 1024 bytes, writes
    /// them back, and closes each connection.
    fn start_tcp_echo_server(
        port: u16,
    ) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
        use std::net::TcpListener;
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let listener =
                TcpListener::bind(format!("127.0.0.1:{}", port)).expect("echo server bind failed");
            listener.set_nonblocking(true).ok();
            loop {
                // Check for shutdown signal
                if rx.try_recv().is_ok() {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                let _ = stream.write_all(&buf[..n]);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        (handle, tx)
    }

    /// Stop an echo server started by `start_tcp_echo_server`.
    fn stop_tcp_echo_server(handle: std::thread::JoinHandle<()>, tx: std::sync::mpsc::Sender<()>) {
        let _ = tx.send(());
        let _ = handle.join();
    }

    /// Wait until a TCP port is accepting connections, with timeout.
    fn wait_for_port(port: u16, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(timeout_secs) {
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", port).parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    /// Ports already handed out by this process — see allocate_port.
    static USED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

    /// Find an available TCP port. Never re-issues a port already handed
    /// out by this process, and re-verifies availability right before
    /// returning (narrows the probe-then-drop window).
    fn allocate_port() -> u16 {
        use std::net::TcpListener;
        for _ in 0..64 {
            let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
                break;
            };
            let Ok(addr) = listener.local_addr() else {
                break;
            };
            let port = addr.port();
            {
                let mut used = USED_PORTS.lock().unwrap();
                if !used.insert(port) {
                    continue; // already handed out in this process — probe again
                }
                // Narrow the probe-then-drop window: confirm the port is
                // still free before handing it out.
                if TcpListener::bind(("127.0.0.1", port)).is_err() {
                    used.remove(&port);
                    continue;
                }
            }
            return port;
        }
        sandbox_fallback()
    }

    /// Sandbox fallback: return an ephemeral port (49152-65535 range).
    /// Deterministic per process, so walk past ports already handed out to
    /// avoid handing the same fallback port to two tests.
    fn sandbox_fallback() -> u16 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_usize(std::process::id() as usize);
        let base = 49152 + (h.finish() % 16384) as u16;
        let mut used = USED_PORTS.lock().unwrap();
        for i in 0..16384u16 {
            let port = 49152 + ((base - 49152 + i) % 16384);
            if used.insert(port) {
                return port;
            }
        }
        base
    }

    /// Send data to a TCP port and read the response.
    fn tcp_echo(port: u16, data: &[u8], timeout_secs: u64) -> Result<Vec<u8>, String> {
        let mut stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", port).parse().unwrap(),
            Duration::from_secs(timeout_secs),
        )
        .map_err(|e| format!("connect: {}", e))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(timeout_secs)))
            .ok();
        stream
            .write_all(data)
            .map_err(|e| format!("write: {}", e))?;
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).map_err(|e| format!("read: {}", e))?;
        Ok(buf[..n].to_vec())
    }

    #[tokio::test]
    async fn test_reload_add_proxy() {
        // No tracing init needed — test uses eprintln! for diagnostics.

        // Skip if binaries not built.
        let frps_bin = workspace_bin("frps");
        let frpc_bin = workspace_bin("frpc");
        if !frps_bin.exists() || !frpc_bin.exists() {
            eprintln!(
                "Skipping: binaries not found ({}, {}) — build with: cargo build -p frps -p frpc",
                frps_bin.display(),
                frpc_bin.display(),
            );
            return;
        }

        let bind_port = allocate_port();
        let proxy_a_local = allocate_port();
        let proxy_a_remote = allocate_port();
        let proxy_b_local = allocate_port();
        let proxy_b_remote = allocate_port();
        let token = "test-reload-token";

        let dir = tempfile::TempDir::new().unwrap();
        let frps_config_path = dir.path().join("frps.toml");
        let frpc_config_path = dir.path().join("frpc.toml");

        // ---- Step 1: Start echo servers for proxy A and B ----
        let (echo_a_handle, echo_a_tx) = start_tcp_echo_server(proxy_a_local);
        let (echo_b_handle, echo_b_tx) = start_tcp_echo_server(proxy_b_local);
        assert!(wait_for_port(proxy_a_local, 5), "echo A did not start");
        assert!(wait_for_port(proxy_b_local, 5), "echo B did not start");

        // ---- Step 2: Write frps config ----
        let frps_config = format!(
            r#"
bind_addr = "127.0.0.1"
bind_port = {bind_port}

[auth]
method = "token"
token = "{token}"

[transport]
tcp_mux = false
"#,
            bind_port = bind_port,
            token = token,
        );
        std::fs::write(&frps_config_path, &frps_config).unwrap();

        // ---- Step 3: Write initial frpc config (proxy A only) ----
        let frpc_config_initial = format!(
            r#"
server_addr = "127.0.0.1"
server_port = {bind_port}
auth.token = "{token}"
transport.tls.enable = false
transport.tcp_mux = false

[[proxies]]
name = "tcp-a"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {proxy_a_local}
remote_port = {proxy_a_remote}
"#,
            bind_port = bind_port,
            token = token,
            proxy_a_local = proxy_a_local,
            proxy_a_remote = proxy_a_remote,
        );
        std::fs::write(&frpc_config_path, &frpc_config_initial).unwrap();

        // ---- Step 4: Start frps ----
        let mut frps = Command::new(&frps_bin)
            .arg("-c")
            .arg(&frps_config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start frps");
        assert!(wait_for_port(bind_port, 10), "frps did not start");

        // ---- Step 5: Start frpc ----
        let mut frpc = Command::new(&frpc_bin)
            .arg("-c")
            .arg(&frpc_config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start frpc");

        // Wait for proxy A to be ready (poll the remote port).
        assert!(
            wait_for_port(proxy_a_remote, 10),
            "proxy A never became ready"
        );

        // ---- Step 6: Test proxy A works ----
        let echo_result = tcp_echo(proxy_a_remote, b"hello-from-a", 5);
        assert!(
            echo_result.is_ok(),
            "proxy A should work before reload: {:?}",
            echo_result.err()
        );
        assert_eq!(echo_result.unwrap(), b"hello-from-a".to_vec());

        // ---- Step 7: Rewrite frpc config with proxy B added ----
        let frpc_config_reloaded = format!(
            r#"
server_addr = "127.0.0.1"
server_port = {bind_port}
auth.token = "{token}"
transport.tls.enable = false
transport.tcp_mux = false

[[proxies]]
name = "tcp-a"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {proxy_a_local}
remote_port = {proxy_a_remote}

[[proxies]]
name = "tcp-b"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {proxy_b_local}
remote_port = {proxy_b_remote}
"#,
            bind_port = bind_port,
            token = token,
            proxy_a_local = proxy_a_local,
            proxy_a_remote = proxy_a_remote,
            proxy_b_local = proxy_b_local,
            proxy_b_remote = proxy_b_remote,
        );
        std::fs::write(&frpc_config_path, &frpc_config_reloaded).unwrap();

        // ---- Step 8: Send SIGUSR1 to frpc ----
        let frpc_pid = frpc.id();
        let kill_status = Command::new("kill")
            .args(["-USR1", &frpc_pid.to_string()])
            .status()
            .expect("kill command failed");
        assert!(kill_status.success(), "kill -USR1 failed");

        // Wait for reload to take effect (proxy B's remote port must come up).
        assert!(
            wait_for_port(proxy_b_remote, 10),
            "proxy B never became ready after reload"
        );

        // ---- Step 9: Verify proxy A still works (no interruption) ----
        let echo_a_after = tcp_echo(proxy_a_remote, b"hello-a-after", 5);
        assert!(
            echo_a_after.is_ok(),
            "proxy A should still work after reload: {:?}",
            echo_a_after.err()
        );
        assert_eq!(echo_a_after.unwrap(), b"hello-a-after".to_vec());

        // ---- Step 10: Verify proxy B now works ----
        let echo_b_result = tcp_echo(proxy_b_remote, b"hello-from-b", 5);
        assert!(
            echo_b_result.is_ok(),
            "proxy B should work after reload: {:?}",
            echo_b_result.err()
        );
        assert_eq!(echo_b_result.unwrap(), b"hello-from-b".to_vec());

        // Cleanup
        let _ = frpc.kill();
        let _ = frps.kill();
        let _ = frpc.wait();
        let _ = frps.wait();
        stop_tcp_echo_server(echo_a_handle, echo_a_tx);
        stop_tcp_echo_server(echo_b_handle, echo_b_tx);
    }
}
