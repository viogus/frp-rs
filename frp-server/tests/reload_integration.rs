//! Integration tests for configuration reload (SIGUSR1).
//!
//! These tests verify that frpc correctly handles SIGUSR1 by reloading
//! its proxy configuration and sending CloseProxy/NewProxy messages to frps.

#[cfg(unix)]
mod unix_tests {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
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

    /// Wait until a TCP port stops accepting connections, with timeout.
    /// A listening socket that has been closed rejects new connects.
    fn wait_for_port_closed(port: u16, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(timeout_secs) {
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{}", port).parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_err()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    /// Current byte length of a log file (appended to by a live child).
    fn log_len(path: &Path) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// Wait for `marker` to appear in the log file at or after byte `offset`.
    fn wait_for_log_since(path: &Path, offset: u64, marker: &str, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(timeout_secs) {
            if let Ok(content) = std::fs::read(path) {
                if content.len() as u64 > offset
                    && String::from_utf8_lossy(&content[offset as usize..]).contains(marker)
                {
                    return true;
                }
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

    /// Reload of a health-checked proxy WITH `user` configured (regression).
    ///
    /// Audit-fix Task 5: `try_reload` keyed its health-state cleanup by the
    /// BARE proxy name while every producer/consumer (spawn_health_checks,
    /// Service::new, the CloseProxy handler, the Recover handler) uses the
    /// WIRE name `{user}.{name}`. With `user` configured that meant:
    ///   - a reload-REMOVED health-checked proxy kept its health task forever
    ///     and re-registered on the server whenever the local service came
    ///     back after a failure, and
    ///   - a reload-ADDED health-checked proxy's Recover event found no
    ///     config, so it never re-registered after recovery.
    /// A CHANGED proxy goes through the same reload insert path as an added
    /// one (Step 5/6 of reload_from_sources), so the add phase below covers
    /// the changed lookup too; the removal phase covers the Step 1 cancel
    /// path that changed proxies share.
    ///
    /// The test drives the real frps/frpc binaries and asserts on frpc's
    /// RUST_LOG=info output (captured to a file), with remote ports as a
    /// secondary observable:
    ///   Phase 1 (removal): reload-remove the health-checked proxy, then kill
    ///     and restore the local echo server. With the fix the health task
    ///     was cancelled at reload, so no Recover event for the removed proxy
    ///     ever appears again and the remote port stays closed. With the bug
    ///     the surviving task fires Recover after the local service recovers
    ///     and the stale config re-registers the proxy.
    ///   Phase 2 (add): reload-add a health-checked proxy, kill and restore
    ///     its local echo server. With the fix the Recover handler finds the
    ///     config and logs "Health recovery: re-registered proxy ...". With
    ///     the bug the lookup misses and it logs "no config found" instead.
    ///
    /// NOTE: the recovered remote port is NOT asserted via port probes: on
    /// the first success tick after a failure, frp-rs's health monitor sends
    /// Recover AND re-fires Close in the same tick (the `failures` counter is
    /// monotonic and the Close guard also runs on success ticks — a
    /// pre-existing Go-frp deviation outside this task's scope), so a
    /// re-registered port closes again microseconds later. The log markers
    /// prove the Recover handler found the config and sent NewProxy.
    #[tokio::test]
    async fn test_reload_health_check_with_user() {
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
        let local_h = allocate_port();
        let remote_h = allocate_port();
        let local_h2 = allocate_port();
        let remote_h2 = allocate_port();
        let token = "test-reload-token";
        // Health check floors in spawn_health_checks: interval >= 10s. One
        // full interval plus margin is the longest we must wait for a buggy
        // surviving task to fire its next Close/Recover.
        const HC_INTERVAL_SECS: u64 = 10;

        let dir = tempfile::TempDir::new().unwrap();
        let frps_config_path = dir.path().join("frps.toml");
        let frpc_config_path = dir.path().join("frpc.toml");
        let frpc_log_path = dir.path().join("frpc.log");

        // ---- Step 1: Start echo servers for the two local services ----
        let (echo_h_handle, echo_h_tx) = start_tcp_echo_server(local_h);
        let (echo_h2_handle, echo_h2_tx) = start_tcp_echo_server(local_h2);
        assert!(wait_for_port(local_h, 5), "echo H did not start");
        assert!(wait_for_port(local_h2, 5), "echo H2 did not start");

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

        // A health-checked TCP proxy block; the client runs with `user`.
        let health_proxy_block = |name: &str, local_port: u16, remote_port: u16| {
            format!(
                r#"
[[proxies]]
name = "{name}"
type = "tcp"
local_ip = "127.0.0.1"
local_port = {local_port}
remote_port = {remote_port}
health_check_type = "tcp"
health_check_interval_seconds = {HC_INTERVAL_SECS}
health_check_timeout_seconds = 3
health_check_max_failed = 1
"#,
                name = name,
                local_port = local_port,
                remote_port = remote_port,
            )
        };
        let frpc_config = |proxy_block: &str| {
            format!(
                r#"
server_addr = "127.0.0.1"
server_port = {bind_port}
user = "testuser"
auth.token = "{token}"
transport.tls.enable = false
transport.tcp_mux = false
{proxy_block}
"#,
                bind_port = bind_port,
                token = token,
                proxy_block = proxy_block,
            )
        };

        // ---- Step 3: Write initial frpc config (health-checked tcp-h) ----
        std::fs::write(
            &frpc_config_path,
            frpc_config(&health_proxy_block("tcp-h", local_h, remote_h)),
        )
        .unwrap();

        // ---- Step 4: Start frps and frpc ----
        let mut frps = Command::new(&frps_bin)
            .arg("-c")
            .arg(&frps_config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start frps");
        assert!(wait_for_port(bind_port, 10), "frps did not start");

        // frpc runs with RUST_LOG=info and its stdout/stderr captured to a
        // log file (the tracing fmt layer defaults to stdout) so the test can
        // assert on health Recover/Close markers.
        let frpc_log = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&frpc_log_path)
            .expect("create frpc log file");
        let frpc_log_stdout = frpc_log.try_clone().expect("clone frpc log file");
        let mut frpc = Command::new(&frpc_bin)
            .arg("-c")
            .arg(&frpc_config_path)
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::from(frpc_log))
            .stderr(std::process::Stdio::from(frpc_log_stdout))
            .spawn()
            .expect("failed to start frpc");

        // Wait for tcp-h to be ready and working.
        assert!(
            wait_for_port(remote_h, 15),
            "health-checked proxy tcp-h never became ready"
        );
        let echo_result = tcp_echo(remote_h, b"hello-h-before", 5);
        assert!(
            echo_result.is_ok(),
            "proxy tcp-h should work before reload: {:?}",
            echo_result.err()
        );
        assert_eq!(echo_result.unwrap(), b"hello-h-before".to_vec());
        // Let the first health tick succeed so the monitor has seen the
        // service healthy (Close only fires after a proxy was healthy once).
        tokio::time::sleep(Duration::from_secs(3)).await;

        // ---- Phase 1: reload REMOVES the health-checked proxy ----
        let log_base = log_len(&frpc_log_path);
        std::fs::write(&frpc_config_path, frpc_config("")).unwrap();
        let frpc_pid = frpc.id();
        let kill_status = Command::new("kill")
            .args(["-USR1", &frpc_pid.to_string()])
            .status()
            .expect("kill command failed");
        assert!(kill_status.success(), "kill -USR1 failed");
        assert!(
            wait_for_port_closed(remote_h, 15),
            "remote port should close after reload removed tcp-h"
        );

        // With the bug the health task survives the reload: kill the local
        // service and wait out a full health interval (Close fires), then
        // bring it back and wait out another interval (Recover fires and the
        // stale config re-registers the proxy on the server). With the fix
        // the task was cancelled at reload and no Recover is ever emitted.
        let _ = echo_h_tx.send(());
        let _ = echo_h_handle.join();
        tokio::time::sleep(Duration::from_secs(HC_INTERVAL_SECS + 5)).await;
        assert!(
            wait_for_port_closed(remote_h, 2),
            "remote port must stay closed while local service is down"
        );

        let (echo_h_handle, echo_h_tx) = start_tcp_echo_server(local_h);
        assert!(wait_for_port(local_h, 5), "echo H did not restart");
        tokio::time::sleep(Duration::from_secs(HC_INTERVAL_SECS + 5)).await;
        // Regression assert: with the bug the surviving health task fires
        // Recover for the removed proxy here; with the fix it was cancelled
        // at reload, so the wire-named Recover marker never appears.
        assert!(
            !wait_for_log_since(
                &frpc_log_path,
                log_base,
                "Health check recovered for 'testuser.tcp-h'",
                2,
            ),
            "REMOVED proxy still has a live health task — Recover fired after reload removal"
        );
        assert!(
            wait_for_port_closed(remote_h, 2),
            "REMOVED proxy remote port resurrected after recovery"
        );

        // ---- Phase 2: reload ADDS a second health-checked proxy ----
        let log_base = log_len(&frpc_log_path);
        std::fs::write(
            &frpc_config_path,
            frpc_config(&health_proxy_block("tcp-h2", local_h2, remote_h2)),
        )
        .unwrap();
        let frpc_pid = frpc.id();
        let kill_status = Command::new("kill")
            .args(["-USR1", &frpc_pid.to_string()])
            .status()
            .expect("kill command failed");
        assert!(kill_status.success(), "kill -USR1 failed");
        assert!(
            wait_for_port(remote_h2, 15),
            "added health-checked proxy tcp-h2 never became ready"
        );
        // Let the new health task see one successful check first.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Kill the local service: the monitor must fire Close and the remote
        // port must close.
        let _ = echo_h2_tx.send(());
        let _ = echo_h2_handle.join();
        assert!(
            wait_for_port_closed(remote_h2, 20),
            "remote port did not close after local service died"
        );

        // Bring the local service back: the monitor must recover and the
        // Recover handler must find the config (keyed by wire name) and send
        // NewProxy. With the bug the Recover lookup misses and the handler
        // logs "no config found" instead of re-registering.
        let (echo_h2_handle, echo_h2_tx) = start_tcp_echo_server(local_h2);
        assert!(wait_for_port(local_h2, 5), "echo H2 did not restart");
        assert!(
            wait_for_log_since(
                &frpc_log_path,
                log_base,
                "Health recovery: re-registered proxy 'testuser.tcp-h2'",
                25,
            ),
            "added health-checked proxy's Recover found no config — never re-registered after recovery"
        );

        // Cleanup
        let _ = frpc.kill();
        let _ = frps.kill();
        let _ = frpc.wait();
        let _ = frps.wait();
        stop_tcp_echo_server(echo_h_handle, echo_h_tx);
        stop_tcp_echo_server(echo_h2_handle, echo_h2_tx);
    }
}
