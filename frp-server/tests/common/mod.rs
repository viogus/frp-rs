use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::task::JoinHandle;

use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{FrpMessage, Login, LoginResp};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_server::service::Service;

/// Ports already handed out by this process. Parallel tests must never
/// receive the same port twice — the probe-then-drop window in
/// allocate_port would otherwise let a second test grab the port before
/// the first test's server binds it (CI flake: a tcpmux CONNECT landing on
/// a foreign listener → connection reset).
static USED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// RAII guard holding an exclusive flock(2) on the shared port-allocation
/// lock file. Every integration-test **bin** is a separate process, so each
/// compiles its own copy of `common` with its own `USED_PORTS` set; the
/// kernel-level flock is the only thing that serializes the probe-then-drop
/// window **across** those processes. The lock is held for the duration of
/// one `allocate_port` call, so two bins can never both confirm the same
/// ephemeral port is free and hand it out at once.
#[cfg(unix)]
struct PortRequestGuard {
    file: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl Drop for PortRequestGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: `fd` is a live OwnedFd held by self until this Drop ends;
        // flock(LOCK_UN) is always safe on a valid fd. The OwnedFd's own Drop
        // then closes the descriptor after we release the lock.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Acquire the cross-process port-allocation lock (blocking). The lock file
/// is kept in the OS temp dir so every test-bin process resolves the same
/// path; the file is never deleted (it is a persistent flock anchor).
#[cfg(unix)]
fn acquire_port_request_lock() -> PortRequestGuard {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    let path = std::env::temp_dir().join("frp-test-port-alloc.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .expect("open shared port-alloc lock file");
    // Transfer the raw fd ownership into an OwnedFd; it (not the File) is what
    // the guard holds, so the descriptor stays live for the whole lock.
    // SAFETY: `fd` is a valid, owned descriptor freshly produced by open(2)
    // above; transferring it into OwnedFd::from_raw_fd is the canonical idiom.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(file.into_raw_fd()) };
    // Exclusive, blocking: concurrent bins queue here so only one probes-and-
    // confirms at a time. Failures from environmental fd exhaustion abort the
    // test loudly rather than silently racing for ports.
    let ret = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(ret, 0, "flock on shared port-alloc lock file failed: errno");
    PortRequestGuard { file: fd }
}

/// Non-unix fallback: a no-op guard so `allocate_port` compiles everywhere
/// (flock(2) is unix-only; the target platforms are macOS + Linux CI). Keeps
/// the `let _lock = acquire_port_request_lock();` call site cfg-free.
#[cfg(not(unix))]
struct PortRequestGuard;

#[cfg(not(unix))]
fn acquire_port_request_lock() -> PortRequestGuard {
    PortRequestGuard
}

/// Bind to a random port, return the port number, then drop the socket.
/// Never returns a port already handed out by this process, and re-verifies
/// the port is still bindable right before returning (narrows the
/// probe-then-drop window). Falls back to a random ephemeral port on
/// sandboxed environments where explicit binding is disallowed.
pub fn allocate_port() -> u16 {
    // Serialize the whole probe→confirm→hand-out across processes so the
    // probe-then-drop window cannot be interleaved by another test bin.
    let _lock = acquire_port_request_lock();
    for _ in 0..64 {
        let Some(port) = probe_ephemeral_port() else {
            return sandbox_fallback();
        };
        {
            let mut used = USED_PORTS.lock().unwrap();
            if !used.insert(port) {
                continue; // already handed out in this process — probe again
            }
            // Narrow the probe-then-drop window: confirm the port is still
            // free before handing it out.
            if !port_is_free(port) {
                used.remove(&port);
                continue;
            }
        }
        return port;
    }
    sandbox_fallback()
}

/// Bind to an ephemeral port and return the kernel-assigned number.
fn probe_ephemeral_port() -> Option<u16> {
    let socket = TcpSocket::new_v4().ok()?;
    socket.bind("127.0.0.1:0".parse().unwrap()).ok()?;
    socket.local_addr().ok().map(|a| a.port())
}

/// Re-bind `port` to confirm it is still available (the probe socket was
/// dropped, so a concurrent test could have taken it in between).
fn port_is_free(port: u16) -> bool {
    TcpSocket::new_v4()
        .and_then(|s| s.bind(format!("127.0.0.1:{port}").parse().unwrap()))
        .is_ok()
}

/// Sandbox fallback: return an ephemeral port (49152-65535 range).
/// Tests that need the port will bind to 0 and read the actual port.
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

/// Start the frp server on the given config, returning the join handle.
/// The server is ready to accept connections after a short sleep.
/// Note: tcp_mux is disabled by default for tests (raw V1 frames, no yamux).
#[allow(dead_code)]
pub async fn start_test_server(mut cfg: ServerConfig) -> (JoinHandle<()>, u16) {
    cfg.transport.tcp_mux = Some(false); // test clients use raw V1 frames
    let port = cfg.bind_port;
    let service = Service::new(cfg, None).await.expect("create service");
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    // Wait until the server actually accepts connections (poll instead of a
    // fixed sleep: on slow CI the old 150ms sleep was not always enough).
    // The probe connection is accepted and closed by the server harmlessly.
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        ready,
        "test server did not start listening on {addr} in time"
    );
    (handle, port)
}

/// Fully parametrized login: like `raw_login` plus the client identity
/// (`user`, `metas`) and `pool_count` Go frpc sends. Used by the plugin
/// tests to assert the `user` object and flat Login fields in payloads.
pub async fn raw_login_full(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
    user: Option<String>,
    metas: Option<std::collections::HashMap<String, String>>,
    pool_count: Option<i32>,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to {}: {}", addr, e).into()))?;

    let login = FrpMessage::Login(Box::new(Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user,
        run_id: None,
        client_id: None,
        pool_count,
        timestamp,
        privilege_key,
        metas,
        client_spec: None,
        multiplexer: None,
    }));

    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await?;

    match read_msg_v1(&mut io).await? {
        FrpMessage::LoginResp(resp) => {
            // Wrap in AES-128-CFB encryption (matches server post-login)
            let enc_key = encryption::derive_key(token);
            let mut encrypted = io.into_encrypted(enc_key)?;

            // Drain initial ReqWorkConn messages sent by server after LoginResp.
            // Server sends pool_count ReqWorkConn immediately after wrapping
            // in CipherStream (matching Go frps ctl.Start()).
            let pool_count = if let FrpMessage::Login(ref l) = login {
                l.pool_count.unwrap_or(1).max(1) as usize
            } else {
                1
            };
            for _ in 0..pool_count {
                match read_msg_v1(&mut encrypted).await {
                    Ok(FrpMessage::ReqWorkConn(_)) => continue,
                    Ok(_) => break,
                    Err(_) => break,
                }
            }
            Ok((encrypted, resp))
        }
        other => Err(frp_core::Error::Protocol(
            format!(
                "expected LoginResp, got type byte {:?}",
                other.v1_type_byte()
            )
            .into(),
        )),
    }
}

/// Connect to the server and send a Login message.
/// Returns the encrypted IoStream (AES-128-CFB, matching server post-login)
/// and the LoginResp. Caller can continue sending/receiving messages.
/// `token` is the shared auth secret (empty = no auth); used for key derivation.
pub async fn raw_login(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    raw_login_full(addr, privilege_key, timestamp, token, None, None, Some(1)).await
}

/// Log in with the default test token plus a client identity (user + metas),
/// generating a fresh timestamp and privilege_key (like login_with_test_token).
#[allow(dead_code)]
pub async fn login_with_identity(
    addr: SocketAddr,
    user: &str,
    metas: std::collections::HashMap<String, String>,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    raw_login_full(
        addr,
        Some(key),
        Some(ts),
        TEST_TOKEN,
        Some(user.into()),
        Some(metas),
        Some(1),
    )
    .await
}

/// Like raw_login but discards the stream, returning only the LoginResp.
#[allow(dead_code)]
pub async fn raw_login_resp(
    addr: SocketAddr,
    privilege_key: Option<String>,
    timestamp: Option<i64>,
    token: &str,
) -> Result<LoginResp, frp_core::Error> {
    let (_, resp) = raw_login(addr, privilege_key, timestamp, token).await?;
    Ok(resp)
}

/// Default test token used for authentication in integration tests.
#[allow(dead_code)]
pub const TEST_TOKEN: &str = "test-token";

/// Create a default `AuthServerConfig` with a test token for integration tests.
#[allow(dead_code)]
pub fn test_auth_cfg() -> frp_core::config::AuthServerConfig {
    frp_core::config::AuthServerConfig {
        method: "token".into(),
        token: TEST_TOKEN.into(),
        ..Default::default()
    }
}

/// Convenience: log in with the default test token.
/// Generates a fresh timestamp and privilege_key on every call.
#[allow(dead_code)]
pub async fn login_with_test_token(
    addr: SocketAddr,
) -> Result<(IoStream, LoginResp), frp_core::Error> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let key = frp_core::auth::generate_token(TEST_TOKEN, ts);
    raw_login(addr, Some(key), Some(ts), TEST_TOKEN).await
}

/// Handle to a running frps child process with dashboard.
/// Kills the process on drop.
#[allow(dead_code)]
pub struct FrpsHandle {
    child: Child,
    #[allow(dead_code)]
    pub bind_port: u16,
    pub dashboard_port: u16,
    _config_dir: tempfile::TempDir,
}

impl FrpsHandle {
    /// Start frps with the given TOML config content.
    /// Returns handle after both bind_port and dashboard_port are accepting connections.
    #[allow(dead_code)]
    pub async fn start(config_content: &str) -> Self {
        let config_dir = tempfile::TempDir::new().unwrap();
        let config_path = config_dir.path().join("frps.toml");
        std::fs::write(&config_path, config_content).unwrap();

        // Extract ports from config
        let bind_port = config_content
            .lines()
            .find(|l| l.trim().starts_with("bind_port"))
            .and_then(|l| l.split('=').nth(1))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let dashboard_port = config_content
            .lines()
            .find(|l| l.trim().starts_with("port") && l.contains("web_server"))
            .or_else(|| {
                // port might be in [web_server] section, scan after web_server header
                let mut in_web = false;
                config_content.lines().find(|l| {
                    if l.trim() == "[web_server]" {
                        in_web = true;
                        return false;
                    }
                    if in_web && l.trim().starts_with("port") {
                        return true;
                    }
                    false
                })
            })
            .and_then(|l| l.split('=').nth(1))
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Resolve frps binary. Order of precedence:
        //   1. FRPS_BIN env var (pre-built release binary)
        //   2. CARGO_BIN_EXE_frps (set by cargo when frps is a dependency)
        //   3. ../frps in workspace root (downloaded release)
        //   4. ../target/{profile}/frps (built from source)
        let frps_bin = std::env::var("FRPS_BIN")
            .or_else(|_| std::env::var("CARGO_BIN_EXE_frps"))
            .or_else(|_| {
                let local = "../frps";
                if std::path::Path::new(local).is_file() {
                    Ok(local.to_string())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            })
            .unwrap_or_else(|_| {
                let profile = if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                };
                format!("../target/{}/frps", profile)
            });

        let child = Command::new(&frps_bin)
            .arg("-c")
            .arg(&config_path)
            .env("RUST_LOG", "error")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start frps");

        // Wait for ports
        if bind_port > 0 {
            wait_tcp_port(bind_port, Duration::from_secs(15))
                .await
                .expect("frps bind_port not ready");
        }
        if dashboard_port > 0 {
            wait_tcp_port(dashboard_port, Duration::from_secs(15))
                .await
                .expect("frps dashboard_port not ready");
        }
        // Poll /healthz until the dashboard HTTP server is actually serving
        // requests (not just accepting TCP connections). Without this, CI
        // can hit IncompleteMessage when axum hasn't started processing yet.
        if dashboard_port > 0 {
            wait_http_ok(
                &format!("http://127.0.0.1:{}/healthz", dashboard_port),
                Duration::from_secs(15),
            )
            .await
            .expect("frps dashboard not healthy");
        }

        Self {
            child,
            bind_port,
            dashboard_port,
            _config_dir: config_dir,
        }
    }

    #[allow(dead_code)]
    pub fn dashboard_url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.dashboard_port, path)
    }
}

impl Drop for FrpsHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Wait for a TCP port to accept connections.
#[allow(dead_code)]
pub async fn wait_tcp_port(port: u16, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("port {} not ready after {:?}", port, timeout))
}

/// Poll a URL until it returns HTTP 200 OK (or timeout).
/// Ensures the HTTP server is actually processing requests, not just
/// accepting TCP connections. Uses a throwaway client to avoid pool
/// interference with test clients.
#[allow(dead_code)]
pub async fn wait_http_ok(url: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("failed to build health-check client: {e}"))?;
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                // Server is up but returning an error status — wait for it
                // to become healthy (e.g. readiness probe during startup).
                let _ = resp.bytes().await;
            }
            Err(_) => {
                // Server not ready yet (connection refused, incomplete, etc.)
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("{url} not healthy after {timeout:?}"))
}
