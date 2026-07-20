use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::task::JoinHandle;

use frp_core::config::ServerConfig;
use frp_core::encryption;
use frp_core::msg::{FrpMessage, Login, LoginResp};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_server::service::Service;

/// Bind to a random port, return the port number, then drop the socket.
/// Small race window between drop and reuse, but negligible on localhost.
/// Falls back to a random ephemeral port on sandboxed environments where
/// explicit binding is disallowed.
pub fn allocate_port() -> u16 {
    if let Ok(socket) = TcpSocket::new_v4() {
        if socket.bind("127.0.0.1:0".parse().unwrap()).is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.port();
            }
        }
    }
    // Sandbox fallback: return an ephemeral port (49152-65535 range).
    // Tests that need the port will bind to 0 and read the actual port.
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_usize(std::process::id() as usize);
    49152 + (h.finish() % 16384) as u16
}

/// Start the frp server on the given config, returning the join handle.
/// The server is ready to accept connections after a short sleep.
/// Note: tcp_mux is disabled by default for tests (raw V1 frames, no yamux).
#[allow(dead_code)]
pub async fn start_test_server(mut cfg: ServerConfig) -> (JoinHandle<()>, u16) {
    cfg.transport.tcp_mux = false; // test clients use raw V1 frames
    let port = cfg.bind_port;
    let service = Service::new(cfg, None).await.expect("create service");
    let handle = tokio::spawn(async move {
        let _ = service.run().await;
    });
    // Give the server time to bind and start accepting
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    (handle, port)
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
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| frp_core::Error::Transport(format!("connect to {}: {}", addr, e).into()))?;

    let login = FrpMessage::Login(Box::new(Login {
        version: Some(frp_core::VERSION.into()),
        hostname: Some("test-host".into()),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp,
        privilege_key,
        metas: None,
        client_spec: None,
        multiplexer: None,
    }));

    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await?;

    match read_msg_v1(&mut io).await? {
        FrpMessage::LoginResp(resp) => {
            // Wrap in AES-128-CFB encryption (matches server post-login)
            let enc_key = encryption::derive_key(token);
            let mut encrypted = io.into_encrypted(enc_key);

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
                if std::path::Path::new(local).exists() {
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
