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
pub fn allocate_port() -> u16 {
    let socket = TcpSocket::new_v4().expect("create socket");
    socket.bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    socket.local_addr().unwrap().port()
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
    let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
        frp_core::Error::Transport(format!("connect to {}: {}", addr, e))
    })?;

    let login = FrpMessage::Login(Login {
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
        
    });

    let mut io = IoStream::Tcp(stream);
    write_msg_v1(&mut io, &login).await?;

    match read_msg_v1(&mut io).await? {
        FrpMessage::LoginResp(resp) => {
            // Wrap in AES-128-CFB encryption (matches server post-login)
            let enc_key = encryption::derive_key(token);
            let encrypted = io.into_encrypted(enc_key);
            Ok((encrypted, resp))
        }
        other => Err(frp_core::Error::Protocol(format!(
            "expected LoginResp, got type byte {:?}",
            other.v1_type_byte()
        ))),
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

/// Handle to a running frps child process with dashboard.
/// Kills the process on drop.
pub struct FrpsHandle {
    child: Child,
    pub bind_port: u16,
    pub dashboard_port: u16,
    _config_dir: tempfile::TempDir,
}

impl FrpsHandle {
    /// Start frps with the given TOML config content.
    /// Returns handle after both bind_port and dashboard_port are accepting connections.
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

        // Try to find the frps binary
        let frps_bin = std::env::var("CARGO_BIN_EXE_frps").unwrap_or_else(|_| {
            // Fallback: look in target directory.
            // Tests run from the crate root (frp-server/), so target/ is one level up.
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
        // Extra time for dashboard routes to register
        tokio::time::sleep(Duration::from_millis(300)).await;

        Self {
            child,
            bind_port,
            dashboard_port,
            _config_dir: config_dir,
        }
    }

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
pub async fn wait_tcp_port(port: u16, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("port {} not ready after {:?}", port, timeout))
}
