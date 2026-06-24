use std::net::SocketAddr;
use std::sync::Once;
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::JoinHandle;

use frp_core::config::{ClientConfig, ProxyConfig, ServerConfig};
use frp_client::service::Service as ClientService;
use frp_server::service::Service as ServerService;

static INIT_LOG: Once = Once::new();

#[allow(dead_code)]
pub fn init_tracing() {
    INIT_LOG.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init()
            .ok();
    });
}

/// Bind to a random port, return the port number.
pub fn allocate_port() -> u16 {
    let socket = TcpSocket::new_v4().expect("create socket");
    socket.bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    socket.local_addr().unwrap().port()
}

/// Start a simple TCP echo server on the given port.
/// Accepts connections in a loop, spawns a task per connection
/// that copies data bidirectionally (echo).
pub fn start_echo_server(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("echo server bind");
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let (mut r, mut w) = stream.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    });
                }
                Err(_) => break,
            }
        }
    })
}

/// Start the frps server on the given port with an optional auth token.
pub fn start_frps(port: u16, token: &str) -> JoinHandle<()> {
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: frp_core::config::AuthServerConfig {
            method: if token.is_empty() {
                "token".into()
            } else {
                "token".into()
            },
            token: token.to_string(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            oidc_token_endpoint: String::new(),
        },
        allow_port_start: port.saturating_sub(50),
        allow_port_end: port.saturating_add(50).min(u16::MAX),
        ..Default::default()
    };
    let service = ServerService::new(cfg);
    tokio::spawn(async move {
        let _ = service.run().await;
    })
}

/// Poll `TcpStream::connect` until it succeeds or timeout.
/// The connection is held open briefly to avoid tripping the server's
/// peek_connection_type with an empty connect-then-drop.
pub async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> Result<(), ()> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
            // Hold the connection briefly so the server's peek sees data,
            // then shut down gracefully.
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(stream);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(())
}

/// Full integration test harness: echo server + frps + frpc.
/// On drop, all background tasks are aborted.
#[allow(dead_code)]
pub struct TestHarness {
    pub server_port: u16,
    pub proxy_port: u16,
    pub echo_port: u16,
    _echo_handle: JoinHandle<()>,
    _server_handle: JoinHandle<()>,
    _client_handle: JoinHandle<()>,
}

impl TestHarness {
    /// Build and start the full stack.
    ///
    /// `use_encryption` enables AES-128-CFB on the proxy.
    /// `token` is the shared auth token (empty = no auth).
    pub async fn new(use_encryption: bool, token: &str) -> Self {
        init_tracing();
        let echo_port = allocate_port();
        let server_port = allocate_port();
        let proxy_port = allocate_port();

        // 1. Start echo server
        let echo_handle = start_echo_server(echo_port);

        // 2. Start frps
        let server_handle = start_frps(server_port, token);
        // Wait for server to start accepting connections
        let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
        wait_for_port(server_addr, Duration::from_secs(5))
            .await
            .expect("server port did not become ready within 5s");

        // 3. Start frpc
        let client_cfg = ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.to_string(),
            login_fail_exit: false,
            pool_count: 1,
            proxies: vec![ProxyConfig {
                name: "e2e-test".into(),
                proxy_type: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: echo_port,
                remote_port: proxy_port,
                use_encryption,
                use_compression: false,
                sk: String::new(),
                plugin: None,
                custom_domains: vec![],
                subdomain: String::new(),
                http_user: String::new(),
                http_pwd: String::new(),
                http_password: String::new(),
                locations: vec![],
                host_header_rewrite: String::new(),
                headers: std::collections::HashMap::new(),
                response_headers: std::collections::HashMap::new(),
                route_by_http_user: String::new(),
                allow_users: vec![],
                bandwidth_limit: String::new(),
                bandwidth_limit_mode: String::new(),
                annotations: std::collections::HashMap::new(),
                metas: std::collections::HashMap::new(),
                multiplexer: String::new(),
                group: String::new(),
                group_key: String::new(),
                health_check_type: String::new(),
                health_check_interval_seconds: 0,
                health_check_timeout_seconds: 0,
                health_check_max_failed: 0,
            }],
            ..Default::default()
        };
        let client_service = ClientService::new(client_cfg);
        let client_handle = tokio::spawn(async move {
            let _ = client_service.run().await;
        });

        // 4. Wait for proxy port to become connectable
        let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();
        wait_for_port(proxy_addr, Duration::from_secs(10))
            .await
            .expect("proxy port did not become ready within 10s");

        TestHarness {
            server_port,
            proxy_port,
            echo_port,
            _echo_handle: echo_handle,
            _server_handle: server_handle,
            _client_handle: client_handle,
        }
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        self._echo_handle.abort();
        self._server_handle.abort();
        self._client_handle.abort();
    }
}
