use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex, Once};
use std::time::Duration;
use tokio::net::{TcpListener, TcpSocket};
use tokio::task::JoinHandle;

use frp_client::service::Service as ClientService;
use frp_core::config::{ClientConfig, ProxyConfig, ServerConfig};
use frp_server::service::Service as ServerService;

static INIT_LOG: Once = Once::new();

#[allow(dead_code, clippy::unnecessary_min_or_max)]
pub fn init_tracing() {
    INIT_LOG.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init()
            .ok();
    });
}

/// Ports already handed out by this process. Parallel tests must never
/// receive the same port twice — a second test would otherwise grab the
/// port before the first test's server binds it (CI flake: client traffic
/// landing on a foreign listener → connection reset).
static USED_PORTS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Bind to a random port, return the port number.
/// Never returns a port already handed out by this process, and re-verifies
/// the port is still bindable right before returning. NOTE: the probe
/// socket must be DROPPED before the re-bind check — re-binding a port
/// that our own socket still holds always fails with EADDRINUSE (this was
/// a bug that silently routed every allocation to the random fallback, the
/// root cause of CI "echo server bind: Address already in use" flake).
pub fn allocate_port() -> u16 {
    for _ in 0..64 {
        let Some(port) = probe_port() else {
            return sandbox_fallback();
        };
        // probe_port dropped its socket: the port is free again, so a
        // re-bind now genuinely confirms availability.
        if USED_PORTS.lock().unwrap().insert(port) {
            if TcpSocket::new_v4()
                .and_then(|s| s.bind(format!("127.0.0.1:{port}").parse().unwrap()))
                .is_ok()
            {
                return port;
            }
            USED_PORTS.lock().unwrap().remove(&port);
        }
    }
    sandbox_fallback()
}

/// Bind to an ephemeral port, return the kernel-assigned number, then drop
/// the socket so the caller can bind the port itself.
fn probe_port() -> Option<u16> {
    let socket = TcpSocket::new_v4().ok()?;
    socket.bind("127.0.0.1:0".parse().unwrap()).ok()?;
    socket.local_addr().ok().map(|a| a.port())
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

/// Start a simple TCP echo server on the given port.
/// Accepts connections in a loop, spawns a task per connection
/// that copies data bidirectionally (echo).
pub fn start_echo_server(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("echo server bind");
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    })
}

/// Allocate a UDP port that is bindable and not handed out to any test in
/// this process.
///
/// Distinct from [`allocate_port`] (TCP): TCP and UDP port spaces are
/// independent, so a TCP-probed port can be held by a parallel test's UDP
/// socket. UDP-typed ports (SUDP echo servers, SUDP visitor bind ports)
/// must come from here.
#[allow(dead_code)] // used only by the sudp e2e target
pub fn allocate_udp_port() -> u16 {
    for _ in 0..64 {
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => break,
        };
        let port = match socket.local_addr() {
            Ok(a) => a.port(),
            Err(_) => break,
        };
        drop(socket);
        {
            let mut used = USED_PORTS.lock().unwrap();
            if !used.insert(port) {
                continue; // already handed out in this process — probe again
            }
            // Narrow the probe-then-drop window: confirm the port is still
            // UDP-bindable before handing it out.
            if std::net::UdpSocket::bind(format!("127.0.0.1:{port}")).is_err() {
                used.remove(&port);
                continue;
            }
        }
        return port;
    }
    sandbox_fallback()
}

/// Start a simple UDP echo server on the given port.
/// Every datagram received is sent back to its source.
#[allow(dead_code)] // used only by the sudp e2e target
pub fn start_udp_echo_server(port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let socket = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port))
            .await
            .expect("udp echo server bind");
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], src).await;
        }
    })
}

/// Start the frps server on the given port with an optional auth token.
pub async fn start_frps(port: u16, token: &str) -> JoinHandle<()> {
    let cfg = ServerConfig {
        bind_addr: "127.0.0.1".into(),
        bind_port: port,
        auth: frp_core::config::AuthServerConfig {
            method: "token".into(),
            token: token.to_string(),
            ..Default::default()
        },
        // No port restriction in e2e tests — proxy ports can be anywhere.
        // allow_port_start/end default to 0 (unrestricted), matching production.
        allow_port_start: 0,
        allow_port_end: 0,
        transport: frp_core::config::ServerTransportConfig {
            tcp_mux: Some(false),
            ..Default::default()
        },
        ..Default::default()
    };
    let service = ServerService::new(cfg, None)
        .await
        .expect("create server service");
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
#[allow(dead_code, clippy::unnecessary_min_or_max)]
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
    /// `v2` enables V2 wire protocol (defaults to V1).
    #[allow(dead_code, clippy::unnecessary_min_or_max)]
    pub async fn new(use_encryption: bool, token: &str) -> Self {
        Self::new_inner(use_encryption, token, false).await
    }

    /// Build and start the full stack with V2 protocol support.
    #[allow(dead_code, clippy::unnecessary_min_or_max)]
    pub async fn new_v2(use_encryption: bool, token: &str) -> Self {
        Self::new_inner(use_encryption, token, true).await
    }

    async fn new_inner(use_encryption: bool, token: &str, v2: bool) -> Self {
        init_tracing();
        let echo_port = allocate_port();
        let server_port = allocate_port();
        let proxy_port = allocate_port();

        // 1. Start echo server
        let echo_handle = start_echo_server(echo_port);

        // 2. Start frps
        let server_handle = start_frps(server_port, token).await;
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
            pool_count: 2,
            tcp_mux: false,
            tls_enable: false,
            v2,
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
                health_check_url: String::new(),
                health_check_interval_seconds: 0,
                health_check_timeout_seconds: 0,
                health_check_max_failed: 0,
                virtual_net: String::new(),
                advertise_subnet: String::new(),
                vnet_ip: String::new(),
                vnet_netmask: String::new(),
                vnet_mtu: 1420,
                health_check_http_headers: Vec::new(),
                proxy_protocol_version: String::new(),
                enabled: true,
                disable_assisted_addrs: false,
            }],
            ..Default::default()
        };
        let client_service = ClientService::new(client_cfg, None)
            .await
            .expect("create client service");
        let client_handle = tokio::spawn(async move {
            let _ = client_service.run().await;
        });

        // 4. Wait for proxy to be ready.
        // Use a sleep instead of wait_for_port to avoid consuming
        // a pooled work connection (which causes on-demand hang in V2).
        // The proxy listener starts synchronously after login+registration.
        tokio::time::sleep(Duration::from_secs(1)).await;

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
