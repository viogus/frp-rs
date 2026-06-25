use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};

use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::ClientConfig;
use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::mux::YamuxSession;
use frp_core::transport::{TransportProtocol, DialOptions, dial_server, IoStream};

use crate::plugin::{self, PluginHandle};
use crate::proxy;
use crate::control::ControlConnection;

/// Proxy config needed at runtime for work connections.
#[derive(Clone)]
struct ProxyRuntimeInfo {
    local_addr: String,
    use_encryption: bool,
    use_compression: bool,
    /// Bandwidth limit in bytes/sec (0 = unlimited).
    bandwidth_limit: u64,
    /// Bandwidth limit mode: "client", "server", or "both".
    bandwidth_limit_mode: String,
}

/// The main frpc service.
pub struct Service {
    cfg: ClientConfig,
    auth_cfg: Arc<AuthConfig>,
    encryption_key: [u8; 16],
    /// Map proxy_name -> runtime info for looking up where to connect
    proxy_info_map: HashMap<String, ProxyRuntimeInfo>,
    /// Plugin handles kept alive for the lifetime of the service.
    _plugin_handles: Vec<PluginHandle>,
}

impl Service {
    pub async fn new(cfg: ClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let auth_cfg = AuthConfig {
            method: AuthMethod::Token,
            token: cfg.token.clone(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            additional_data: None,
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);

        // Start plugins for proxies that have them configured.
        let mut plugin_handles = Vec::new();
        let mut plugin_addrs: HashMap<String, String> = HashMap::new();
        for p in &cfg.proxies {
            if let Some(ref plugin_cfg) = p.plugin {
                if plugin_cfg.plugin_type == "http_proxy" {
                    match plugin::start_http_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("http_proxy plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start http_proxy plugin for '{}': {}", p.name, e);
                        }
                    }
                } else {
                    warn!("Unknown plugin type '{}' for proxy '{}'", plugin_cfg.plugin_type, p.name);
                }
            }
        }

        let mut proxy_info_map: HashMap<String, ProxyRuntimeInfo> = HashMap::new();
        for p in &cfg.proxies {
            if proxy_info_map.contains_key(&p.name) {
                warn!("Duplicate proxy name '{}' — only the first entry will be used", p.name);
                continue;
            }
            let bw_limit = frp_core::config::parse_bandwidth_limit(&p.bandwidth_limit).unwrap_or(0);
            // Use plugin address if available, otherwise use configured local_ip:local_port
            let local_addr = plugin_addrs
                .get(&p.name)
                .cloned()
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            proxy_info_map.insert(p.name.clone(), ProxyRuntimeInfo {
                local_addr,
                use_encryption: p.use_encryption,
                use_compression: p.use_compression,
                bandwidth_limit: bw_limit,
                bandwidth_limit_mode: p.bandwidth_limit_mode.clone(),
            });
        }

        Ok(Self {
            cfg,
            auth_cfg: Arc::new(auth_cfg),
            encryption_key: enc_key,
            proxy_info_map,
            _plugin_handles: plugin_handles,
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, self.cfg.server_addr, self.cfg.server_port
        );

        let protocol: TransportProtocol = match self.cfg.transport_protocol.parse() {
            Ok(p) => p,
            Err(_) => {
                warn!("Unknown transport protocol '{}', falling back to tcp", self.cfg.transport_protocol);
                TransportProtocol::Tcp
            }
        };
        let pool_count = self.cfg.pool_count.max(0);
        let proxies = self.cfg.proxies.clone();

        if proxies.is_empty() {
            warn!("No proxies configured");
        }

        // Channel for health checks to signal unhealthy proxies.
        // Health checks send the proxy name; the control loop sends CloseProxy to the server.
        let (health_tx, mut health_rx) = mpsc::unbounded_channel::<String>();

        // Spawn health checks once, outside reconnect loop (they are per-proxy, not per-session)
        for p in &proxies {
            let hc_type = p.health_check_type.clone();
            if hc_type.is_empty() {
                continue;
            }
            if hc_type != "tcp" && hc_type != "http" {
                warn!("Health check type '{}' not yet supported for '{}'", hc_type, p.name);
                continue;
            }
            let la = self.proxy_info_map
                .get(&p.name)
                .map(|info| info.local_addr.clone())
                .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
            let pn = p.name.clone();
            let interval = std::time::Duration::from_secs(
                p.health_check_interval_seconds.max(10)
            );
            let timeout = std::time::Duration::from_secs(
                p.health_check_timeout_seconds.max(3)
            );
            let max_failed = p.health_check_max_failed.max(1);
            let tx = health_tx.clone();
            let hc_url = if hc_type == "http" { p.health_check_url.clone() } else { String::new() };
            tokio::spawn(async move {
                run_health_check(pn, la, hc_type, hc_url, interval, timeout, max_failed, tx).await;
            });
        }

        // Main session loop with reconnection
        let mut did_login_once = false;
        loop {
            let mut ctl = ControlConnection::new(
                self.cfg.server_addr.clone(),
                self.cfg.server_port,
                self.auth_cfg.clone(),
                protocol.clone(),
                pool_count,
                self.cfg.user.clone(),
                self.cfg.client_id.clone(),
                self.cfg.tls_enable,
                self.cfg.tls_server_name.clone(),
                if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                self.cfg.tcp_mux,
            );

            let (mut control_stream, run_id, yamux_session) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
                    // After login, wrap control stream in AES-128-CFB encryption.
                    // Go frps v0.69.1 always encrypts the control connection for V1.
                    let (stream, run_id, yamux) = r;
                    let enc_key = encryption::derive_key(&self.auth_cfg.token);
                    (stream.into_encrypted(enc_key), run_id, yamux)
                }
                Err(e) => {
                    warn!("Login failed: {}", e);
                    if self.cfg.login_fail_exit && !did_login_once {
                        return Err(e.into());
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            let yamux = yamux_session.map(|s| std::sync::Arc::new(s));
            info!("Logged in. run_id: {}", run_id);

            // Register proxies using IoStream directly (supports TCP and TLS)
            for p in &proxies {
                let local_addr = self.proxy_info_map
                    .get(&p.name)
                    .map(|info| info.local_addr.clone())
                    .unwrap_or_else(|| format!("{}:{}", p.local_ip, p.local_port));
                match ctl.register_proxy(p, &local_addr, &mut control_stream).await {
                    Ok(resp) => {
                        info!("Proxy '{}' registered on remote port {:?}", p.name, resp.remote_addr);
                    }
                    Err(e) => {
                        warn!("Failed to register proxy '{}': {}", p.name, e);
                    }
                }
            }

            // Split control stream for reading and writing
            let (mut reader, raw_writer) = control_stream.into_split();
            let writer = Arc::new(Mutex::new(raw_writer));

            // Spawn initial pool work connections
            let auth_token = self.auth_cfg.token.clone();
            for i in 0..pool_count {
                spawn_work_conn(
                    &self.cfg.server_addr,
                    self.cfg.server_port,
                    &protocol,
                    &run_id,
                    &self.proxy_info_map,
                    self.encryption_key,
                    i,
                    auth_token.clone(),
                    self.cfg.tls_enable,
                    self.cfg.tls_server_name.clone(),
                    if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                    yamux.clone(),
                );
            }

            // Spawn STCP/XTCP visitor listeners
            for v in &self.cfg.visitors {
                if v.bind_port == 0 {
                    continue;
                }
                let sa = self.cfg.server_addr.clone();
                let sp = self.cfg.server_port;
                let pt = protocol.clone();
                let server_name = v.server_name.clone();
                let secret_key = v.secret_key.clone();
                let bind_addr = format!("{}:{}", v.bind_addr, v.bind_port);
                let use_enc = v.use_encryption;
                let use_comp = v.use_compression;
                let name = v.name.clone();
                let tls_enable = self.cfg.tls_enable;
                let tls_server_name = self.cfg.tls_server_name.clone();
                let tls_ca_file = if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) };
                tokio::spawn(async move {
                    run_visitor_listener(sa, sp, pt, server_name, secret_key, bind_addr, use_enc, use_comp, name,
                        tls_enable, tls_server_name, tls_ca_file).await;
                });
            }

            // Bind local UDP sockets for UDP proxies and spawn sender tasks
            // (UDP traffic flows over the control connection, Go frp v0.69.1 compat)
            let mut udp_sockets: HashMap<String, Arc<UdpSocket>> = HashMap::new();
            // Per-proxy encryption config: keyed by local_addr and proxy name
            let mut udp_enc_cfg: HashMap<String, (bool, bool)> = HashMap::new();
            for p in &proxies {
                if p.proxy_type == "udp" {
                    let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                    let socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!("UDP proxy '{}': bind failed: {}", p.name, e);
                            continue;
                        }
                    };
                    // Connect to local UDP service for send/recv
                    if let Err(e) = socket.connect(&local_addr).await {
                        warn!("UDP proxy '{}': connect to local {} failed: {}", p.name, local_addr, e);
                        continue;
                    }
                    // Map by local_str (matches UDPPacket.local_addr from server) and by name
                    udp_sockets.insert(local_addr.clone(), socket.clone());
                    udp_sockets.insert(p.name.clone(), socket.clone());
                    // Store encryption config for both lookup keys
                    let enc_cfg = (p.use_encryption, p.use_compression);
                    udp_enc_cfg.insert(local_addr.clone(), enc_cfg);
                    udp_enc_cfg.insert(p.name.clone(), enc_cfg);

                    // Spawn task: read from local UDP → send UDPPacket to server
                    let sock = socket;
                    let w = writer.clone();
                    let pn = p.name.clone();
                    let la = local_addr.clone();
                    let use_enc = p.use_encryption;
                    let use_comp = p.use_compression;
                    let enc_key = self.encryption_key;
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        loop {
                            match sock.recv_from(&mut buf).await {
                                Ok((n, src)) => {
                                    let mut payload = buf[..n].to_vec();
                                    // Encrypt/compress on the client→server path
                                    // (server decrypts before forwarding to remote)
                                    if use_comp {
                                        if let Ok(compressed) = encryption::compress(&payload) {
                                            payload = compressed;
                                        }
                                    }
                                    if use_enc {
                                        if let Ok(encrypted) = encryption::encrypt(&payload, &enc_key) {
                                            payload = encrypted;
                                        }
                                    }
                                    let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                                        content: payload,
                                        local_addr: la.clone(),
                                        remote_addr: src.to_string(),
                                    });
                                    let mut guard = w.lock().await;
                                    if let Err(e) = write_msg_v1(&mut *guard, &pkt).await {
                                        debug!("UDP '{}' send to server failed: {}", pn, e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    debug!("UDP '{}' recv from local failed: {}", pn, e);
                                    break;
                                }
                            }
                        }
                    });
                    let enc_label = if use_enc { "encrypted" } else { "plain" };
                    info!("UDP proxy '{}' bridging to {} ({})", p.name, local_addr, enc_label);
                }
            }

            // --- Message loop ---
            let mut ping_interval = interval(Duration::from_secs(30));

            loop {
                tokio::select! {
                    msg = read_msg_v1(&mut reader) => {
                        match msg {
                            Ok(FrpMessage::ReqWorkConn(_)) => {
                                debug!("Received ReqWorkConn, creating work connection");
                                spawn_work_conn(
                                    &self.cfg.server_addr,
                                    self.cfg.server_port,
                                    &protocol,
                                    &run_id,
                                    &self.proxy_info_map,
                                    self.encryption_key,
                                    -1, // on-demand, not pool
                                    auth_token.clone(),
                                    self.cfg.tls_enable,
                                    self.cfg.tls_server_name.clone(),
                                    if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) },
                                    yamux.clone(),
                                );
                            }
                            Ok(FrpMessage::Pong(_)) => {
                                debug!("Pong received");
                            }
                            Ok(FrpMessage::UDPPacket(up)) => {
                                // Forward to local UDP socket (Go frp v0.69.1 compat).
                                // Use local_addr to find the matching proxy; fall back to first socket.
                                let sock = udp_sockets.get(&up.local_addr)
                                    .or_else(|| udp_sockets.values().next())
                                    .cloned();
                                // Decrypt/decompress if the proxy requires it
                                let content_len = up.content.len();
                                let mut payload = up.content;
                                if let Some(&(use_enc, use_comp)) = udp_enc_cfg.get(&up.local_addr) {
                                    if use_enc {
                                        if let Ok(decrypted) = encryption::decrypt(&payload, &self.encryption_key) {
                                            payload = decrypted;
                                        }
                                    }
                                    if use_comp {
                                        if let Ok(decompressed) = encryption::decompress(&payload) {
                                            payload = decompressed;
                                        }
                                    }
                                }
                                if let Some(sock) = sock {
                                    let content = payload;
                                    tokio::spawn(async move {
                                        let _ = sock.send(&content).await;
                                    });
                                } else {
                                    warn!("No UDP socket for proxy, dropping {} bytes", content_len);
                                }
                            }
                            Ok(FrpMessage::CloseProxy(cp)) => {
                                info!("Server closed proxy: {}", cp.proxy_name);
                            }
                            Ok(FrpMessage::CloseProxyResp(cpr)) => {
                                info!("Server confirmed proxy close: {}", cpr.proxy_name);
                            }
                            Ok(FrpMessage::Error(err)) => {
                                warn!("Server error: {}", err.error);
                            }
                            Ok(FrpMessage::NewProxyResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Proxy registration error: {}", err);
                                }
                            }
                            Ok(_) => {
                                // Other messages are ignored
                            }
                            Err(e) => {
                                warn!("Control read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }

                    _ = ping_interval.tick() => {
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let ping_auth = AuthConfig {
                            method: AuthMethod::Token,
                            token: auth_token.clone(),
                            oidc_issuer: String::new(),
                            oidc_audience: String::new(),
                            additional_data: None,
                        };
                        let ping = FrpMessage::Ping(msg::Ping {
                            privilege_key: ping_auth.generate_login_key(ts),
                            timestamp: Some(ts),
                        });
                        if let Err(e) = write_msg_v1(&mut *writer.lock().await, &ping).await {
                            warn!("Ping failed: {}. Reconnecting...", e);
                            break;
                        }
                        debug!("Ping sent");
                    }

                    Some(proxy_name) = health_rx.recv() => {
                        info!("Health check sending CloseProxy for unhealthy proxy: {}", proxy_name);
                        let close = FrpMessage::CloseProxy(msg::CloseProxy {
                            proxy_name: proxy_name.clone(),
                        });
                        if let Err(e) = write_msg_v1(&mut *writer.lock().await, &close).await {
                            warn!("Failed to send CloseProxy for {}: {}", proxy_name, e);
                        }
                    }
                }
            }

            // Reconnect delay (login_fail_exit only applies to initial login, not session drops)
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

// ---------------------------------------------------------------
// Work connection management
// ---------------------------------------------------------------

/// Spawn a single work connection task.
///
/// The task:
/// 1. Under TcpMux: opens a yamux stream on the shared session
///    Without TcpMux: dials the server via TCP/TLS/WS
/// 2. Without TcpMux: sends NewWorkConn (with run_id + auth)
/// 3. Reads StartWorkConn from the server
/// 4. Connects to the local service
/// 5. Bridges data bidirectionally
///
/// `pool_id` is for logging only (< 0 means on-demand).
fn spawn_work_conn(
    server_addr: &str,
    server_port: u16,
    protocol: &TransportProtocol,
    run_id: &str,
    proxy_info_map: &HashMap<String, ProxyRuntimeInfo>,
    enc_key: [u8; 16],
    pool_id: i32,
    auth_token: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    yamux: Option<std::sync::Arc<YamuxSession>>,
) {
    let server_addr = server_addr.to_string();
    let run_id = run_id.to_string();
    let protocol = protocol.clone();
    let proxy_info_map = proxy_info_map.clone();
    let tls_server_name = tls_server_name.clone();

    tokio::spawn(async move {
        let label = if pool_id >= 0 {
            format!("pool-{}", pool_id)
        } else {
            "on-demand".to_string()
        };

        // Acquire the underlying transport stream.
        // Under TcpMux: open a yamux stream instead of dialing new TCP.
        let mut work = if let Some(ref yamux) = yamux {
            match yamux.open_stream().await {
                Some(stream) => {
                    debug!("Work conn {} opened yamux stream", label);
                    IoStream::Yamux(stream)
                }
                None => {
                    warn!("Work conn {}: yamux open stream failed, session closed?", label);
                    return;
                }
            }
        } else {
            debug!("Work conn {} dialing server", label);
            let opts = DialOptions {
                server_addr: server_addr.clone(),
                server_port,
                protocol: protocol.clone(),
                tls_enable,
                tls_server_name: tls_server_name.clone(),
                tls_ca_file: tls_ca_file.clone(),
                ..Default::default()
            };
            match dial_server(&opts).await {
                Ok(io) => io,
                Err(e) => {
                    warn!("Work conn {} dial failed: {}", label, e);
                    return;
                }
            }
        };

        // Send NewWorkConn — required for both yamux and raw transports.
        // Go frps needs the run_id and auth to associate the stream.
        {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let auth_cfg = frp_core::auth::AuthConfig {
                method: frp_core::auth::AuthMethod::Token,
                token: auth_token.clone(),
                oidc_issuer: String::new(),
                oidc_audience: String::new(),
                additional_data: None,
            };
            let privilege_key = auth_cfg.generate_login_key(timestamp);
            let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: Some(timestamp),
                privilege_key,
            });
            if let Err(e) = work.write_v1_frame(&nwc).await {
                warn!("Work conn {} failed to send NewWorkConn: {}", label, e);
                return;
            }
            debug!("Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);
        }

        // Read StartWorkConn
        match work.read_v1_frame().await {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                let proxy_name = &swc.proxy_name;
                info!("Work conn {} assigned to proxy '{}'", label, proxy_name);

                // Look up the proxy runtime info
                let info = match proxy_info_map.get(proxy_name) {
                    Some(info) => info,
                    None => {
                        warn!("Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                // Connect to local service
                match proxy::connect_local(&info.local_addr).await {
                    Ok(local) => {
                        let enc = if info.use_encryption { Some(&enc_key) } else { None };
                        proxy::bridge_streams(local, work, proxy_name, info.use_encryption, info.use_compression, enc, info.bandwidth_limit, &info.bandwidth_limit_mode).await;
                    }
                    Err(e) => {
                        warn!("Work conn {}: failed to connect to local {}: {}", label, info.local_addr, e);
                    }
                }
            }
            Ok(other) => {
                warn!("Work conn {}: unexpected message: {:?}", label, other.v1_type_byte());
            }
            Err(e) => {
                warn!("Work conn {}: read error: {}", label, e);
            }
        }

        debug!("Work conn {} completed", label);

        // Replenish pool: spawn replacement to maintain pool_count
        // (Go frp v0.69.1 compat — idle work conns refilled after use)
        if pool_id >= 0 {
            spawn_work_conn(
                &server_addr,
                server_port,
                &protocol,
                &run_id,
                &proxy_info_map,
                enc_key,
                pool_id,
                auth_token,
                tls_enable,
                tls_server_name,
                tls_ca_file,
                yamux,
            );
        }
    });
}

/// Run a health check for a proxy.
/// Supports "tcp" (connect only) and "http" (GET + check 2xx status).
/// When the local service exceeds max_failed consecutive failures, sends
/// the proxy name on `health_tx` so the control loop can send CloseProxy
/// to the server.
async fn run_health_check(
    proxy_name: String,
    local_addr: String,
    check_type: String,
    check_url: String,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    max_failed: u32,
    health_tx: mpsc::UnboundedSender<String>,
) {
    info!("Health check ({}) started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        check_type, proxy_name, local_addr, interval, timeout);

    let mut failures: u32 = 0;

    loop {
        tokio::time::sleep(interval).await;

        let result = if check_type == "http" {
            run_http_check(&local_addr, &check_url, timeout).await
        } else {
            run_tcp_check(&local_addr, timeout).await
        };

        match result {
            Ok(()) => {
                failures = 0;
                debug!("Health check OK for '{}'", proxy_name);
            }
            Err(e) => {
                failures += 1;
                warn!("Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
        }

        if failures >= max_failed {
            warn!("Health check: proxy '{}' exceeded max failures ({}), sending CloseProxy",
                proxy_name, max_failed);
            let _ = health_tx.send(proxy_name.clone());
            failures = 0; // Reset to avoid repeated warnings
        }
    }
}

/// TCP health check: connect to addr, then close. Success = connection established.
async fn run_tcp_check(addr: &str, timeout: std::time::Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("TCP connect: {e}")),
        Err(_) => Err("timeout".into()),
    }
}

/// HTTP health check: connect, send GET, verify 2xx status code.
/// Uses raw TCP to avoid adding an HTTP client dependency.
async fn run_http_check(addr: &str, url: &str, timeout: std::time::Duration) -> Result<(), String> {
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("TCP connect: {e}"))?;

    // Extract host from addr (strip port for Host header)
    let host = addr.split(':').next().unwrap_or(addr);
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url, host
    );

    tokio::time::timeout(timeout, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    if n == 0 {
        return Err("empty response".into());
    }

    // Parse status line: "HTTP/1.x NNN ..."
    let response = std::str::from_utf8(&buf[..n]).map_err(|e| format!("utf8: {e}"))?;
    let status_line = response.lines().next().ok_or("no status line")?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("bad status line: {status_line}"));
    }
    let code: u16 = parts[1].parse().map_err(|_| format!("bad status code: {}", parts[1]))?;

    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(format!("HTTP {code}"))
    }
}

/// Run an STCP/XTCP visitor listener.
/// Binds a local port, accepts connections, and tunnels them
/// through the frps server to the remote STCP proxy.
async fn run_visitor_listener(
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    server_name: String,
    secret_key: String,
    bind_addr: String,
    use_encryption: bool,
    use_compression: bool,
    name: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
) {
    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Visitor '{}': bind {} failed: {}", name, bind_addr, e);
            return;
        }
    };
    info!("Visitor '{}' listening on {}", name, bind_addr);

    loop {
        match listener.accept().await {
            Ok((user_conn, peer)) => {
                debug!("Visitor '{}': user connection from {}", name, peer);

                let sa = server_addr.clone();
                let sp = server_port;
                let pt = protocol.clone();
                let sn = server_name.clone();
                let sk = secret_key.clone();
                let visitor_name = name.clone();
                let tls_sn = tls_server_name.clone();
                let tls_ca = tls_ca_file.clone();

                tokio::spawn(async move {
                    // Connect to the server
                    let opts = DialOptions {
                        server_addr: sa.clone(),
                        server_port: sp,
                        protocol: pt.clone(),
                        tls_enable,
                        tls_server_name: tls_sn,
                        tls_ca_file: tls_ca,
                        ..Default::default()
                    };
                    let mut server_conn = match dial_server(&opts).await {
                        Ok(io) => io,
                        Err(e) => {
                            warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                            return;
                        }
                    };

                    // Send NewVisitorConn
                    let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                    if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                        warn!("Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                        return;
                    }
                    debug!("Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                    // Bridge user connection ↔ server connection
                    // The server will relay to the STCP provider.
                    let mut user = user_conn;
                    match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                        Ok((to_server, to_user)) => {
                            debug!("Visitor '{}' closed: {}B to server, {}B to user", visitor_name, to_server, to_user);
                        }
                        Err(e) => {
                            debug!("Visitor '{}' bridge error: {}", visitor_name, e);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Visitor '{}': accept error: {}", name, e);
                break;
            }
        }
    }
}
