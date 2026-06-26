use std::sync::Arc;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};

use frp_core::auth::{AuthConfig, AuthMethod, OidcClient};
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
    /// OIDC client for fetching access tokens (None when auth method is Token).
    oidc_client: Option<Arc<OidcClient>>,
}

impl Service {
    pub async fn new(cfg: ClientConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Determine auth method from [auth] section if present, otherwise token
        let auth_method = if let Some(ref ac) = cfg.auth {
            if ac.method == "oidc" { AuthMethod::Oidc } else { AuthMethod::Token }
        } else {
            AuthMethod::Token
        };

        let auth_cfg = AuthConfig {
            method: auth_method.clone(),
            token: cfg.token.clone(),
            oidc_issuer: cfg.auth.as_ref().map(|a| a.oidc_issuer.clone()).unwrap_or_default(),
            oidc_audience: cfg.auth.as_ref().map(|a| a.oidc_audience.clone()).unwrap_or_default(),
            oidc_skip_expiry: false,
            oidc_skip_issuer: false,
            additional_data: None,
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);

        // Create OIDC client if auth method is OIDC
        let oidc_client = if auth_method == AuthMethod::Oidc {
            let ac = cfg.auth.as_ref().ok_or("OIDC auth requires [auth] section in config")?;
            let client = OidcClient::new(
                ac.oidc_client_id.clone(),
                ac.oidc_client_secret.clone(),
                ac.oidc_audience.clone(),
                Some(ac.oidc_token_endpoint.clone()).filter(|s| !s.is_empty()),
                ac.oidc_scope.clone(),
                Some(ac.oidc_issuer.clone()).filter(|s| !s.is_empty()),
            ).await.map_err(|e| format!("OIDC client init failed: {e}"))?;
            info!("OIDC client initialized, token endpoint: {}", client.token_endpoint());
            Some(Arc::new(client))
        } else {
            None
        };

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
                } else if plugin_cfg.plugin_type == "socks5" {
                    match plugin::start_socks5_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("socks5 plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start socks5 plugin for '{}': {}", p.name, e);
                        }
                    }
                } else if plugin_cfg.plugin_type == "static_file" {
                    match plugin::start_static_file_proxy(plugin_cfg).await {
                        Ok(handle) => {
                            let addr = handle.local_addr.to_string();
                            info!("static_file plugin for '{}' started on {}", p.name, addr);
                            plugin_addrs.insert(p.name.clone(), addr);
                            plugin_handles.push(handle);
                        }
                        Err(e) => {
                            warn!("Failed to start static_file plugin for '{}': {}", p.name, e);
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
            oidc_client,
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
                if self.cfg.tls_cert_file.is_empty() { None } else { Some(self.cfg.tls_cert_file.clone()) },
                if self.cfg.tls_key_file.is_empty() { None } else { Some(self.cfg.tls_key_file.clone()) },
                if self.cfg.dns_server.is_empty() { None } else { Some(self.cfg.dns_server.clone()) },
                self.cfg.tcp_mux,
                self.oidc_client.clone(),
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
                    self.oidc_client.clone(),
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
                let visitor_type = v.visitor_type.clone();
                tokio::spawn(async move {
                    run_visitor_listener(sa, sp, pt, server_name, secret_key, bind_addr, use_enc, use_comp, name,
                        tls_enable, tls_server_name, tls_ca_file, visitor_type).await;
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
                                        local_addr: msg::UdpAddr::from_string(&la),
                                        remote_addr: Some(msg::UdpAddr {
                                            ip: src.ip().to_string(),
                                            port: src.port(),
                                            zone: String::new(),
                                        }),
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
                                    self.oidc_client.clone(),
                                );
                            }
                            Ok(FrpMessage::Pong(_)) => {
                                debug!("Pong received");
                            }
                            Ok(FrpMessage::UDPPacket(up)) => {
                                // Forward to local UDP socket (Go frp v0.69.1 compat).
                                // Use local_addr to find the matching proxy; fall back to first socket.
                                let local_str = up.local_addr.as_ref().map(|a| a.to_string()).unwrap_or_default();
                                let sock = udp_sockets.get(&local_str)
                                    .or_else(|| udp_sockets.values().next())
                                    .cloned();
                                // Decrypt/decompress if the proxy requires it
                                let content_len = up.content.len();
                                let mut payload = up.content;
                                if let Some(&(use_enc, use_comp)) = udp_enc_cfg.get(&local_str) {
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
                            Ok(FrpMessage::NatHoleClient(nhc)) => {
                                debug!("Received NatHoleClient for proxy '{}'", nhc.proxy_name);
                                let visitor_addr = nhc.visitor_addr.unwrap_or_default();
                                let proxy_name = nhc.proxy_name.clone();
                                let sid = nhc.sid.unwrap_or_default();
                                let local_addr = self.proxy_info_map
                                    .get(&proxy_name)
                                    .map(|p| p.local_addr.clone());

                                if visitor_addr.is_empty() {
                                    warn!("NatHoleClient without visitor_addr for '{}'", proxy_name);
                                    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                        sid: Some(sid.clone()),
                                    });
                                    let _ = write_msg_v1(&mut *writer.lock().await, &report).await;
                                    continue;
                                }

                                // Send NatHoleSid FIRST — so visitor can start punching concurrently
                                let sid_msg = FrpMessage::NatHoleSid(msg::NatHoleSid {
                                    sid: Some(sid.clone()),
                                    provider_addr: None, // server fills from control connection peer addr
                                });
                                if let Err(e) = write_msg_v1(&mut *writer.lock().await, &sid_msg).await {
                                    warn!("Failed to send NatHoleSid: {}", e);
                                    continue;
                                }

                                // TCP simultaneous open (visitor is punching at the same time)
                                match tcp_simultaneous_open(&visitor_addr).await {
                                    Ok(p2p_stream) => {
                                        // Connect to local service and bridge
                                        if let Some(ref local) = local_addr {
                                            match tokio::net::TcpStream::connect(local).await {
                                                Ok(local_stream) => {
                                                    tokio::spawn(async move {
                                                        let mut p2p = p2p_stream;
                                                        let mut local = local_stream;
                                                        match tokio::io::copy_bidirectional(&mut p2p, &mut local).await {
                                                            Ok((to_local, to_p2p)) => {
                                                                debug!("XTCP provider '{}' closed: {}B to local, {}B to P2P",
                                                                    proxy_name, to_local, to_p2p);
                                                            }
                                                            Err(e) => {
                                                                debug!("XTCP provider '{}' bridge error: {}", proxy_name, e);
                                                            }
                                                        }
                                                    });
                                                    // Don't send NatHoleReport — Go frp uses implicit success.
                                                    // If bridge fails, the TCP close propagates naturally.
                                                }
                                                Err(e) => {
                                                    warn!("XTCP provider '{}': connect local failed: {}", proxy_name, e);
                                                    let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                                        sid: Some(sid),
                                                    });
                                                    let _ = write_msg_v1(&mut *writer.lock().await, &report).await;
                                                }
                                            }
                                        } else {
                                            warn!("XTCP provider '{}': no local address", proxy_name);
                                            let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                                sid: Some(sid),
                                            });
                                            let _ = write_msg_v1(&mut *writer.lock().await, &report).await;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("XTCP hole punch for '{}' failed: {}", proxy_name, e);
                                        // Report failure — triggers STCP fallback on visitor side
                                        let report = FrpMessage::NatHoleReport(msg::NatHoleReport {
                                            sid: Some(sid),
                                        });
                                        let _ = write_msg_v1(&mut *writer.lock().await, &report).await;
                                    }
                                }
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
                        let mut ping_msg = msg::Ping {
                            privilege_key: None,
                            timestamp: None,
                        };
                        if let Some(ref oidc) = self.oidc_client {
                            if let Err(e) = oidc.set_ping(&mut ping_msg).await {
                                warn!("OIDC ping token failed: {}. Reconnecting...", e);
                                break;
                            }
                        } else {
                            let ts = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;
                            let ping_auth = AuthConfig {
                                method: AuthMethod::Token,
                                token: self.auth_cfg.token.clone(),
                                oidc_issuer: String::new(),
                                oidc_audience: String::new(),
                                oidc_skip_expiry: false,
                                oidc_skip_issuer: false,
                                additional_data: None,
                            };
                            ping_msg.privilege_key = ping_auth.generate_login_key(ts);
                            ping_msg.timestamp = Some(ts);
                        }
                        let ping = FrpMessage::Ping(ping_msg);
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
    oidc_client: Option<Arc<OidcClient>>,
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
            let nwc_token = auth_token.clone();
            let mut nwc_msg = msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            };
            if let Some(ref oidc) = oidc_client {
                if let Err(e) = oidc.set_new_work_conn(&mut nwc_msg).await {
                    warn!("Work conn {} OIDC NewWorkConn auth failed: {}", label, e);
                    return;
                }
            } else {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let auth_cfg = frp_core::auth::AuthConfig {
                    method: frp_core::auth::AuthMethod::Token,
                    token: nwc_token,
                    oidc_issuer: String::new(),
                    oidc_audience: String::new(),
                    oidc_skip_expiry: false,
                    oidc_skip_issuer: false,
                    additional_data: None,
                };
                nwc_msg.privilege_key = auth_cfg.generate_login_key(timestamp);
                nwc_msg.timestamp = Some(timestamp);
            }
            let nwc = FrpMessage::NewWorkConn(nwc_msg);
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
                oidc_client,
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
/// Attempt TCP simultaneous open to `peer_addr`.
///
/// Binds a local port with SO_REUSEADDR (required for simultaneous open),
/// then dials the peer. When both sides do this at roughly the same time,
/// the kernel's TCP stack matches the SYN packets and establishes a P2P
/// connection through most NAT types.
///
/// Returns the connected TcpStream on success, or an error on timeout (5s)
/// or other failures.
async fn tcp_simultaneous_open(peer_addr: &str) -> Result<tokio::net::TcpStream, String> {
    use std::net::SocketAddr;
    use tokio::net::TcpSocket;

    let peer: SocketAddr = peer_addr
        .parse()
        .map_err(|e| format!("invalid peer address '{}': {}", peer_addr, e))?;

    let local = TcpSocket::new_v4().map_err(|e| format!("TcpSocket::new_v4: {}", e))?;

    // SO_REUSEADDR is required for TCP simultaneous open:
    // both sides bind to the same port they use to connect.
    local
        .set_reuseaddr(true)
        .map_err(|e| format!("set_reuseaddr: {}", e))?;
    #[cfg(unix)]
    local.set_reuseport(true).ok();

    // Bind to any available port
    local
        .bind("0.0.0.0:0".parse().unwrap())
        .map_err(|e| format!("bind: {}", e))?;

    debug!("TCP simultaneous open: bound to local, dialing {}", peer);

    // Dial with 5-second timeout
    match tokio::time::timeout(Duration::from_secs(5), local.connect(peer)).await {
        Ok(Ok(stream)) => {
            debug!("TCP simultaneous open to {} succeeded", peer);
            Ok(stream)
        }
        Ok(Err(e)) => {
            debug!("TCP simultaneous open to {} failed: {}", peer, e);
            Err(format!("connect failed: {}", e))
        }
        Err(_) => {
            debug!("TCP simultaneous open to {} timed out after 5s", peer);
            Err("hole punch timeout".into())
        }
    }
}

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
    visitor_type: String,
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
                let vt = visitor_type.clone();

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

                    if vt == "xtcp" {
                        // --- XTCP NAT hole punch path ---
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        // Build NatHoleVisitor with MD5 sign_key
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let sign_key = if sk.is_empty() {
                            sk.clone()
                        } else {
                            frp_core::auth::generate_token(&sk, timestamp)
                        };
                        let nhv = FrpMessage::NatHoleVisitor(msg::NatHoleVisitor {
                            proxy_name: sn.clone(),
                            sign_key: Some(sign_key),
                            timestamp: Some(timestamp),
                            run_id: None,
                            use_encryption: Some(use_encryption),
                            use_compression: Some(use_compression),
                        });
                        if let Err(e) = server_conn.write_v1_frame(&nhv).await {
                            warn!("Visitor '{}': send NatHoleVisitor failed: {}", visitor_name, e);
                            return;
                        }
                        debug!("Visitor '{}': sent NatHoleVisitor for '{}'", visitor_name, sn);

                        // Read NatHoleSid (contains provider address)
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NatHoleSid(sid_msg)) => {
                                let provider_addr = sid_msg.provider_addr.unwrap_or_default();
                                debug!("Visitor '{}': got provider addr '{}'", visitor_name, provider_addr);

                                // Read NatHoleReport (provider is ready)
                                match server_conn.read_v1_frame().await {
                                    Ok(FrpMessage::NatHoleReport(_)) => {
                                        debug!("Visitor '{}': provider ready, attempting P2P", visitor_name);

                                        if !provider_addr.is_empty() {
                                            match tcp_simultaneous_open(&provider_addr).await {
                                                Ok(p2p_stream) => {
                                                    info!("Visitor '{}': XTCP P2P connected to {}", visitor_name, provider_addr);
                                                    let mut user = user_conn;
                                                    let mut p2p = p2p_stream;
                                                    match tokio::io::copy_bidirectional(&mut user, &mut p2p).await {
                                                        Ok((to_p2p, to_user)) => {
                                                            debug!("Visitor '{}' XTCP closed: {}B to P2P, {}B to user",
                                                                visitor_name, to_p2p, to_user);
                                                        }
                                                        Err(e) => {
                                                            debug!("Visitor '{}' XTCP bridge error: {}", visitor_name, e);
                                                        }
                                                    }
                                                    return; // P2P succeeded, done
                                                }
                                                Err(e) => {
                                                    warn!("Visitor '{}': XTCP hole punch failed: {}", visitor_name, e);
                                                    // Fall through to STCP fallback
                                                }
                                            }
                                        }
                                    }
                                    Ok(FrpMessage::NatHoleResp(resp)) => {
                                        if let Some(err) = resp.error {
                                            warn!("Visitor '{}': server error: {}", visitor_name, err);
                                        }
                                        return;
                                    }
                                    other => {
                                        warn!("Visitor '{}': unexpected NatHole response: {:?}", visitor_name,
                                            other.as_ref().map(|m| m.v1_type_byte()));
                                        return;
                                    }
                                }
                            }
                            Ok(FrpMessage::NatHoleResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': server error: {}", visitor_name, err);
                                }
                                return;
                            }
                            other => {
                                warn!("Visitor '{}': unexpected response to NatHoleVisitor: {:?}", visitor_name,
                                    other.as_ref().map(|m| m.v1_type_byte()));
                                return;
                            }
                        }

                        // --- STCP fallback (hole punch failed) ---
                        // Open a NEW connection for STCP relay
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!("Visitor '{}': STCP fallback dial failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': STCP fallback send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        info!("Visitor '{}': fell back to STCP relay for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' STCP relay closed: {}B to server, {}B to user",
                                    visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' STCP relay bridge error: {}", visitor_name, e);
                            }
                        }
                    } else {
                        // --- STCP relay path (existing) ---
                        let mut server_conn = match dial_server(&opts).await {
                            Ok(io) => io,
                            Err(e) => {
                                warn!("Visitor '{}': dial server failed: {}", visitor_name, e);
                                return;
                            }
                        };

                        let nvc = crate::proxy::create_visitor_conn_msg(&sn, &sk, use_encryption, use_compression);
                        debug!("Visitor '{}': NewVisitorConn JSON: {}", visitor_name, serde_json::to_string(&nvc).unwrap_or_default());
                        if let Err(e) = server_conn.write_v1_frame(&nvc).await {
                            warn!("Visitor '{}': send NewVisitorConn failed: {}", visitor_name, e);
                            return;
                        }
                        debug!("Visitor '{}': sent NewVisitorConn for '{}'", visitor_name, sn);

                        // Read NewVisitorConnResp before bridging
                        match server_conn.read_v1_frame().await {
                            Ok(FrpMessage::NewVisitorConnResp(resp)) => {
                                if let Some(err) = resp.error {
                                    warn!("Visitor '{}': STCP server error: {}", visitor_name, err);
                                    return;
                                }
                                debug!("Visitor '{}': STCP relay ready for '{}'", visitor_name, resp.proxy_name);
                            }
                            Ok(other) => {
                                warn!("Visitor '{}': unexpected response type 0x{:02x}, msg={:?}", visitor_name, other.v1_type_byte(), other);
                                return;
                            }
                            Err(e) => {
                                warn!("Visitor '{}': read NewVisitorConnResp failed: {}", visitor_name, e);
                                return;
                            }
                        }

                        let mut user = user_conn;
                        match tokio::io::copy_bidirectional(&mut user, &mut server_conn).await {
                            Ok((to_server, to_user)) => {
                                debug!("Visitor '{}' closed: {}B to server, {}B to user", visitor_name, to_server, to_user);
                            }
                            Err(e) => {
                                debug!("Visitor '{}' bridge error: {}", visitor_name, e);
                            }
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
