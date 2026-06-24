use std::sync::Arc;
use std::collections::HashMap;
use tokio::time::{interval, Duration};
use tracing::{info, warn, debug};

use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::ClientConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::{TransportProtocol, DialOptions, dial_server, IoStream};

use crate::proxy;
use crate::control::ControlConnection;

/// Proxy config needed at runtime for work connections.
#[derive(Clone)]
struct ProxyRuntimeInfo {
    local_addr: String,
    use_encryption: bool,
    use_compression: bool,
}

/// The main frpc service.
pub struct Service {
    cfg: ClientConfig,
    auth_cfg: Arc<AuthConfig>,
    encryption_key: [u8; 16],
    /// Map proxy_name -> runtime info for looking up where to connect
    proxy_info_map: HashMap<String, ProxyRuntimeInfo>,
}

impl Service {
    pub fn new(cfg: ClientConfig) -> Self {
        let auth_cfg = AuthConfig {
            method: AuthMethod::Token,
            token: cfg.token.clone(),
            oidc_issuer: String::new(),
            oidc_audience: String::new(),
            additional_data: None,
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);

        let mut proxy_info_map: HashMap<String, ProxyRuntimeInfo> = HashMap::new();
        for p in &cfg.proxies {
            if proxy_info_map.contains_key(&p.name) {
                warn!("Duplicate proxy name '{}' — only the first entry will be used", p.name);
                continue;
            }
            proxy_info_map.insert(p.name.clone(), ProxyRuntimeInfo {
                local_addr: format!("{}:{}", p.local_ip, p.local_port),
                use_encryption: p.use_encryption,
                use_compression: p.use_compression,
            });
        }

        Self { cfg, auth_cfg: Arc::new(auth_cfg), encryption_key: enc_key, proxy_info_map }
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

        // Spawn health checks once, outside reconnect loop (they are per-proxy, not per-session)
        for p in &proxies {
            if !p.health_check_type.is_empty() && p.health_check_type != "tcp" {
                warn!("Health check type '{}' not yet supported for '{}'", p.health_check_type, p.name);
            }
            if p.health_check_type == "tcp" {
                let la = format!("{}:{}", p.local_ip, p.local_port);
                let pn = p.name.clone();
                let interval = std::time::Duration::from_secs(
                    p.health_check_interval_seconds.max(10)
                );
                let timeout = std::time::Duration::from_secs(
                    p.health_check_timeout_seconds.max(3)
                );
                let max_failed = p.health_check_max_failed.max(1);
                tokio::spawn(async move {
                    run_health_check(pn, la, interval, timeout, max_failed).await;
                });
            }
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
            );

            let (mut control_stream, run_id) = match ctl.login().await {
                Ok(r) => {
                    did_login_once = true;
                    r
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
            info!("Logged in. run_id: {}", run_id);

            // Register proxies using IoStream directly (supports TCP and TLS)
            for p in &proxies {
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
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
            let (mut reader, mut writer) = control_stream.into_split();

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

            // Spawn UDP proxy listeners for UDP proxy types
            for p in &proxies {
                if p.proxy_type == "udp" {
                    let sa = self.cfg.server_addr.clone();
                    let sp = self.cfg.server_port;
                    let pt = protocol.clone();
                    let ru = run_id.clone();
                    let la = format!("{}:{}", p.local_ip, p.local_port);
                    let pn = p.name.clone();
                    let enc = p.use_encryption;
                    let ek = self.encryption_key;
                    let tk = auth_token.clone();
                    let tls_en = self.cfg.tls_enable;
                    let tls_sn = self.cfg.tls_server_name.clone();
                    let tls_ca = if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.clone()) };
                    tokio::spawn(async move {
                        run_udp_work_conn(sa, sp, pt, ru, la, pn, enc, ek, tk, tls_en, tls_sn, tls_ca).await;
                    });
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
                                );
                            }
                            Ok(FrpMessage::Pong(_)) => {
                                debug!("Pong received");
                            }
                            Ok(FrpMessage::UDPPacket(up)) => {
                                warn!("UDPPacket received on control connection for proxy '{}' — UDP should use dedicated work conn", up.local_addr);
                            }
                            Ok(FrpMessage::CloseProxy(cp)) => {
                                info!("Server closed proxy: {}", cp.proxy_name);
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
                        if let Err(e) = write_msg_v1(&mut writer, &ping).await {
                            warn!("Ping failed: {}. Reconnecting...", e);
                            break;
                        }
                        debug!("Ping sent");
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
/// 1. Dials the server
/// 2. Sends NewWorkConn (with run_id + auth)
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

        let mut work = match dial_server(&opts).await {
            Ok(io) => io,
            Err(e) => {
                warn!("Work conn {} dial failed: {}", label, e);
                return;
            }
        };

        // Reject unsupported transports for work conns
        match &work {
            IoStream::Kcp(_) => {
                warn!("Work conn {}: KCP not yet supported", label);
                return;
            }
            _ => {} // Tcp, Tls, and WebSocket are supported
        }

        // Build auth for work conn (Go frp v0.69.1 compat: server verifies auth on NewWorkConn)
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

        // Send NewWorkConn with run_id and auth so the server can route and verify it
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
                        proxy::bridge_streams(local, work, proxy_name, info.use_encryption, info.use_compression, enc).await;
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
            );
        }
    });
}

/// Run a health check for a TCP proxy.
/// Periodically connects to the local service and reports status.
async fn run_health_check(
    proxy_name: String,
    local_addr: String,
    interval: std::time::Duration,
    timeout: std::time::Duration,
    max_failed: u32,
) {
    info!("Health check started for '{}' -> {} (interval: {:?}, timeout: {:?})",
        proxy_name, local_addr, interval, timeout);
    
    let mut failures: u32 = 0;
    
    loop {
        tokio::time::sleep(interval).await;
        
        let result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&local_addr)).await;
        
        match result {
            Ok(Ok(_)) => {
                failures = 0;
                debug!("Health check OK for '{}'", proxy_name);
            }
            Ok(Err(e)) => {
                failures += 1;
                warn!("Health check FAIL for '{}' ({}): {}", proxy_name, failures, e);
            }
            Err(_) => {
                failures += 1;
                warn!("Health check TIMEOUT for '{}' ({})", proxy_name, failures);
            }
        }
        
        if failures >= max_failed {
            warn!("Health check: proxy '{}' exceeded max failures ({}), marking unhealthy",
                proxy_name, max_failed);
            // TODO: Send CloseProxy to server
            failures = 0; // Reset to avoid repeated warnings
        }
    }
}

/// Run a UDP work connection: dedicated TCP tunnel for UDP traffic.
/// Reads UDPPacket messages from the server and forwards to local UDP.
/// Receives local UDP data and sends as UDPPacket messages to the server.
async fn run_udp_work_conn(
    server_addr: String,
    server_port: u16,
    protocol: TransportProtocol,
    run_id: String,
    local_addr: String,
    proxy_name: String,
    use_encryption: bool,
    #[allow(unused_variables)] enc_key: [u8; 16],
    auth_token: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
) {
    if use_encryption {
        warn!("UDP work conn '{}': encryption not yet implemented for UDP tunnels", proxy_name);
        return;
    }
    debug!("UDP work conn for '{}' dialing server", proxy_name);

    let opts = DialOptions {
        server_addr,
        server_port,
        protocol,
        tls_enable,
        tls_server_name,
        tls_ca_file,
        ..Default::default()
    };

    let mut work = match dial_server(&opts).await {
        Ok(io) => io,
        Err(e) => {
            warn!("UDP work conn {} dial failed: {}", proxy_name, e);
            return;
        }
    };

    // Build auth for work conn
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let auth_cfg = frp_core::auth::AuthConfig {
        method: frp_core::auth::AuthMethod::Token,
        token: auth_token,
        oidc_issuer: String::new(),
        oidc_audience: String::new(),
        additional_data: None,
    };
    let privilege_key = auth_cfg.generate_login_key(timestamp);

    // Send NewWorkConn with auth
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id),
        timestamp: Some(timestamp),
        privilege_key,
    });
    if let Err(e) = write_msg_v1(&mut work, &nwc).await {
        warn!("UDP work conn {}: failed to send NewWorkConn: {}", proxy_name, e);
        return;
    }

    // Read StartWorkConn
    match read_msg_v1(&mut work).await {
        Ok(FrpMessage::StartWorkConn(_swc)) => {
            info!("UDP work conn '{}' assigned", proxy_name);
        }
        Ok(_) => {
            warn!("UDP work conn {}: unexpected first message", proxy_name);
            return;
        }
        Err(e) => {
            warn!("UDP work conn {}: read error: {}", proxy_name, e);
            return;
        }
    }

    // Bind local UDP socket
    let local_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            warn!("UDP work conn {}: bind failed: {}", proxy_name, e);
            return;
        }
    };

    // Connect to local UDP service
    if let Err(e) = local_socket.connect(&local_addr).await {
        warn!("UDP work conn {}: connect to local {} failed: {}", proxy_name, local_addr, e);
        return;
    }

    info!("UDP work conn '{}' bridging to {}", proxy_name, local_addr);

    // Main bridge loop: read from work conn (UDPPacket → local UDP)
    // and read from local UDP (local data → UDPPacket on work conn)
    let mut udp_buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            // Read from work connection (server → local)
            msg = read_msg_v1(&mut work) => {
                match msg {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        if let Err(e) = local_socket.send(&up.content).await {
                            debug!("UDP '{}' send to local failed: {}", proxy_name, e);
                            break;
                        }
                    }
                    Ok(FrpMessage::CloseProxy(_)) => {
                        info!("UDP proxy '{}' closed by server", proxy_name);
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        debug!("UDP work conn '{}' read error: {}", proxy_name, e);
                        break;
                    }
                }
            }

            // Read from local UDP (local → server)
            result = local_socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src)) => {
                        let udp_packet = FrpMessage::UDPPacket(msg::UDPPacket {
                            content: udp_buf[..n].to_vec(),
                            local_addr: local_addr.clone(),
                            remote_addr: src.to_string(),
                        });
                        if let Err(e) = write_msg_v1(&mut work, &udp_packet).await {
                            debug!("UDP '{}' send to server failed: {}", proxy_name, e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP '{}' recv from local failed: {}", proxy_name, e);
                        break;
                    }
                }
            }
        }
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
