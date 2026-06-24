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

/// The main frpc service.
pub struct Service {
    cfg: ClientConfig,
    auth_cfg: Arc<AuthConfig>,
    /// Map proxy_name -> local_addr for looking up where to connect
    proxy_local_map: HashMap<String, String>,
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

        let proxy_local_map: HashMap<String, String> = cfg.proxies.iter()
            .map(|p| (p.name.clone(), format!("{}:{}", p.local_ip, p.local_port)))
            .collect();

        Self { cfg, auth_cfg: Arc::new(auth_cfg), proxy_local_map }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, self.cfg.server_addr, self.cfg.server_port
        );

        let protocol = TransportProtocol::from_str(&self.cfg.transport_protocol);
        let pool_count = self.cfg.pool_count;
        let proxies = self.cfg.proxies.clone();

        if proxies.is_empty() {
            warn!("No proxies configured");
        }

        // Main session loop with reconnection
        loop {
            let mut ctl = ControlConnection::new(
                self.cfg.server_addr.clone(),
                self.cfg.server_port,
                self.auth_cfg.clone(),
                protocol.clone(),
                pool_count,
                self.cfg.user.clone(),
            );

            let (mut control_stream, run_id) = match ctl.login().await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Login failed: {}", e);
                    if self.cfg.login_fail_exit {
                        return Err(e.into());
                    }
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            info!("Logged in. run_id: {}", run_id);

            // Register proxies
            if let IoStream::Tcp(ref mut tcp) = control_stream {
                for p in &proxies {
                    let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                    match ctl.register_proxy(
                        &p.name, &p.proxy_type, &local_addr, p.remote_port,
                        p.use_encryption, p.use_compression, &p.sk,
                        &p.custom_domains,
                        tcp,
                    ).await {
                        Ok(resp) => {
                            info!("Proxy '{}' registered on remote port {:?}", p.name, resp.remote_port);
                        }
                        Err(e) => {
                            warn!("Failed to register proxy '{}': {}", p.name, e);
                        }
                    }
                }
            } else {
                warn!("TLS control connection: proxy registration not yet supported");
            }

            // Split control stream for reading and writing
            let (mut reader, mut writer) = control_stream.into_split();

            // Spawn initial pool work connections (TCP only)
            for i in 0..pool_count {
                spawn_work_conn(
                    &self.cfg.server_addr,
                    self.cfg.server_port,
                    &protocol,
                    &run_id,
                    &self.proxy_local_map,
                    i,
                );
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
                    tokio::spawn(async move {
                        run_udp_work_conn(sa, sp, pt, ru, la, pn).await;
                    });
                }
            }

            // Spawn health checks for proxies with health check enabled
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

            // --- Message loop ---
            let mut ping_interval = interval(Duration::from_secs(30));
            #[allow(unused_assignments)]
            let mut should_reconnect = false;

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
                                    &self.proxy_local_map,
                                    -1, // on-demand, not pool
                                );
                            }
                            Ok(FrpMessage::Pong(_)) => {
                                debug!("Pong received");
                            }
                            Ok(FrpMessage::UDPPacket(up)) => {
                                debug!("UDPPacket received for proxy '{}'", up.local_addr);
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
                                should_reconnect = true;
                                break;
                            }
                        }
                    }

                    _ = ping_interval.tick() => {
                        let ping = FrpMessage::Ping(msg::Ping {
                            privilege_key: None,
                            timestamp: None,
                        });
                        if let Err(e) = write_msg_v1(&mut writer, &ping).await {
                            warn!("Ping failed: {}. Reconnecting...", e);
                            should_reconnect = true;
                            break;
                        }
                        debug!("Ping sent");
                    }
                }
            }

            if self.cfg.login_fail_exit && should_reconnect {
                return Err("connection lost".into());
            }

            // Reconnect delay
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
/// 2. Sends NewWorkConn (with run_id)
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
    proxy_local_map: &HashMap<String, String>,
    pool_id: i32,
) {
    let server_addr = server_addr.to_string();
    let run_id = run_id.to_string();
    let protocol = protocol.clone();
    let proxy_local_map = proxy_local_map.clone();

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
            ..Default::default()
        };

        let mut work = match dial_server(&opts).await {
            Ok(IoStream::Tcp(s)) => s,
            Ok(IoStream::Kcp(_)) => {
                warn!("Work conn {}: KCP not yet supported for work conns", label);
                return;
            }
            Ok(IoStream::WebSocket(_)) => {
                warn!("Work conn {}: WebSocket not supported for work conns", label);
                return;
            }
            Ok(IoStream::Tls(_)) => {
                warn!("Work conn {}: TLS not yet supported for work conns", label);
                return;
            }
            Err(e) => {
                warn!("Work conn {} dial failed: {}", label, e);
                return;
            }
        };

        // Send NewWorkConn with run_id so the server can route it
        let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: Some(run_id.clone()),
            timestamp: None,
            privilege_key: None,
        });

        if let Err(e) = write_msg_v1(&mut work, &nwc).await {
            warn!("Work conn {} failed to send NewWorkConn: {}", label, e);
            return;
        }

        debug!("Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);

        // Read StartWorkConn
        match read_msg_v1(&mut work).await {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                let proxy_name = &swc.proxy_name;
                info!("Work conn {} assigned to proxy '{}'", label, proxy_name);

                // Look up the local address for this proxy
                let local_addr = match proxy_local_map.get(proxy_name) {
                    Some(addr) => addr.clone(),
                    None => {
                        warn!("Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                // Connect to local service
                match proxy::connect_local(&local_addr).await {
                    Ok(local) => {
                        proxy::bridge_streams(local, work, proxy_name).await;
                    }
                    Err(e) => {
                        warn!("Work conn {}: failed to connect to local {}: {}", label, local_addr, e);
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
) {
    debug!("UDP work conn for '{}' dialing server", proxy_name);

    let opts = DialOptions {
        server_addr,
        server_port,
        protocol,
        ..Default::default()
    };

    let mut work = match dial_server(&opts).await {
        Ok(IoStream::Tcp(s)) => s,
        Ok(IoStream::Tls(_)) => {
            warn!("UDP work conn {}: TLS not supported", proxy_name);
            return;
        }
        _ => {
            warn!("UDP work conn {} dial failed", proxy_name);
            return;
        }
    };

    // Send NewWorkConn
    let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
        run_id: Some(run_id),
        timestamp: None,
        privilege_key: None,
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
