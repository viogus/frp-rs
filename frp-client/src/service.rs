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
            for p in &proxies {
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                match ctl.register_proxy(
                    &p.name, &p.proxy_type, &local_addr, p.remote_port,
                    p.use_encryption, p.use_compression, &p.sk,
                    &mut control_stream,
                ).await {
                    Ok(resp) => {
                        info!("Proxy '{}' registered on remote port {:?}", p.name, resp.remote_port);
                    }
                    Err(e) => {
                        warn!("Failed to register proxy '{}': {}", p.name, e);
                    }
                }
            }

            // Split control stream for reading and writing
            let (mut reader, mut writer) = control_stream.split();

            // Spawn initial pool work connections
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
