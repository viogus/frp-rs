use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

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
}

impl Service {
    pub fn new(cfg: ClientConfig) -> Self {
        let auth_cfg = AuthConfig {
            method: AuthMethod::Token,
            token: cfg.token.clone(),
            additional_data: None,
        };
        Self { cfg, auth_cfg: Arc::new(auth_cfg) }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!(
            "frpc (Rust) v{} connecting to {}:{}",
            frp_core::VERSION, self.cfg.server_addr, self.cfg.server_port
        );

        let protocol = TransportProtocol::from_str(&self.cfg.transport_protocol);
        let proxies = &self.cfg.proxies;

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
                self.cfg.pool_count,
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
            for p in proxies {
                let local_addr = format!("{}:{}", p.local_ip, p.local_port);
                match ctl.register_proxy(
                    &p.name, &p.proxy_type, &local_addr, p.remote_port,
                    p.use_encryption, p.use_compression, &p.sk,
                    &mut control_stream,
                ).await {
                    Ok(_) => {
                        let pn = p.name.clone();
                        let la = local_addr.clone();
                        let sa = self.cfg.server_addr.clone();
                        let sp = self.cfg.server_port;
                        let ac = self.auth_cfg.clone();
                        let pt = protocol.clone();

                        tokio::spawn(async move {
                            handle_work_connections(&pn, &la, &sa, sp, ac, pt).await;
                        });
                    }
                    Err(e) => {
                        warn!("Failed to register proxy '{}': {}", p.name, e);
                    }
                }
            }

            // Heartbeat loop
            let (mut _reader, mut writer) = control_stream.split();
            let mut heartbeat = interval(Duration::from_secs(30));

            loop {
                heartbeat.tick().await;
                if let Err(e) = ControlConnection::send_ping(&mut writer).await {
                    warn!("Ping failed: {}. Reconnecting...", e);
                    break;
                }
            }
        }
    }
}

async fn handle_work_connections(
    proxy_name: &str,
    local_addr: &str,
    server_addr: &str,
    server_port: u16,
    _auth_cfg: Arc<AuthConfig>,
    protocol: TransportProtocol,
) {
    loop {
        let mut work = match dial_server(&DialOptions {
            server_addr: server_addr.to_string(),
            server_port,
            protocol: protocol.clone(),
            ..Default::default()
        }).await {
            Ok(IoStream::Tcp(s)) => s,
            Ok(IoStream::WebSocket(_)) => {
                warn!("WebSocket work conns not yet supported");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            Err(e) => {
                warn!("Work conn dial failed for '{}': {}", proxy_name, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };


        // Send NewWorkConn
        let nwc = FrpMessage::NewWorkConn(msg::NewWorkConn {
            run_id: None, timestamp: None, privilege_key: None,
        });
        if let Err(e) = write_msg_v1(&mut work, &nwc).await {
            warn!("Failed to send NewWorkConn: {}", e);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }

        // Read StartWorkConn
        match read_msg_v1(&mut work).await {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                info!("Work conn assigned to proxy '{}'", swc.proxy_name);
                match proxy::connect_local(local_addr).await {
                    Ok(local) => {
                        proxy::bridge_streams(local, work, proxy_name).await;
                    }
                    Err(e) => {
                        warn!("Failed to connect to local {}: {}", local_addr, e);
                    }
                }
            }
            Ok(_) => warn!("Unexpected message on work channel"),
            Err(e) => warn!("Read error on work channel: {}", e),
        }
    }
}
