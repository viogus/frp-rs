use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::transport::{IoStream, TlsConfig};

use crate::proxy::{ProxyManager, ProxyEntry};
use crate::control;

/// The main frps service.
pub struct Service {
    cfg: ServerConfig,
    proxy_manager: Arc<ProxyManager>,
    auth_cfg: Arc<AuthConfig>,
    proxy_table: Arc<RwLock<HashMap<String, ProxyEntry>>>,
    used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    _tls_cfg: TlsConfig,
}

impl Service {
    pub fn new(cfg: ServerConfig) -> Self {
        let auth_cfg = AuthConfig {
            method: match cfg.auth.method.to_lowercase().as_str() {
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: cfg.auth.token.clone(),
            additional_data: None,
        };

        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            auth_cfg: Arc::new(auth_cfg),
            proxy_table: Arc::new(RwLock::new(HashMap::new())),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            _tls_cfg: TlsConfig {
                enable: cfg.tls_enable,
                cert_file: if cfg.tls_cert_file.is_empty() {
                    None
                } else {
                    Some(cfg.tls_cert_file.clone())
                },
                key_file: if cfg.tls_key_file.is_empty() {
                    None
                } else {
                    Some(cfg.tls_key_file.clone())
                },
                ca_file: if cfg.tls_ca_file.is_empty() {
                    None
                } else {
                    Some(cfg.tls_ca_file.clone())
                },
            },
            cfg,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.bind_port);
        info!("frps starting on {}", bind_addr);

        let listener = TcpListener::bind(&bind_addr).await?;
        info!("frps listener started on {}", bind_addr);

        if self.cfg.websocket_port > 0 {
            let ws_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.websocket_port);
            let pm = self.proxy_manager.clone();
            let ac = self.auth_cfg.clone();
            let pt = self.proxy_table.clone();
            let up = self.used_ports.clone();
            tokio::spawn(async move {
                ws_listener(&ws_addr, pm, ac, pt, up).await;
            });
            info!("WebSocket listener started on {}", ws_addr);
        }

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New connection from {}", addr);
                    let pm = self.proxy_manager.clone();
                    let ac = self.auth_cfg.clone();
                    let pt = self.proxy_table.clone();
                    let up = self.used_ports.clone();
                    tokio::spawn(async move {
                        control::handle_control(stream, pm, ac, pt, up).await;
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

async fn ws_listener(
    addr: &str,
    proxy_manager: Arc<ProxyManager>,
    auth_cfg: Arc<AuthConfig>,
    proxy_table: Arc<RwLock<HashMap<String, ProxyEntry>>>,
    used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind WebSocket listener: {}", e);
            return;
        }
    };
    info!("WebSocket listener ready on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New WebSocket connection from {}", addr);
                let pm = proxy_manager.clone();
                let ac = auth_cfg.clone();
                let pt = proxy_table.clone();
                let up = used_ports.clone();
                tokio::spawn(async move {
                    let io = frp_core::transport::accept_websocket(stream).await;
                    match io {
                        Ok(ws_stream) => {
                            info!("WebSocket upgrade completed for {}", addr);
                            drop(ws_stream);
                        }
                        Err(e) => warn!("WebSocket upgrade failed: {}", e),
                    }
                });
            }
            Err(e) => error!("WebSocket accept error: {}", e),
        }
    }
}
