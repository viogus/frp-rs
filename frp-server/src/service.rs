use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::net::TcpListener;

use tokio::sync::mpsc;

use tracing::{info, error, warn};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::read_msg_v1;
use frp_core::transport::IoStream;
use frp_core::transport::build_tls_acceptor;

use crate::proxy::ProxyManager;
use crate::control;
use crate::vhost::VhostManager;

// ---------------------------------------------------------------
// Shared state for cross-task communication
// ---------------------------------------------------------------

#[derive(Debug)]
pub enum InternalMsg {
    NewWorkConn(IoStream),
    ProxyUserConn {
        proxy_name: String,
        user_conn: IoStream,
    },
    UdpData {
        proxy_name: String,
        content: Vec<u8>,
        remote_addr: String,
    },
}

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::UnboundedSender<InternalMsg>,
}

pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    pub auth_cfg: Arc<AuthConfig>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    pub run_id_to_ctl_tx: Arc<RwLock<HashMap<String, ControlTx>>>,
    pub proxy_bind_addr: String,
    pub vhost_manager: Arc<VhostManager>,
    pub vhost_http_port: u16,
    pub encryption_key: [u8; 32],
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
    pub dashboard_start: std::time::Instant,
}

impl AppState {
    pub fn new(auth_cfg: AuthConfig, proxy_bind_addr: String, encryption_key: [u8; 32]) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            auth_cfg: Arc::new(auth_cfg),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            run_id_to_ctl_tx: Arc::new(RwLock::new(HashMap::new())),
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            vhost_http_port: 0,
            encryption_key,
            dashboard_start: std::time::Instant::now(),
            sk_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// ---------------------------------------------------------------
// Service
// ---------------------------------------------------------------

pub struct Service {
    cfg: ServerConfig,
    state: Arc<AppState>,
}

impl Service {
    pub fn new(cfg: ServerConfig) -> Self {
        let auth_cfg = AuthConfig {
            method: match cfg.auth.method.to_lowercase().as_str() {
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: cfg.auth.token.clone(),
            oidc_issuer: cfg.auth.oidc_issuer.clone(),
            oidc_audience: cfg.auth.oidc_audience.clone(),
            additional_data: None,
        };
        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);
        Self {
            state: Arc::new(AppState::new(
            auth_cfg,
            if cfg.proxy_bind_addr.is_empty() {
                cfg.bind_addr.clone()
            } else {
                cfg.proxy_bind_addr.clone()
            },
            enc_key,
        )),
            cfg,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.bind_port);
        info!("frps starting on {}", bind_addr);

        let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = if self.cfg.tls_enable {
            match build_tls_acceptor(&self.cfg.tls_cert_file, &self.cfg.tls_key_file) {
                Ok(acc) => {
                    info!("TLS enabled with cert: {}", self.cfg.tls_cert_file);
                    Some(acc)
                }
                Err(e) => {
                    error!("Failed to initialize TLS: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            None
        };

        let listener = TcpListener::bind(&bind_addr).await?;
        info!("frps listener started on {}", bind_addr);

        // Optional WebSocket listener
        if self.cfg.websocket_port > 0 {
            let ws_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.websocket_port);
            let ws_addr2 = ws_addr.clone();
            tokio::spawn(async move {
                if let Ok(listener) = TcpListener::bind(&ws_addr2).await {
                    info!("WebSocket listener ready on {}", ws_addr2);
                    loop {
                        if let Ok((stream, addr)) = listener.accept().await {
                            info!("New WebSocket connection from {}", addr);
                            tokio::spawn(async move {
                                if let Ok(_ws) = frp_core::transport::accept_websocket(stream).await {
                                    info!("WebSocket upgrade completed for {}", addr);
                                }
                            });
                        }
                    }
                }
            });
            info!("WebSocket listener started on {}", ws_addr);
        }


        // Start HTTPS VHost listener if configured
        if self.cfg.vhost_https_port > 0 && self.cfg.tls_enable {
            let https_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.vhost_https_port);
            let https_addr2 = https_addr.clone();
            let https_state = self.state.clone();
            let cert = self.cfg.tls_cert_file.clone();
            let key = self.cfg.tls_key_file.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::vhost::run_vhost_https_listener(https_addr, cert, key, https_state).await {
                    error!("HTTPS VHost listener failed: {}", e);
                }
            });
            info!("HTTPS VHost listener starting on {}", https_addr2);
        }

        // Start dashboard server if configured
        if self.cfg.web_server.port > 0 {
            let dash_addr = format!("{}:{}", self.cfg.web_server.addr, self.cfg.web_server.port);
            let dash_addr2 = dash_addr.clone();
            let dash_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(dash_addr, dash_state).await {
                    tracing::error!("Dashboard server failed: {}", e);
                }
            });
            tracing::info!("Dashboard web UI starting on {}", dash_addr2);
        }

        // Main accept loop
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let state = self.state.clone();
                    let acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        if let Some(acceptor) = acceptor {
                            handle_tls_connection(stream, state, addr, acceptor).await;
                        } else {
                            handle_plain_connection(stream, state, addr).await;
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle a TLS connection: handshake, read first V1 frame, dispatch.
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    state: Arc<AppState>,
    addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!("TLS handshake failed from {}: {}", addr, e);
            return;
        }
    };

    info!("TLS connection from {}", addr);
    let mut tls = tls_stream;

    match read_msg_v1(&mut tls).await {
        Ok(FrpMessage::Login(login)) => {
            control::handle_control(tls, login, state, Some(addr)).await;
        }
        Ok(FrpMessage::NewWorkConn(nwc)) => {
            // TLS work connection: wrap in IoStream::Tls for pooling
            let io = IoStream::Tls(tokio_rustls::TlsStream::Server(tls));
            handle_work_conn_inner(io, nwc, state).await;
        }
        Ok(other) => {
            warn!("Unexpected first message from {}: {:?}", addr, other.v1_type_byte());
        }
        Err(e) => {
            warn!("Failed to read first message from {}: {}", addr, e);
        }
    }
}

/// Handle a non-TLS connection: read first V1 frame, dispatch.
async fn handle_plain_connection(
    mut stream: tokio::net::TcpStream,
    state: Arc<AppState>,
    addr: SocketAddr,
) {
    match read_msg_v1(&mut stream).await {
        Ok(FrpMessage::Login(login)) => {
            control::handle_control(stream, login, state, Some(addr)).await;
        }
        Ok(FrpMessage::NewWorkConn(nwc)) => {
            let io = IoStream::Tcp(stream);
            handle_work_conn_inner(io, nwc, state).await;
        }
        Ok(other) => {
            warn!("Unexpected first message from {}: {:?}", addr, other.v1_type_byte());
        }
        Err(e) => {
            warn!("Failed to read first message from {}: {}", addr, e);
        }
    }
}

/// Handle an incoming work connection. Routes the IoStream to the
/// appropriate control handler via InternalMsg.
async fn handle_work_conn_inner(
    stream: IoStream,
    msg: msg::NewWorkConn,
    state: Arc<AppState>,
) {
    let run_id = match msg.run_id {
        Some(id) => id,
        None => {
            warn!("NewWorkConn without run_id, ignoring");
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            if ctl.tx.send(InternalMsg::NewWorkConn(stream)).is_err() {
                warn!("Control handler for {} has gone away", run_id);
            }
        }
        None => {
            warn!("No control handler found for run_id {}", run_id);
        }
    }
}
