use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, error, warn};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::read_msg_v1;
use frp_core::transport::IoStream;

use crate::proxy::ProxyManager;
use crate::control;

// ---------------------------------------------------------------
// Shared state for cross-task communication
// ---------------------------------------------------------------

/// Messages sent between the control handler, proxy listeners, and work-conn handlers.
#[derive(Debug)]
pub enum InternalMsg {
    /// A new work connection (IoStream) has arrived.
    NewWorkConn(IoStream),
    /// A user has connected to a proxy port and needs a work connection.
    ProxyUserConn {
        proxy_name: String,
        user_conn: tokio::net::TcpStream,
    },
}

/// A sender handle for sending InternalMsg to a control handler.
#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::UnboundedSender<InternalMsg>,
}

/// Global application state shared across all server tasks.
pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    pub auth_cfg: Arc<AuthConfig>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    /// Map from run_id to the control handler's internal message sender.
    pub run_id_to_ctl_tx: Arc<RwLock<HashMap<String, ControlTx>>>,
}

impl AppState {
    pub fn new(auth_cfg: AuthConfig) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            auth_cfg: Arc::new(auth_cfg),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            run_id_to_ctl_tx: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// ---------------------------------------------------------------
// Service
// ---------------------------------------------------------------

/// The main frps service.
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
            additional_data: None,
        };
        Self {
            state: Arc::new(AppState::new(auth_cfg)),
            cfg,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format!("{}:{}", self.cfg.bind_addr, self.cfg.bind_port);
        info!("frps starting on {}", bind_addr);

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

        // Main accept loop — dispatch on first message type
        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // Read the first V1 frame to determine connection type
                        match read_msg_v1(&mut stream).await {
                            Ok(FrpMessage::Login(login)) => {
                                info!("New control connection from {}", addr);
                                control::handle_control(stream, login, state).await;
                            }
                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                info!("New work connection from {}", addr);
                                handle_work_conn(stream, nwc, state).await;
                            }
                            Ok(other) => {
                                warn!("Unexpected first message type from {}: {:?}", addr, other.v1_type_byte());
                            }
                            Err(e) => {
                                warn!("Failed to read first message from {}: {}", addr, e);
                            }
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

/// Handle an incoming work connection (NewWorkConn message).
/// Routes the IoStream to the appropriate control handler via InternalMsg.
async fn handle_work_conn(
    stream: tokio::net::TcpStream,
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
            if ctl.tx.send(InternalMsg::NewWorkConn(IoStream::Tcp(stream))).is_err() {
                warn!("Control handler for {} has gone away", run_id);
            }
        }
        None => {
            warn!("No control handler found for run_id {}", run_id);
        }
    }
}
