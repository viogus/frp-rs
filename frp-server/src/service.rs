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
use frp_core::transport::{IoStream, ConnectionType, peek_connection_type, consume_tls_head_byte};
use frp_core::transport::{build_tls_acceptor, accept_websocket};
use frp_core::format_socket_addr;

use crate::proxy::ProxyManager;
use crate::control;
use crate::vhost::VhostManager;

// ---------------------------------------------------------------
// Shared state for cross-task communication
// ---------------------------------------------------------------

#[derive(Debug)]
pub enum InternalMsg {
    NewWorkConn(IoStream),
    VisitorConn {
        proxy_name: String,
        visitor_conn: IoStream,
    },
    ProxyUserConn {
        proxy_name: String,
        user_conn: IoStream,
        pre_read: Vec<u8>,
    },
    UdpData {
        proxy_name: String,
        content: Vec<u8>,
        remote_addr: String,
    },
    /// Sent when a new control connection claims the same run_id.
    /// The old handler should stop listening and clean up.
    Shutdown,
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
    pub encryption_key: [u8; 16],
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
    pub dashboard_start: std::time::Instant,
    pub allow_port_start: u16,
    pub allow_port_end: u16,
    pub sub_domain_host: String,
}

impl AppState {
    pub fn new(auth_cfg: AuthConfig, proxy_bind_addr: String, encryption_key: [u8; 16], allow_port_start: u16, allow_port_end: u16, sub_domain_host: String) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            auth_cfg: Arc::new(auth_cfg),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            run_id_to_ctl_tx: Arc::new(RwLock::new(HashMap::new())),
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            vhost_http_port: 0, // set by Service::run() before starting listeners
            encryption_key,
            dashboard_start: std::time::Instant::now(),
            sk_index: Arc::new(RwLock::new(HashMap::new())),
            allow_port_start,
            allow_port_end,
            sub_domain_host,
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
        let allow_start = cfg.allow_port_start;
        let allow_end = cfg.allow_port_end;
        let sub_host = cfg.sub_domain_host.clone();
        Self {
            state: Arc::new(AppState::new(
            auth_cfg,
            if cfg.proxy_bind_addr.is_empty() {
                cfg.bind_addr.clone()
            } else {
                cfg.proxy_bind_addr.clone()
            },
            enc_key,
            allow_start,
            allow_end,
            sub_host,
        )),
            cfg,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.bind_port);
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
            let ws_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.websocket_port);
            let ws_addr2 = ws_addr.clone();
            let ws_state = self.state.clone();
            tokio::spawn(async move {
                if let Ok(listener) = TcpListener::bind(&ws_addr2).await {
                    info!("WebSocket listener ready on {}", ws_addr2);
                    loop {
                        if let Ok((stream, addr)) = listener.accept().await {
                            info!("New WebSocket connection from {}", addr);
                            let state = ws_state.clone();
                            tokio::spawn(async move {
                                match frp_core::transport::accept_websocket(stream).await {
                                    Ok(ws) => {
                                        info!("WebSocket upgrade completed for {}", addr);
                                        // Read first frame to dispatch
                                        let ws_inner = match ws {
                                            IoStream::WebSocket(inner) => inner,
                                            _ => unreachable!(),
                                        };
                                        let mut adapter = frp_core::transport::WsByteStream::new(ws_inner);
                                        match read_msg_v1(&mut adapter).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(adapter, login, state.clone(), Some(addr)).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                let io = IoStream::WebSocket(adapter.into_inner());
                                                handle_work_conn_inner(io, nwc, state.clone()).await;
                                            }
                                            Ok(other) => {
                                                warn!("Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                warn!("WS read error from {}: {}", addr, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("WebSocket upgrade failed for {}: {}", addr, e);
                                    }
                                }
                            });
                        }
                    }
                }
            });
            info!("WebSocket listener started on {}", ws_addr);
        }


        // Start HTTP VHost listener if configured
        if self.cfg.vhost_http_port > 0 {
            let http_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.vhost_http_port);
            let http_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::vhost::run_vhost_http_listener(http_addr, http_state).await {
                    error!("HTTP VHost listener failed: {}", e);
                }
            });
            info!("HTTP VHost listener starting on port {}", self.cfg.vhost_http_port);
        }

        // Start HTTPS VHost listener if configured
        if self.cfg.vhost_https_port > 0 && self.cfg.tls_enable {
            let https_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.vhost_https_port);
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
            let dash_addr = format_socket_addr(&self.cfg.web_server.addr, self.cfg.web_server.port);
            let dash_addr2 = dash_addr.clone();
            let dash_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(dash_addr, dash_state).await {
                    tracing::error!("Dashboard server failed: {}", e);
                }
            });
            tracing::info!("Dashboard web UI starting on {}", dash_addr2);
        }

        // Main accept loop — mixed-mode: TLS, WebSocket, and V1 on same port.
        // Uses MSG_PEEK to detect connection type without consuming bytes,
        // matching Go frp v0.69.1 behavior.
        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    let state = self.state.clone();
                    let acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        let ct = match peek_connection_type(&stream).await {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("Failed to peek connection type from {}: {}", addr, e);
                                return;
                            }
                        };

                        match ct {
                            ConnectionType::Tls => {
                                // Consume 0x17 head byte, then TLS handshake
                                if let Err(e) = consume_tls_head_byte(&mut stream).await {
                                    warn!("Failed to consume TLS head byte from {}: {}", addr, e);
                                    return;
                                }
                                let acceptor = match acceptor {
                                    Some(a) => a,
                                    None => {
                                        warn!("TLS connection from {} but TLS not configured", addr);
                                        return;
                                    }
                                };
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
                                        let io = IoStream::Tls(tokio_rustls::TlsStream::Server(tls));
                                        handle_work_conn_inner(io, nwc, state).await;
                                    }
                                    Ok(other) => {
                                        warn!("Unexpected TLS first message from {}: {:?}", addr, other.v1_type_byte());
                                    }
                                    Err(e) => {
                                        warn!("TLS read error from {}: {}", addr, e);
                                    }
                                }
                            }

                            ConnectionType::WebSocket => {
                                // Byte is still in buffer (MSG_PEEK), WS upgrade directly
                                match accept_websocket(stream).await {
                                    Ok(ws) => {
                                        info!("WebSocket upgrade on main port for {}", addr);
                                        let ws_inner = match ws {
                                            IoStream::WebSocket(inner) => inner,
                                            _ => unreachable!(),
                                        };
                                        let mut adapter = frp_core::transport::WsByteStream::new(ws_inner);
                                        match read_msg_v1(&mut adapter).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(adapter, login, state.clone(), Some(addr)).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                let io = IoStream::WebSocket(adapter.into_inner());
                                                handle_work_conn_inner(io, nwc, state.clone()).await;
                                            }
                                            Ok(other) => {
                                                warn!("Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                warn!("WS read error from {}: {}", addr, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("WebSocket upgrade failed for {}: {}", addr, e);
                                    }
                                }
                            }

                            ConnectionType::V1(_byte) => {
                                // Byte is still in buffer, read_msg_v1 will consume it
                                match read_msg_v1(&mut stream).await {
                                    Ok(FrpMessage::Login(login)) => {
                                        control::handle_control(stream, login, state, Some(addr)).await;
                                    }
                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                        let io = IoStream::Tcp(stream);
                                        handle_work_conn_inner(io, nwc, state).await;
                                    }
                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                        let io = IoStream::Tcp(stream);
                                        handle_visitor_conn_inner(io, nvc, state).await;
                                    }
                                    Ok(other) => {
                                        warn!("Unexpected first message from {}: {:?}", addr, other.v1_type_byte());
                                    }
                                    Err(e) => {
                                        warn!("Failed to read first message from {}: {}", addr, e);
                                    }
                                }
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

/// Handle an incoming STCP visitor connection. Looks up the proxy via
/// the secret key (sk → proxy_name → run_id) and routes the IoStream
/// to the provider's control handler via InternalMsg::VisitorConn.
async fn handle_visitor_conn_inner(
    stream: IoStream,
    msg: msg::NewVisitorConn,
    state: Arc<AppState>,
) {
    let sk = msg.sign_key.unwrap_or_default();
    if sk.is_empty() {
        warn!("NewVisitorConn without sign_key, ignoring");
        return;
    }

    // Look up proxy name from sk_index
    let proxy_name = {
        state.sk_index.read().await.get(&sk).cloned()
    };
    let proxy_name = match proxy_name {
        Some(pn) => pn,
        None => {
            warn!("NewVisitorConn: no STCP proxy found for sk");
            return;
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!("NewVisitorConn: no run_id found for proxy '{}'", proxy_name);
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            info!("STCP visitor for proxy '{}' routed to provider {}", proxy_name, run_id);
            if ctl.tx.send(InternalMsg::VisitorConn {
                proxy_name,
                visitor_conn: stream,
            }).is_err() {
                warn!("Provider for run_id {} has gone away", run_id);
            }
        }
        None => {
            warn!("No provider found for run_id {}", run_id);
        }
    }
}

/// Handle an incoming work connection. Verifies auth, then routes the
/// IoStream to the appropriate control handler via InternalMsg.
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

    // Verify work connection auth (Go frp v0.69.1 compat)
    if let Err(e) = state.auth_cfg.validate_login(
        msg.privilege_key.as_deref(),
        msg.timestamp,
    ) {
        warn!("Work conn auth failed for run_id {}: {}", run_id, e);
        return;
    }

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
