use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;

use tokio::sync::mpsc;

use tracing::{info, error, warn};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod, OidcVerifier};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::read_msg_v1;
use frp_core::mux;
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
    pub allow_ports: Vec<(u16, u16)>,
    pub sub_domain_host: String,
    pub tcp_mux: bool,
    pub tcp_mux_keepalive: i64,
    pub tls_only: bool,
    pub oidc_verifier: Option<Arc<OidcVerifier>>,
    pub oidc_subjects: Arc<RwLock<HashMap<String, String>>>,
}

impl AppState {
    pub fn new(auth_cfg: AuthConfig, proxy_bind_addr: String, encryption_key: [u8; 16], allow_ports: Vec<(u16, u16)>, sub_domain_host: String, tcp_mux: bool, tcp_mux_keepalive: i64, tls_only: bool, oidc_verifier: Option<Arc<OidcVerifier>>) -> Self {
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
            allow_ports,
            sub_domain_host,
            tcp_mux,
            tcp_mux_keepalive,
            tls_only,
            oidc_verifier,
            oidc_subjects: Arc::new(RwLock::new(HashMap::new())),
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
    pub async fn new(cfg: ServerConfig) -> Self {
        let auth_cfg = AuthConfig {
            method: match cfg.auth.method.to_lowercase().as_str() {
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: cfg.auth.token.clone(),
            oidc_issuer: cfg.auth.oidc_issuer.clone(),
            oidc_audience: cfg.auth.oidc_audience.clone(),
            oidc_skip_expiry: cfg.auth.oidc_skip_expiry,
            oidc_skip_issuer: cfg.auth.oidc_skip_issuer,
            additional_data: None,
        };

        let oidc_verifier = if auth_cfg.method == AuthMethod::Oidc {
            match OidcVerifier::new(
                auth_cfg.oidc_issuer.clone(),
                auth_cfg.oidc_audience.clone(),
                auth_cfg.oidc_skip_expiry,
                auth_cfg.oidc_skip_issuer,
            ).await {
                Ok(v) => {
                    info!("OIDC verifier initialized (issuer: {})", auth_cfg.oidc_issuer);
                    Some(Arc::new(v))
                }
                Err(e) => {
                    error!("OIDC verifier initialization failed: {e}");
                    panic!("Cannot start frps with OIDC auth: {e}");
                }
            }
        } else {
            None
        };

        let enc_key = frp_core::encryption::derive_key(&auth_cfg.token);
        let allow_ports = if !cfg.allow_ports.is_empty() {
            frp_core::config::parse_allow_ports(&cfg.allow_ports)
        } else {
            vec![(cfg.allow_port_start, cfg.allow_port_end)]
        };
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
            allow_ports,
            sub_host,
            cfg.transport.tcp_mux,
            cfg.transport.tcp_mux_keepalive_interval,
            cfg.tls_only,
            oidc_verifier,
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
                                    Ok(mut ws) => {
                                        info!("WebSocket upgrade completed for {}", addr);
                                        match read_msg_v1(&mut ws).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(ws, login, state.clone(), Some(addr), None).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                handle_visitor_conn_inner(ws, nvc, state.clone()).await;
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

        // Start KCP listener if configured
        if self.cfg.kcp_bind_port > 0 {
            let kcp_state = self.state.clone();
            let kcp_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.kcp_bind_port);
            let kcp_addr2 = kcp_addr.clone();
            tokio::spawn(async move {
                let mut listener = match frp_core::kcp::KcpListener::bind(&kcp_addr2, Default::default()).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("KCP listener bind failed: {}", e);
                        return;
                    }
                };
                tracing::info!("KCP listener started on {}", kcp_addr2);
                loop {
                    match listener.accept().await {
                        Ok(stream) => {
                            let state = kcp_state.clone();
                            tokio::spawn(async move {
                                let mut ctl = frp_core::transport::IoStream::Kcp(stream);
                                match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                    Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                        control::handle_control(ctl, login, state, None, None).await;
                                    }
                                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                        handle_work_conn_inner(ctl, nwc, state).await;
                                    }
                                    Ok(other) => {
                                        tracing::warn!("Unexpected KCP message: {:?}", other.v1_type_byte());
                                    }
                                    Err(e) => {
                                        tracing::warn!("KCP read error: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("KCP accept error: {}", e);
                            break;
                        }
                    }
                }
            });
            tracing::info!("KCP listener starting on {}", kcp_addr);
        }

        // Start QUIC listener if configured (requires TLS cert/key)
        if self.cfg.quic_bind_port > 0 && self.cfg.tls_enable {
            let quic_state = self.state.clone();
            let quic_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.quic_bind_port);
            let quic_addr2 = quic_addr.clone();
            let cert_path = self.cfg.tls_cert_file.clone();
            let key_path = self.cfg.tls_key_file.clone();
            tokio::spawn(async move {
                let cert_pem = match std::fs::read_to_string(&cert_path) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("QUIC: failed to read cert file {}: {}", cert_path, e);
                        return;
                    }
                };
                let key_pem = match std::fs::read_to_string(&key_path) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("QUIC: failed to read key file {}: {}", key_path, e);
                        return;
                    }
                };
                let sockaddr: std::net::SocketAddr = match quic_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("QUIC: invalid bind address {}: {}", quic_addr, e);
                        return;
                    }
                };
                let listener = match frp_core::quic::QuicListener::new(sockaddr, &cert_pem, &key_pem) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!("QUIC listener bind failed: {}", e);
                        return;
                    }
                };
                tracing::info!("QUIC listener started on {}", quic_addr);
                loop {
                    match listener.accept().await {
                        Ok(stream) => {
                            let state = quic_state.clone();
                            tokio::spawn(async move {
                                let mut ctl = frp_core::transport::IoStream::Quic(stream);
                                match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                    Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                        control::handle_control(ctl, login, state, None, None).await;
                                    }
                                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                        handle_work_conn_inner(ctl, nwc, state).await;
                                    }
                                    Ok(other) => {
                                        tracing::warn!("Unexpected QUIC message: {:?}", other.v1_type_byte());
                                    }
                                    Err(e) => {
                                        tracing::warn!("QUIC read error: {}", e);
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("QUIC accept error: {}", e);
                            break;
                        }
                    }
                }
            });
            tracing::info!("QUIC listener starting on {}", quic_addr2);
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
                                        control::handle_control(tls, login, state, Some(addr), None).await;
                                    }
                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                        let io = IoStream::Tls(tokio_rustls::TlsStream::Server(tls));
                                        handle_work_conn_inner(io, nwc, state).await;
                                    }
                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                        let io = IoStream::Tls(tokio_rustls::TlsStream::Server(tls));
                                        handle_visitor_conn_inner(io, nvc, state).await;
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
                                if state.tls_only {
                                    warn!("TLS-only mode: rejected WebSocket from {}", addr);
                                    return;
                                }
                                // Byte is still in buffer (MSG_PEEK), WS upgrade directly.
                                // accept_websocket returns IoStream::WebSocket(WsByteStream)
                                // — ready for read_msg_v1/write_msg_v1 directly.
                                match accept_websocket(stream).await {
                                    Ok(mut ws) => {
                                        info!("WebSocket upgrade on main port for {}", addr);
                                        match read_msg_v1(&mut ws).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(ws, login, state.clone(), Some(addr), None).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                handle_visitor_conn_inner(ws, nvc, state.clone()).await;
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
                                if state.tls_only {
                                    warn!("TLS-only mode: rejected plain TCP from {}", addr);
                                    return;
                                }
                                // When tcp_mux is enabled, wrap in yamux BEFORE reading
                                // the first message. This matches Go frp v0.69.1 behaviour:
                                // both sides wrap immediately, then Login flows through
                                // a yamux stream — not on raw TCP.
                                if state.tcp_mux {
                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(stream, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!("Yamux session established for {:?}", addr);
                                            match read_msg_v1(&mut io).await {
                                                Ok(FrpMessage::Login(login)) => {
                                                    control::handle_control(io, login, state, Some(addr), Some(incoming)).await;
                                                }
                                                Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                    handle_work_conn_inner(io, nwc, state).await;
                                                }
                                                Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                    handle_visitor_conn_inner(io, nvc, state).await;
                                                }
                                                Ok(other) => {
                                                    warn!("Unexpected yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    warn!("Failed to read yamux first message from {}: {}", addr, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to start yamux server for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    // Byte is still in buffer, read_msg_v1 will consume it
                                    match read_msg_v1(&mut stream).await {
                                        Ok(FrpMessage::Login(login)) => {
                                            control::handle_control(stream, login, state, Some(addr), None).await;
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
    // OIDC path: verify JWT + subject binding
    let nwc_auth_result = if let Some(ref verifier) = state.oidc_verifier {
        let expected_sub = state.oidc_subjects.read().await
            .get(&run_id).cloned().unwrap_or_default();
        verifier.verify_new_work_conn(
            msg.privilege_key.as_deref().unwrap_or(""),
            &expected_sub,
        ).await
    } else {
        state.auth_cfg.validate_login(
            msg.privilege_key.as_deref(),
            msg.timestamp,
        ).map(|_| ())
    };
    if let Err(e) = nwc_auth_result {
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
