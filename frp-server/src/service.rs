use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;

use tokio::sync::{mpsc, oneshot};

use tracing::{info, error, warn, debug};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod, OidcVerifier};
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, read_msg_v2, write_msg_v1};
use frp_core::mux;
use frp_core::transport::{IoStream, ConnectionType, peek_connection_type, consume_tls_head_byte, PreReadStream};
use frp_core::transport::{build_tls_acceptor, accept_websocket};
use frp_core::format_socket_addr;
use frp_core::metrics::ProxyMetricsRegistry;

use crate::proxy::ProxyManager;
use crate::control;
use crate::nathole::controller::{self as nathole_ctrl, Controller};
use crate::nathole::{classify, NAT_HOLE_TIMEOUT};
use crate::vhost::VhostManager;
use crate::tcpmux::TcpMuxManager;

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
    /// UDP proxy needs a work connection for data forwarding
    /// (Go frp v0.69.1 uses work connections, not control connection).
    UdpNeedsWorkConn {
        proxy_name: String,
    },
    /// Sent when a new control connection claims the same run_id.
    /// The old handler should stop listening and clean up.
    Shutdown,
    /// NAT hole punch: server tells provider to initiate hole punch.
    NatHoleClient {
        proxy_name: String,
        transaction_id: String,
        visitor_addr: Option<String>,
    },
    /// Forward NatHoleSid to visitor via control channel (Go frp compat).
    WriteNatHoleSid {
        sid: String,
        provider_addr: Option<String>,
    },
    /// Forward NatHoleReport to visitor via control channel (Go frp compat).
    WriteNatHoleReport {
        sid: String,
    },
    /// Forward NatHoleResp to visitor via control channel (Go frp XTCP compat).
    /// Carries provider's candidate/assisted addresses for NAT traversal.
    WriteNatHoleResp {
        transaction_id: String,
        error: Option<String>,
        sid: Option<String>,
        protocol: Option<String>,
        candidate_addrs: Option<Vec<String>>,
        assisted_addrs: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone)]
pub struct ControlTx {
    pub tx: mpsc::UnboundedSender<InternalMsg>,
    pub client_addr: Option<SocketAddr>,
    pub login_time: Instant,
}

/// Hot-reloadable server configuration subset, updated atomically on SIGUSR1.
#[derive(Debug, Clone)]
pub struct ReloadableState {
    pub auth_cfg: Arc<AuthConfig>,
    pub encryption_key: [u8; 16],
    pub allow_ports: Vec<(u16, u16)>,
    pub additional_auth_scopes: Vec<String>,
}

pub struct AppState {
    pub proxy_manager: Arc<ProxyManager>,
    /// Hot-reloadable config (auth, encryption, allow_ports).
    /// Uses std::sync::RwLock — blocking read has no async overhead.
    /// Writes only happen on SIGUSR1 reload (vanishingly rare).
    pub reloadable: Arc<std::sync::RwLock<ReloadableState>>,
    pub used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
    pub run_id_to_ctl_tx: Arc<RwLock<HashMap<String, ControlTx>>>,
    pub proxy_bind_addr: String,
    pub vhost_manager: Arc<VhostManager>,
    pub vhost_http_port: u16,
    pub sk_index: Arc<RwLock<HashMap<String, String>>>,
    pub dashboard_start: std::time::Instant,
    pub sub_domain_host: String,
    pub tcp_mux: bool,
    pub tcp_mux_keepalive: i64,
    pub heartbeat_timeout: i64,
    pub udp_packet_size: usize,
    pub tls_only: bool,
    pub oidc_verifier: Option<Arc<OidcVerifier>>,
    pub oidc_subjects: Arc<RwLock<HashMap<String, String>>>,
    pub nat_hole: Arc<Controller>,
    /// Shared UDP port for SUDP proxies. When > 0, all SUDP proxies
    /// use this port instead of their individual remote_port.
    pub sudp_port: u16,
    pub vhost_http_timeout: u64,
    pub user_conn_timeout: u64,
    pub tcp_mux_passthrough: bool,
    /// Custom 404 page body (HTML) from WebServerConfig.
    pub custom_404_page: String,
    /// Server-side HTTP plugin manager for lifecycle hooks.
    pub plugin_manager: Arc<crate::plugin::HttpPluginManager>,
    /// In-memory store for proxy configs submitted via dashboard Store API.
    pub proxy_config_store: Arc<RwLock<HashMap<String, frp_core::config::ProxyConfig>>>,
    /// TCPMux HTTP CONNECT route table (domain → proxy mapping).
    pub tcpmux_manager: Arc<TcpMuxManager>,
    /// Per-proxy traffic metrics for dashboard API.
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(auth_cfg: AuthConfig, proxy_bind_addr: String, encryption_key: [u8; 16], allow_ports: Vec<(u16, u16)>, sub_domain_host: String, tcp_mux: bool, tcp_mux_keepalive: i64, heartbeat_timeout: i64, udp_packet_size: usize, tls_only: bool, oidc_verifier: Option<Arc<OidcVerifier>>, sudp_port: u16, vhost_http_timeout: u64, user_conn_timeout: u64, tcp_mux_passthrough: bool, custom_404_page: String, plugin_manager: Arc<crate::plugin::HttpPluginManager>) -> Self {
        Self {
            proxy_manager: Arc::new(ProxyManager::new()),
            reloadable: Arc::new(std::sync::RwLock::new(ReloadableState {
                auth_cfg: Arc::new(auth_cfg.clone()),
                encryption_key,
                allow_ports,
                additional_auth_scopes: auth_cfg.additional_auth_scopes.clone(),
            })),
            used_ports: Arc::new(RwLock::new(std::collections::HashSet::new())),
            run_id_to_ctl_tx: Arc::new(RwLock::new(HashMap::new())),
            proxy_bind_addr,
            vhost_manager: Arc::new(VhostManager::new()),
            vhost_http_port: 0, // set by Service::run() before starting listeners
            dashboard_start: std::time::Instant::now(),
            sk_index: Arc::new(RwLock::new(HashMap::new())),
            sub_domain_host,
            tcp_mux,
            tcp_mux_keepalive,
            heartbeat_timeout,
            udp_packet_size,
            tls_only,
            oidc_verifier,
            oidc_subjects: Arc::new(RwLock::new(HashMap::new())),
            nat_hole: Arc::new(Controller::new(Duration::from_secs(3600))),
            tcpmux_manager: Arc::new(TcpMuxManager::new()),
            proxy_metrics: Arc::new(ProxyMetricsRegistry::new()),
            sudp_port,
            vhost_http_timeout,
            user_conn_timeout,
            tcp_mux_passthrough,
            custom_404_page,
            plugin_manager,
            proxy_config_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// ---------------------------------------------------------------
// Service
// ---------------------------------------------------------------

pub struct Service {
    cfg: ServerConfig,
    state: Arc<AppState>,
    /// Path to config file for SIGUSR1 reload.
    #[allow(dead_code)]
    config_file: Option<String>,
}

impl Service {
    pub async fn new(cfg: ServerConfig, config_file: Option<String>) -> Result<Self, String> {
        let auth_cfg = AuthConfig {
            method: match cfg.auth.method.to_lowercase().as_str() {
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: frp_core::auth::resolve_dynamic_token(&cfg.auth.token),
            oidc_issuer: cfg.auth.oidc_issuer.clone(),
            oidc_audience: cfg.auth.oidc_audience.clone(),
            oidc_skip_expiry: cfg.auth.oidc_skip_expiry,
            oidc_skip_issuer: cfg.auth.oidc_skip_issuer,
            additional_data: None,
            oidc_proxy_url: cfg.auth.oidc_proxy_url.clone(),
            additional_auth_scopes: cfg.auth.additional_auth_scopes.clone(),
        };

        let oidc_verifier = if auth_cfg.method == AuthMethod::Oidc {
            match OidcVerifier::new(
                auth_cfg.oidc_issuer.clone(),
                auth_cfg.oidc_audience.clone(),
                auth_cfg.oidc_skip_expiry,
                auth_cfg.oidc_skip_issuer,
                Some(auth_cfg.oidc_proxy_url.clone()).filter(|s| !s.is_empty()),
            ).await {
                Ok(v) => {
                    info!("OIDC verifier initialized (issuer: {})", auth_cfg.oidc_issuer);
                    let v = Arc::new(v);
                    v.start_background_refresh();
                    Some(v)
                }
                Err(e) => {
                    error!("OIDC verifier initialization failed: {e}");
                    return Err(format!("Cannot start frps with OIDC auth: {e}"));
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
        let state = AppState::new(
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
            cfg.transport.heartbeat_timeout,
            cfg.udp_packet_size,
            cfg.tls_only,
            oidc_verifier,
            cfg.sudp_port,
            cfg.vhost_http_timeout,
            cfg.user_conn_timeout,
            cfg.tcp_mux_passthrough,
            cfg.web_server.custom_404_page.clone(),
            Arc::new(crate::plugin::HttpPluginManager::new(cfg.http_plugins.clone())),
        );

        // Initialize prometheus registry when enabled
        if cfg.web_server.port > 0 && cfg.web_server.enable_prometheus {
            crate::metrics::prom::register_all();
        }

        Ok(Self {
            state: Arc::new(state),
            cfg,
            config_file,
        })
    }

    /// Get a clone of the shared AppState (for tests and introspection).
    pub fn state(&self) -> std::sync::Arc<AppState> {
        self.state.clone()
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.bind_port);
        info!("frps starting on {}", bind_addr);

        let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = if self.cfg.tls_enable {
            let ca_file = if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.as_str()) };
            match build_tls_acceptor(&self.cfg.tls_cert_file, &self.cfg.tls_key_file, ca_file) {
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
                                                control::handle_control(ws, login, state.clone(), Some(addr), None, false).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                handle_visitor_conn_inner(ws, nvc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                handle_nat_hole_visitor(ws, nhv, state.clone(), None).await;
                                            }
                                            Ok(other) => {
                                                warn!("Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                debug!("WS read error from {}: {}", addr, e);
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

        // Start TCPMux HTTP CONNECT listener if configured
        if self.cfg.tcpmux_httpconnect_port > 0 {
            let tcpmux_addr = format_socket_addr(
                &self.cfg.bind_addr,
                self.cfg.tcpmux_httpconnect_port,
            );
            let tcpmux_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::tcpmux::run_tcpmux_listener(tcpmux_addr, tcpmux_state).await
                {
                    error!("TCPMux HTTP CONNECT listener failed: {}", e);
                }
            });
            info!(
                "TCPMux HTTP CONNECT listener starting on port {}",
                self.cfg.tcpmux_httpconnect_port
            );
        }

        // Start SSH tunnel gateway if configured
        if self.cfg.ssh_tunnel_gateway.bind_port > 0 {
            let ssh_state = self.state.clone();
            let ssh_cfg = self.cfg.clone();
            let token = {
                let r = self.state.reloadable.read().unwrap();
                r.auth_cfg.token.clone()
            };
            tokio::spawn(async move {
                match crate::ssh_gateway::SshListener::new(&ssh_cfg, ssh_state, token).await {
                    Ok(Some(listener)) => {
                        if let Err(e) = listener.run().await {
                            tracing::error!("SSH tunnel gateway failed: {}", e);
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("SSH tunnel gateway disabled (bind_port=0)");
                    }
                    Err(e) => {
                        tracing::error!("SSH tunnel gateway init failed: {}", e);
                    }
                }
            });
            tracing::info!("SSH tunnel gateway starting on port {}", self.cfg.ssh_tunnel_gateway.bind_port);
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
                                        control::handle_control(ctl, login, state, None, None, false).await;
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
                                        control::handle_control(ctl, login, state, None, None, false).await;
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
            let dash_user = self.cfg.web_server.user.clone();
            let dash_pwd = self.cfg.web_server.password.clone();
            let dash_tls_cert = if self.cfg.web_server.tls_cert_file.is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_cert_file.clone())
            };
            let dash_tls_key = if self.cfg.web_server.tls_key_file.is_empty() {
                None
            } else {
                Some(self.cfg.web_server.tls_key_file.clone())
            };
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(
                    dash_addr, dash_state, dash_user, dash_pwd,
                    dash_tls_cert, dash_tls_key,
                ).await {
                    tracing::error!("Dashboard server failed: {}", e);
                }
            });
            tracing::info!("Dashboard web UI starting on {}", dash_addr2);
        }

        // Background cleanup for stale NAT hole punch sessions.
        // Sessions should normally be completed by the provider's NatHoleReport,
        // but if the provider crashes or the network drops, this ensures sessions
        // older than 2 minutes don't leak memory.
        let nat_hole = self.state.nat_hole.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                nat_hole.expire_sessions(Duration::from_secs(120)).await;
            }
        });

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
                            ConnectionType::Tls(first_byte) => {
                                // 0x17 = Go frp TLS prefix (must consume before handshake)
                                // 0x16 = standard TLS ClientHello (byte is part of TLS record)
                                if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
                                    if let Err(e) = consume_tls_head_byte(&mut stream).await {
                                        warn!("Failed to consume TLS head byte from {}: {}", addr, e);
                                        return;
                                    }
                                }
                                // --- SNI peek for HTTPS proxy routing ---
                                // Read ClientHello bytes (up to 4KB) to extract SNI.
                                // If SNI matches an HTTPS proxy, forward raw TLS bytes
                                // directly through the work connection (no TLS termination).
                                let mut sni_buf = vec![0u8; 4096];
                                let sni_peek_n = match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    stream.read(&mut sni_buf),
                                ).await {
                                    Ok(Ok(n)) if n >= 43 => n,
                                    Ok(Ok(_)) => 0,
                                    _ => {
                                        warn!("TLS read timeout from {} during SNI check", addr);
                                        return;
                                    }
                                };

                                // The consumed bytes always start with 0x16 (the TLS record).
                                // If first_byte was 0x17 it was already consumed and discarded above.
                                // If first_byte was 0x16 it was MSG_PEEKed (not consumed) so it is
                                // the first byte of sni_buf.
                                let sni_data = sni_buf[..sni_peek_n].to_vec();

                                // Try SNI-based routing for HTTPS proxies
                                if sni_peek_n > 0 {
                                    if let Some(sni_host) = crate::vhost::extract_sni_from_client_hello(&sni_data) {
                                        debug!("SNI from {}: {}", addr, sni_host);
                                        if let Some(route) = state.vhost_manager.lookup(&sni_host).await {
                                            let ctl_tx = {
                                                let map = state.run_id_to_ctl_tx.read().await;
                                                map.get(&route.run_id).cloned()
                                            };
                                            if let Some(ctl) = ctl_tx {
                                                info!("SNI route '{}' → HTTPS proxy '{}' from {}",
                                                    sni_host, route.proxy_name, addr);
                                                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                                                    proxy_name: route.proxy_name.clone(),
                                                    user_conn: IoStream::Tcp(stream),
                                                    pre_read: sni_data,
                                                }).ok();
                                                return;
                                            }
                                        }
                                    }
                                }

                                // No SNI match — wrap stream to replay consumed ClientHello bytes
                                // for the TLS handshake fallthrough path.
                                let stream = PreReadStream::new(sni_data, stream);

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

                                // When tcp_mux is enabled, wrap TLS stream in yamux
                                // before reading the first message (matches Go frp).
                                if state.tcp_mux {
                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(tls_stream, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!("Yamux over TLS session established for {:?}", addr);
                                            match read_msg_v1(&mut io).await {
                                                Ok(FrpMessage::Login(login)) => {
                                                    control::handle_control(io, login, state, Some(addr), Some(incoming), false).await;
                                                }
                                                Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                    handle_work_conn_inner(io, nwc, state).await;
                                                }
                                                Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                    handle_visitor_conn_inner(io, nvc, state).await;
                                                }
                                                Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                    handle_nat_hole_visitor(io, nhv, state, None).await;
                                                }
                                                Ok(other) => {
                                                    warn!("Unexpected TLS+yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    warn!("TLS+yamux read error from {}: {}", addr, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to start yamux over TLS for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    let mut tls = tls_stream;
                                    match read_msg_v1(&mut tls).await {
                                        Ok(FrpMessage::Login(login)) => {
                                            control::handle_control(tls, login, state, Some(addr), None, false).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            handle_work_conn_inner(io, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            handle_visitor_conn_inner(io, nvc, state).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            let visitor_addr = Some(addr.to_string());
                                            handle_nat_hole_visitor(io, nhv, state, visitor_addr).await;
                                        }
                                        Ok(other) => {
                                            debug!("Unexpected TLS first message from {}: {:?}", addr, other.v1_type_byte());
                                        }
                                        Err(e) => {
                                            debug!("TLS read error from {}: {}", addr, e);
                                        }
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
                                                control::handle_control(ws, login, state.clone(), Some(addr), None, false).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                handle_visitor_conn_inner(ws, nvc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                handle_nat_hole_visitor(ws, nhv, state.clone(), None).await;
                                            }
                                            Ok(other) => {
                                                warn!("Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                debug!("WS read error from {}: {}", addr, e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("WebSocket upgrade failed for {}: {}", addr, e);
                                    }
                                }
                            }

                            ConnectionType::V2 => {
                                // V2 protocol (binary framing + JSON payload)
                                if state.tls_only {
                                    warn!("TLS-only mode: rejected V2 from {}", addr);
                                    return;
                                }
                                // When tcp_mux is enabled, wrap in yamux BEFORE reading
                                // the first message (same pattern as V1 + tcp_mux).
                                if state.tcp_mux {
                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(stream, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!("Yamux over V2 session established for {:?}", addr);
                                            match io.read_v2_frame().await {
                                                Ok(FrpMessage::Login(login)) => {
                                                    control::handle_control(io, login, state, Some(addr), Some(incoming), true).await;
                                                }
                                                Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                    handle_work_conn_inner(io, nwc, state).await;
                                                }
                                                Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                    handle_visitor_conn_inner(io, nvc, state).await;
                                                }
                                                Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                    handle_nat_hole_visitor(io, nhv, state, None).await;
                                                }
                                                Ok(other) => {
                                                    warn!("Unexpected V2+yamux first message from {:?}: {:?}", addr, other.v2_type_id());
                                                }
                                                Err(e) => {
                                                    warn!("V2+yamux read error from {}: {}", addr, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to start yamux over V2 for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    // No tcp_mux: read V2 directly on raw TCP
                                    match read_msg_v2(&mut stream).await {
                                        Ok(FrpMessage::Login(login)) => {
                                            control::handle_control(stream, login, state, Some(addr), None, true).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            let io = IoStream::Tcp(stream);
                                            handle_work_conn_inner(io, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            let io = IoStream::Tcp(stream);
                                            handle_visitor_conn_inner(io, nvc, state).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            let io = IoStream::Tcp(stream);
                                            let visitor_addr = Some(addr.to_string());
                                            handle_nat_hole_visitor(io, nhv, state, visitor_addr).await;
                                        }
                                        Ok(other) => {
                                            warn!("Unexpected V2 first message from {}: {:?}", addr, other.v2_type_id());
                                        }
                                        Err(e) => {
                                            warn!("Failed to read V2 first message from {}: {}", addr, e);
                                        }
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
                                                    control::handle_control(io, login, state, Some(addr), Some(incoming), false).await;
                                                }
                                                Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                    handle_work_conn_inner(io, nwc, state).await;
                                                }
                                                Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                    handle_visitor_conn_inner(io, nvc, state).await;
                                                }
                                                Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                    handle_nat_hole_visitor(io, nhv, state, None).await;
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
                                            control::handle_control(stream, login, state, Some(addr), None, false).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            let io = IoStream::Tcp(stream);
                                            handle_work_conn_inner(io, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            let io = IoStream::Tcp(stream);
                                            handle_visitor_conn_inner(io, nvc, state).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            let io = IoStream::Tcp(stream);
                                            let visitor_addr = Some(addr.to_string());
                                            handle_nat_hole_visitor(io, nhv, state, visitor_addr).await;
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

    /// Reload configuration from the config file (SIGUSR1 handler).
    /// Re-reads the TOML config and applies safe-to-reload settings
    /// (allow_ports, auth token, encryption key). Returns a summary
    /// of changes, or an error if the config cannot be read.
    pub async fn reload(&self) -> Result<String, String> {
        let config_path = match &self.config_file {
            Some(p) => p.clone(),
            None => return Err("No config file path stored".into()),
        };
        let new_cfg: ServerConfig = frp_core::config::load_server_config(&config_path)
            .map_err(|e| format!("Failed to reload config: {e}"))?;

        let mut changes: Vec<String> = Vec::new();

        // Build new reloadable state
        let new_auth_cfg = AuthConfig {
            method: match new_cfg.auth.method.to_lowercase().as_str() {
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: frp_core::auth::resolve_dynamic_token(&new_cfg.auth.token),
            oidc_issuer: new_cfg.auth.oidc_issuer.clone(),
            oidc_audience: new_cfg.auth.oidc_audience.clone(),
            oidc_skip_expiry: new_cfg.auth.oidc_skip_expiry,
            oidc_skip_issuer: new_cfg.auth.oidc_skip_issuer,
            additional_data: None,
            oidc_proxy_url: new_cfg.auth.oidc_proxy_url.clone(),
            additional_auth_scopes: new_cfg.auth.additional_auth_scopes.clone(),
        };
        let new_enc_key = frp_core::encryption::derive_key(&new_auth_cfg.token);
        let new_allow_ports = if !new_cfg.allow_ports.is_empty() {
            frp_core::config::parse_allow_ports(&new_cfg.allow_ports)
        } else {
            vec![(new_cfg.allow_port_start, new_cfg.allow_port_end)]
        };

        // Apply under write lock
        {
            let mut r = self.state.reloadable.write().unwrap();
            if r.allow_ports != new_allow_ports {
                changes.push(format!(
                    "allow_ports: {:?} -> {:?}", r.allow_ports, new_allow_ports
                ));
                r.allow_ports = new_allow_ports;
            }
            if r.auth_cfg.token != new_auth_cfg.token {
                changes.push("auth token updated".into());
                r.auth_cfg = Arc::new(new_auth_cfg);
                r.encryption_key = new_enc_key;
            }
            let new_scopes = &r.auth_cfg.additional_auth_scopes;
            if r.additional_auth_scopes != *new_scopes {
                changes.push(format!(
                    "additional_auth_scopes: {:?} -> {:?}",
                    r.additional_auth_scopes, new_scopes
                ));
                r.additional_auth_scopes = new_scopes.clone();
            }
        }

        // Log settings that require restart
        if self.cfg.bind_port != new_cfg.bind_port {
            changes.push(format!(
                "bind_port: {} -> {} (restart required)",
                self.cfg.bind_port, new_cfg.bind_port
            ));
        }
        if self.cfg.bind_addr != new_cfg.bind_addr {
            changes.push(format!(
                "bind_addr: {} -> {} (restart required)",
                self.cfg.bind_addr, new_cfg.bind_addr
            ));
        }
        if self.cfg.tls_enable != new_cfg.tls_enable {
            changes.push(format!(
                "tls_enable: {} -> {} (restart required)",
                self.cfg.tls_enable, new_cfg.tls_enable
            ));
        }
        // OIDC verifier is created once at startup (async, fetches JWKS).
        // Changes to OIDC settings require a full restart.
        if self.cfg.auth.oidc_issuer != new_cfg.auth.oidc_issuer
            || self.cfg.auth.oidc_audience != new_cfg.auth.oidc_audience
            || self.cfg.auth.oidc_skip_expiry != new_cfg.auth.oidc_skip_expiry
            || self.cfg.auth.oidc_skip_issuer != new_cfg.auth.oidc_skip_issuer
        {
            changes.push(
                "OIDC settings changed (restart required)".to_string()
            );
        }

        if changes.is_empty() {
            Ok("config reloaded: no changes detected".into())
        } else {
            info!("Config reloaded: {}", changes.join("; "));
            Ok(changes.join("; "))
        }
    }

}

/// Handle an incoming STCP visitor connection. Looks up the proxy and
/// routes the IoStream to the provider's control handler.
///
/// Supports two auth modes:
/// 1. Go-compatible: sign_key = MD5(proxy.sk + timestamp), lookup by proxy_name
///    then validate the hash against the registered sk.
/// 2. Legacy Rust: sign_key = raw sk value, looked up directly in sk_index.
async fn handle_visitor_conn_inner(
    mut stream: IoStream,
    msg: msg::NewVisitorConn,
    state: Arc<AppState>,
) {
    let sign_key = msg.sign_key.unwrap_or_default();
    let timestamp = msg.timestamp.unwrap_or(0);

    if sign_key.is_empty() {
        warn!("NewVisitorConn without sign_key, ignoring");
        return;
    }

    // --- Mode 1: Go-compatible — lookup by proxy_name, validate MD5(sk + timestamp) ---
    let proxy_name = if let Some(proxy_info) = state.proxy_manager.get(&msg.proxy_name).await {
        if let Some(ref sk) = proxy_info.sk {
            if !sk.is_empty() {
                let expected = frp_core::auth::generate_token(sk, timestamp);
                if expected == sign_key {
                    debug!("STCP visitor auth OK (Go-compat MD5) for proxy '{}'", msg.proxy_name);
                    Some(msg.proxy_name.clone())
                } else {
                    warn!("STCP visitor MD5 auth mismatch for proxy '{}'", msg.proxy_name);
                    None
                }
            } else {
                // Proxy has no sk — no auth required (allow)
                debug!("STCP visitor: proxy '{}' has no sk, allowing", msg.proxy_name);
                Some(msg.proxy_name.clone())
            }
        } else {
            // Proxy has no sk — no auth required (allow)
            debug!("STCP visitor: proxy '{}' has no sk, allowing", msg.proxy_name);
            Some(msg.proxy_name.clone())
        }
    } else {
        None
    };

    // --- Mode 2: Legacy Rust — raw sk_index lookup (backward compat) ---
    let proxy_name = match proxy_name {
        Some(pn) => pn,
        None => {
            // Fall back to raw sk lookup for old Rust clients that send raw sk as sign_key
            let pn = state.sk_index.read().await.get(&sign_key).cloned();
            match pn {
                Some(pn) => {
                    debug!("STCP visitor auth OK (raw sk_index lookup) for proxy '{}'", pn);
                    pn
                }
                None => {
                    warn!("NewVisitorConn: no STCP proxy found for proxy_name='{}', sign_key='{}...'",
                        msg.proxy_name, &sign_key[..sign_key.len().min(8)]);
                    // Send error response to visitor (Go frp expects NewVisitorConnResp)
                    let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                        proxy_name: msg.proxy_name.clone(),
                        error: Some("proxy not found".into()),
                    });
                    let _ = write_msg_v1(&mut stream, &resp).await;
                    return;
                }
            }
        }
    };

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!("NewVisitorConn: no run_id found for proxy '{}'", proxy_name);
     // Send error response to visitor
     let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
         proxy_name: proxy_name.clone(),
         error: Some("provider not found".into()),
     });
     let _ = write_msg_v1(&mut stream, &resp).await;
     return;
        }
    };

    // --- allow_users check (Go frp compat: XTCP/STCP access control) ---
    if let Some(proxy_info) = state.proxy_manager.get(&proxy_name).await {
        if !proxy_info.allow_users.is_empty() {
            let visitor_run_id = msg.run_id.as_deref().unwrap_or("");
            if !proxy_info.allow_users.iter().any(|u| u == visitor_run_id) {
                warn!("STCP visitor '{}' not in allow_users for proxy '{}'", visitor_run_id, proxy_name);
                let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                    proxy_name: proxy_name.clone(),
                    error: Some("visitor not allowed".into()),
                });
                let _ = write_msg_v1(&mut stream, &resp).await;
                return;
            }
        }
    }

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    match ctl_tx {
        Some(ctl) => {
            info!("STCP visitor for proxy '{}' routed to provider {}", proxy_name, run_id);
       // Send success response to visitor BEFORE forwarding the stream
       // (Go frp visitor expects NewVisitorConnResp on the same connection)
       let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
           proxy_name: proxy_name.clone(),
           error: None,
       });
       if let Err(e) = write_msg_v1(&mut stream, &resp).await {
           warn!("Failed to send NewVisitorConnResp for proxy '{}': {}", proxy_name, e);
           return;
       }
            if ctl.tx.send(InternalMsg::VisitorConn {
                proxy_name,
                visitor_conn: stream,
            }).is_err() {
                warn!("Provider for run_id {} has gone away", run_id);
            }
        }
        None => {
            warn!("No provider found for run_id {}", run_id);
       // Send error response to visitor
       let resp = FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
           proxy_name: proxy_name.clone(),
           error: Some("provider disconnected".into()),
       });
       let _ = write_msg_v1(&mut stream, &resp).await;
        }
    }
}

/// Handle an incoming XTCP NatHoleVisitor connection.
///
/// Uses transaction_id and proxy_name from the message directly.
/// Validates proxy exists, looks up the provider, creates a NAT session,
/// forwards NatHoleClient to the provider via InternalMsg,
/// writes NatHoleResp (OK or error) to the visitor via the accept-loop writer,
/// and waits for the provider's report signal.
async fn handle_nat_hole_visitor(
    stream: IoStream,
    msg: msg::NatHoleVisitor,
    state: Arc<AppState>,
    visitor_addr: Option<String>,
) {
    let transaction_id = msg.transaction_id.clone();
    let proxy_name = msg.proxy_name.clone();

    if proxy_name.is_empty() {
        warn!("NatHoleVisitor without proxy_name, ignoring");
        return;
    }

    // Validate proxy exists
    if state.proxy_manager.get(&proxy_name).await.is_none() {
        warn!("NatHoleVisitor: proxy '{}' not found", proxy_name);
        let mut writer = stream.into_split().1;
        let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: Some("proxy not found".into()),
            ..Default::default()
        });
        let _ = write_msg_v1(&mut writer, &resp).await;
        return;
    }

    // Look up the provider's run_id from proxy_manager
    let run_id = state.proxy_manager.get_run_id(&proxy_name).await;
    let run_id = match run_id {
        Some(id) => id,
        None => {
            warn!("NatHoleVisitor: no run_id found for proxy '{}'", proxy_name);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider offline".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    let ctl_tx = {
        let map = state.run_id_to_ctl_tx.read().await;
        map.get(&run_id).cloned()
    };

    let ctl_tx = match ctl_tx {
        Some(ctl) => ctl,
        None => {
            warn!("No provider control handler for run_id {}", run_id);
            let mut writer = stream.into_split().1;
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider disconnected".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
    };

    let (reader, writer) = stream.into_split();
    let sid = transaction_id.clone();

    // --- Step 1: Create session and notify provider ---
    let (session, report_rx) = state
        .nat_hole
        .create_session_with_writer(
            sid.clone(),
            proxy_name.clone(),
            msg.clone(),
            writer,
        )
        .await;

    // Send NatHoleClient to provider (notification + address info)
    if ctl_tx
        .tx
        .send(InternalMsg::NatHoleClient {
            proxy_name: proxy_name.clone(),
            transaction_id: transaction_id.clone(),
            visitor_addr,
        })
        .is_err()
    {
        warn!("Provider for run_id {} has gone away", run_id);
        state.nat_hole.remove(&transaction_id).await;
        return;
    }

    info!(
        "NatHoleVisitor for proxy '{}': created session {}, waiting for provider",
        proxy_name, sid
    );

    // --- Step 2: Wait for provider's NatHoleClient with STUN addresses ---
    // The provider's control handler will do STUN discovery and send
    // NatHoleClient back with mapped_addrs/assisted_addrs.
    // handle_client() signals notify_ch when the message arrives.

    let notify_rx = {
        let mut guard = session.notify_ch.lock().await;
        let (tx, rx) = oneshot::channel();
        *guard = Some(tx);
        rx
    };

    let client_msg_received = tokio::time::timeout(
        Duration::from_secs(NAT_HOLE_TIMEOUT as u64),
        notify_rx,
    )
    .await;

    if client_msg_received.is_err() {
        warn!(
            "NatHole session {}: timeout waiting for provider NatHoleClient",
            sid
        );
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            let resp = FrpMessage::NatHoleResp(msg::NatHoleResp {
                transaction_id: transaction_id.clone(),
                error: Some("provider NAT detection timeout".into()),
                ..Default::default()
            });
            let _ = write_msg_v1(w, &resp).await;
        }
        state.nat_hole.remove(&sid).await;
        drop(reader);
        return;
    }

    // --- Step 3: Get provider's addresses from session ---
    let client_msg_opt = session.client_msg.lock().await.take();
    let client_msg = match client_msg_opt {
        Some(m) => m,
        None => {
            warn!("NatHole session {}: no client message after notify", sid);
            state.nat_hole.remove(&sid).await;
            drop(reader);
            return;
        }
    };

    let client_mapped = client_msg.mapped_addrs.unwrap_or_default();
    let client_assisted = client_msg.assisted_addrs.unwrap_or_default();
    let visitor_mapped = msg.mapped_addrs.unwrap_or_default();
    let visitor_assisted = msg.assisted_addrs.unwrap_or_default();

    // --- Step 4: Classify both NAT features ---
    let v_feature = classify::classify_nat_feature(&visitor_mapped, &[]).ok();
    let c_feature = classify::classify_nat_feature(&client_mapped, &[]).ok();

    // Store features on session
    if let Some(ref vf) = v_feature {
        *session.v_nat_feature.lock().await = Some(vf.clone());
    }
    if let Some(ref cf) = c_feature {
        *session.c_nat_feature.lock().await = Some(cf.clone());
    }

    // --- Step 5: Run analysis and build responses ---
    let (v_resp, c_resp) = if let (Some(ref vf), Some(ref cf)) = (&v_feature, &c_feature) {
        let key = nathole_ctrl::gen_analysis_key(cf, vf);
        let (mode, _index, c_behavior, v_behavior) =
            state.nat_hole.analyzer.get_recommand_behaviors(&key, cf, vf);

        let timeout_ms = c_behavior.send_delay_ms.max(v_behavior.send_delay_ms) + 5000;
        let v_read_timeout = timeout_ms - v_behavior.send_delay_ms;
        let c_read_timeout = timeout_ms - c_behavior.send_delay_ms;
        let c_ports_diff = cf.ports_difference;
        let v_ports_diff = vf.ports_difference;

        let v_resp = nathole_ctrl::build_nat_hole_response(
            &transaction_id,
            &sid,
            msg.protocol.clone(),
            mode,
            client_mapped.clone(),  // visitor gets PROVIDER's addresses
            client_assisted.clone(),
            v_behavior,
            v_read_timeout,
            c_ports_diff,
        );

        let c_resp = nathole_ctrl::build_nat_hole_response(
            &client_msg.transaction_id,
            &sid,
            client_msg.protocol.clone(),
            mode,
            visitor_mapped.clone(),  // provider gets VISITOR's addresses
            visitor_assisted.clone(),
            c_behavior,
            c_read_timeout,
            v_ports_diff,
        );

        (v_resp, Some(c_resp))
    } else {
        // Fallback: simple exchange without analysis
        let v_resp = msg::NatHoleResp {
            transaction_id: transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: msg.protocol.clone(),
            candidate_addrs: if client_mapped.is_empty() { None } else { Some(client_mapped) },
            assisted_addrs: if client_assisted.is_empty() { None } else { Some(client_assisted) },
            ..Default::default()
        };
        let c_resp = msg::NatHoleResp {
            transaction_id: client_msg.transaction_id.clone(),
            error: None,
            sid: Some(sid.clone()),
            protocol: client_msg.protocol.clone(),
            candidate_addrs: if visitor_mapped.is_empty() { None } else { Some(visitor_mapped) },
            assisted_addrs: if visitor_assisted.is_empty() { None } else { Some(visitor_assisted) },
            ..Default::default()
        };
        (v_resp, Some(c_resp))
    };

    // Store v_resp for reporting
    *session.v_resp.lock().await = Some(v_resp.clone());

    // --- Step 6: Send NatHoleResp to both sides ---
    // Send to visitor via writer
    {
        let mut writer_guard = session.visitor_writer.lock().await;
        if let Some(ref mut w) = *writer_guard {
            let _ = write_msg_v1(w, &FrpMessage::NatHoleResp(v_resp)).await;
        }
    }

    // Send to provider via control channel
    if let Some(ref cr) = c_resp {
        let _ = ctl_tx.tx.send(InternalMsg::WriteNatHoleResp {
            transaction_id: cr.transaction_id.clone(),
            error: cr.error.clone(),
            sid: cr.sid.clone(),
            protocol: cr.protocol.clone(),
            candidate_addrs: cr.candidate_addrs.clone(),
            assisted_addrs: cr.assisted_addrs.clone(),
        });
    }

    info!("NatHole session {}: NatHoleResp sent to both sides", sid);

    // --- Step 7: Wait for report ---
    match tokio::time::timeout(Duration::from_secs(30), report_rx).await {
        Ok(Ok(_report)) => {
            debug!("NatHole session {}: provider completed", sid);
        }
        Ok(Err(_)) => {
            debug!("NatHole session {}: provider dropped without report", sid);
            state.nat_hole.remove(&sid).await;
        }
        Err(_) => {
            warn!("NatHole session {}: timed out waiting for provider report", sid);
            state.nat_hole.remove(&sid).await;
            drop(reader);
        }
    }
    // reader dropped → connection closes
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

    // Verify work connection auth (Go frp v0.69.1 compat).
    // Only validate when "NewWorkConns" is in additional_auth_scopes.
    let requires_nwc_auth = state.reloadable.read().unwrap()
        .additional_auth_scopes.iter().any(|s| s == "NewWorkConns");
    let nwc_auth_result = if !requires_nwc_auth {
        Ok(())
    } else if let Some(ref verifier) = state.oidc_verifier {
        let expected_sub = state.oidc_subjects.read().await
            .get(&run_id).cloned().unwrap_or_default();
        verifier.verify_new_work_conn(
            msg.privilege_key.as_deref().unwrap_or(""),
            &expected_sub,
        ).await
    } else {
        state.reloadable.read().unwrap().auth_cfg.validate_login(
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
