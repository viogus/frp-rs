use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;

#[cfg(feature = "quic")]
use tokio_util::sync::CancellationToken;

use tracing::{info, error, warn, debug};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod};
#[cfg(feature = "oidc")]
use frp_core::auth::OidcVerifier;
use frp_core::msg::FrpMessage;
use frp_core::protocol::read_msg_v1;
use frp_core::mux;
use frp_core::transport::{IoStream, ConnectionType, detect_and_strip_magic, PreReadStream};
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor;
#[cfg(feature = "websocket")]
use frp_core::transport::accept_websocket;
use frp_core::format_socket_addr;

use crate::control;

// Re-export state types for backward compatibility.
// All existing `use crate::service::*` imports continue to work.
pub use crate::state::{InternalMsg, ControlTx, ReloadableState, AppState};

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
                #[cfg(feature = "oidc")]
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

        #[cfg(feature = "oidc")]
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
        #[cfg(not(feature = "oidc"))]
        let oidc_verifier = None;

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
            cfg.max_ports_per_client,
            cfg.nat_hole_analysis_data_reserve_hours,
            cfg.detailed_errors_to_client,
        );

        // Initialize prometheus registry when enabled
        #[cfg(feature = "dashboard")]
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

        #[cfg(feature = "tls")]
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
        #[cfg(not(feature = "tls"))]
        let _tls_acceptor: Option<()> = None;

        let listener = TcpListener::bind(&bind_addr).await?;
        info!("frps listener started on {}", bind_addr);

        // Optional WebSocket listener
        #[cfg(feature = "websocket")]
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
                                match frp_core::transport::accept_websocket(IoStream::Tcp(stream)).await {
                                    Ok(mut ws) => {
                                        info!("WebSocket upgrade completed for {}", addr);
                                        match read_msg_v1(&mut ws).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(ws, login, state.clone(), Some(addr), None, false, None).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                crate::handlers::handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                crate::handlers::handle_visitor_conn_inner(ws, nvc, state.clone(), false).await;
                                            }
                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                crate::handlers::handle_nat_hole_visitor(ws, nhv, state.clone(), None, false).await;
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
        #[cfg(feature = "ssh")]
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
        #[cfg(feature = "kcp")]
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
                                        control::handle_control(ctl, login, state, None, None, false, None).await;
                                    }
                                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                        crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
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
        #[cfg(feature = "quic")]
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
                        Ok((stream, conn)) => {
                            let state = quic_state.clone();
                            tokio::spawn(async move {
                                let mut ctl = frp_core::transport::IoStream::Quic(stream);

                                // Try V2 magic detection on first stream.
                                // Per-stream independence: each QUIC stream gets its own
                                // V2 detection, matching Go frp's WriteMagicIfV2() per stream.
                                let mut magic = [0u8; 7];
                                let is_v2 = match ctl.read_exact(&mut magic).await {
                                    Ok(_) => magic == frp_core::protocol::V2_MAGIC_BYTES,
                                    Err(_) => false,
                                };

                                if is_v2 {
                                    // --- V2 path ---
                                    // ClientHello/ServerHello handshake → AEAD crypto negotiation.
                                    // Login is read as plaintext V2 message; AEAD wrapping happens
                                    // inside handle_control after LoginResp (matching Go frp flow).
                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                        Ok((Some(p), crypto)) => (p, crypto),
                                        Ok((None, crypto)) => {
                                            match ctl.read_raw_v2_frame().await {
                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                Ok((ft, _, _)) => {
                                                    tracing::warn!("QUIC V2: unexpected frame type {} after handshake", ft);
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::warn!("QUIC V2: failed to read message after handshake: {}", e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("QUIC V2 handshake error: {}", e);
                                            return;
                                        }
                                    };

                                    // Get remote address before moving conn into drain task.
                                    let addr: std::net::SocketAddr = conn.remote_address();

                                    // Universal drain task: handles both V2 and V1 work streams.
                                    // Each accepted stream independently detects V2 magic — if V2,
                                    // reads first V2 message; if V1, replays consumed bytes + read_msg_v1.
                                    let cancel = CancellationToken::new();
                                    let drain_cancel = cancel.clone();
                                    let drain_state = state.clone();
                                    let drain_conn = conn.clone();
                                    tokio::spawn(async move {
                                        tracing::debug!("QUIC drain (V2 ctl) started");
                                        loop {
                                            tokio::select! {
                                                _ = drain_cancel.cancelled() => {
                                                    tracing::debug!("QUIC drain (V2 ctl) cancelled");
                                                    break;
                                                }
                                                result = drain_conn.accept_bi() => {
                                                    match result {
                                                        Ok(work_stream) => {
                                                            tracing::debug!("QUIC drain (V2 ctl): accepted new stream");
                                                            let s = drain_state.clone();
                                                            tokio::spawn(async move {
                                                                let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                                                let mut wmagic = [0u8; 7];
                                                                let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                                                    Ok(_) => wmagic == frp_core::protocol::V2_MAGIC_BYTES,
                                                                    Err(_) => false,
                                                                };
                                                                if w_is_v2 {
                                                                    match wc.read_v2_frame().await {
                                                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                            crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                        }
                                                                        Ok(other) => {
                                                                            tracing::warn!("QUIC V2 drain: unexpected msg type_id={:?}", other.v2_type_id());
                                                                        }
                                                                        Err(e) => {
                                                                            tracing::warn!("QUIC V2 drain: read error: {}", e);
                                                                        }
                                                                    }
                                                                } else {
                                                                    let mut wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                                                    match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                            crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                        }
                                                                        Ok(other) => {
                                                                            tracing::warn!("QUIC V1 drain: unexpected msg type_byte={:?}", other.v1_type_byte());
                                                                        }
                                                                        Err(e) => {
                                                                            tracing::warn!("QUIC V1 drain: read error: {}", e);
                                                                        }
                                                                    }
                                                                }
                                                            });
                                                        }
                                                        Err(e) => {
                                                            tracing::debug!("QUIC drain (V2 ctl) done: {e}");
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });

                                    // Dispatch V2 Login → handle_control(v2=true, crypto_ctx).
                                    // handle_control wraps stream in AEAD after LoginResp.
                                    crate::handlers::dispatch_v2_message(ctl, msg_payload, state, addr, None, None, crypto_ctx).await;
                                    cancel.cancel();
                                } else {
                                    // --- V1 fallback ---
                                    // Replay consumed 7 bytes so read_msg_v1 sees the full V1 header.
                                    let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));

                                    match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                        Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                            // Universal drain task (V2-aware, same pattern as V2 path above).
                                            let cancel = CancellationToken::new();
                                            let drain_cancel = cancel.clone();
                                            let drain_state = state.clone();
                                            let drain_conn = conn.clone();
                                            tokio::spawn(async move {
                                                tracing::debug!("QUIC drain (V1 ctl) started");
                                                loop {
                                                    tokio::select! {
                                                        _ = drain_cancel.cancelled() => {
                                                            tracing::debug!("QUIC drain (V1 ctl) cancelled");
                                                            break;
                                                        }
                                                        result = drain_conn.accept_bi() => {
                                                            match result {
                                                                Ok(work_stream) => {
                                                                    tracing::debug!("QUIC drain (V1 ctl): accepted new stream");
                                                                    let s = drain_state.clone();
                                                                    tokio::spawn(async move {
                                                                        let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                                                        let mut wmagic = [0u8; 7];
                                                                        let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                                                            Ok(_) => wmagic == frp_core::protocol::V2_MAGIC_BYTES,
                                                                            Err(_) => false,
                                                                        };
                                                                        if w_is_v2 {
                                                                            match wc.read_v2_frame().await {
                                                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                                }
                                                                                Ok(other) => {
                                                                                    tracing::warn!("QUIC V2 drain: unexpected msg type_id={:?}", other.v2_type_id());
                                                                                }
                                                                                Err(e) => {
                                                                                    tracing::warn!("QUIC V2 drain: read error: {}", e);
                                                                                }
                                                                            }
                                                                        } else {
                                                                            let mut wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                                                            match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                                                }
                                                                                Ok(other) => {
                                                                                    tracing::warn!("QUIC V1 drain: unexpected msg type_byte={:?}", other.v1_type_byte());
                                                                                }
                                                                                Err(e) => {
                                                                                    tracing::warn!("QUIC V1 drain: read error: {}", e);
                                                                                }
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                                Err(e) => {
                                                                    tracing::debug!("QUIC drain (V1 ctl) done: {e}");
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            });
                                            // Run control handler on first stream (blocking).
                                            control::handle_control(ctl, login, state, None, None, false, None).await;
                                            cancel.cancel();
                                        }
                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                            crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                                        }
                                        Ok(other) => {
                                            tracing::warn!("Unexpected QUIC message: {:?}", other.v1_type_byte());
                                        }
                                        Err(e) => {
                                            tracing::warn!("QUIC read error: {}", e);
                                        }
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
        #[cfg(feature = "dashboard")]
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
                // Clean expired analyzer entries to prevent unbounded memory growth.
                let (removed, total) = nat_hole.analyzer.clean();
                if removed > 0 {
                    tracing::debug!("Analyzer cleanup: removed {}/{} expired entries", removed, total);
                }
            }
        });

        // Main accept loop — mixed-mode: TLS, WebSocket, and V1 on same port.
        // Uses MSG_PEEK to detect connection type without consuming bytes,
        // matching Go frp v0.69.1 behavior.
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let state = self.state.clone();
                    #[cfg(feature = "tls")]
                    let acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        let (ct, mut stream_io) = match detect_and_strip_magic(stream).await {
                            Ok((c, s)) => (c, s),
                            Err(e) => {
                                warn!("Failed to detect connection type from {}: {}", addr, e);
                                return;
                            }
                        };

                        match ct {
                            #[cfg(feature = "tls")]
                        ConnectionType::Tls(first_byte) => {
                                // Extract inner TcpStream and pre-read bytes.
                                // detect_and_strip_magic consumed 7 bytes; replay them
                                // (minus the Go frp 0x17 prefix) for TLS.
                                let (mut pre_read_bytes, mut inner_stream) = match stream_io {
                                    IoStream::PreRead(buf, s) => (buf, s),
                                    _ => {
                                        warn!("Expected PreRead for TLS connection from {}", addr);
                                        return;
                                    }
                                };

                                // 0x17 = Go frp TLS prefix (already consumed, strip from replay)
                                // 0x16 = standard TLS ClientHello (keep all bytes)
                                if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE && !pre_read_bytes.is_empty() {
                                    pre_read_bytes.remove(0); // discard 0x17
                                }

                                // --- SNI peek for HTTPS proxy routing ---
                                // Read ClientHello bytes (up to 4KB) from inner stream.
                                // The inner stream is positioned at byte 7 of the original
                                // connection. Combine with pre_read_bytes for full ClientHello.
                                let mut sni_buf = vec![0u8; 4096];
                                let sni_peek_n = match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    inner_stream.read(&mut sni_buf),
                                ).await {
                                    Ok(Ok(n)) if n >= 43 => n,
                                    Ok(Ok(_)) => 0,
                                    _ => {
                                        warn!("TLS read timeout from {} during SNI check", addr);
                                        return;
                                    }
                                };

                                // Build full ClientHello data (pre-read magic bytes + SNI peek)
                                let mut sni_data = pre_read_bytes.clone();
                                if sni_peek_n > 0 {
                                    sni_data.extend_from_slice(&sni_buf[..sni_peek_n]);
                                }

                                // Try SNI-based routing for HTTPS proxies
                                if !sni_data.is_empty() {
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
                                                    user_conn: IoStream::Tcp(inner_stream),
                                                    pre_read: sni_data,
                                                }).ok();
                                                return;
                                            }
                                        }
                                    }
                                }

                                // No SNI match — wrap stream to replay consumed bytes
                                // for the TLS handshake fallthrough path.
                                let stream = PreReadStream::new(sni_data, inner_stream);

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

                                            // Try V2 detection on yamux stream (Go frp: magic on stream)
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                Ok(_) => magic == frp_core::protocol::V2_MAGIC_BYTES,
                                                Err(_) => false,
                                            };
                                            if is_v2 {
                                                // V2 detected on TLS+yamux stream
                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        // Read Login in plaintext. AEAD wrapping happens in
                                                        // handle_control after LoginResp (matching Go frp flow).
                                                        match io.read_raw_v2_frame().await {
                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                            Ok((ft, _, _)) => {
                                                                warn!("Unexpected frame type {} after V2 TLS+yamux handshake from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                            warn!("Failed to read V2 message after TLS+yamux handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    }
                                                    }
                                                    Err(e) => {
                                                        warn!("V2 TLS+yamux handshake error from {}: {}", addr, e);
                                                        return;
                                                    }
                                                };
                                                crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                            } else {
                                                // Not V2. Replay consumed bytes for V1 processing.
                                                let mut io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                                match read_msg_v1(&mut io).await {
                                                    Ok(FrpMessage::Login(login)) => {
                                                        control::handle_control(io, login, state, Some(addr), Some(incoming), false, None).await;
                                                    }
                                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                        crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                                    }
                                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                        crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                                    }
                                                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                        crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                    }
                                                    Ok(other) => {
                                                        warn!("Unexpected TLS+yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                    }
                                                    Err(e) => {
                                                        warn!("TLS+yamux read error from {}: {}", addr, e);
                                                    }
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
                                            control::handle_control(tls, login, state, Some(addr), None, false, None).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            let io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls)));
                                            let visitor_addr = Some(addr.to_string());
                                            crate::handlers::handle_nat_hole_visitor(io, nhv, state, visitor_addr, false).await;
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

                            #[cfg(not(feature = "tls"))]
                            ConnectionType::Tls(_) => {
                                warn!("TLS connection from {} but TLS feature not enabled", addr);
                            }

                            #[cfg(feature = "websocket")]
                            ConnectionType::WebSocket => {
                                if state.tls_only {
                                    warn!("TLS-only mode: rejected WebSocket from {}", addr);
                                    return;
                                }
                                // stream_io is IoStream::PreRead — its AsyncRead replays
                                // the 7 consumed bytes (starting with 'G' for GET).
                                match accept_websocket(stream_io).await {
                                    Ok(mut ws) => {
                                        info!("WebSocket upgrade on main port for {}", addr);
                                        match read_msg_v1(&mut ws).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(ws, login, state.clone(), Some(addr), None, false, None).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                crate::handlers::handle_work_conn_inner(ws, nwc, state.clone()).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                crate::handlers::handle_visitor_conn_inner(ws, nvc, state.clone(), false).await;
                                            }
                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                crate::handlers::handle_nat_hole_visitor(ws, nhv, state.clone(), None, false).await;
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
                                // Already consumed V2 magic. Extract TcpStream.
                                let inner_stream = match stream_io {
                                    IoStream::Tcp(s) => s,
                                    _other => {
                                        warn!("Expected TcpStream for V2 connection from {}, got unexpected stream type", addr);
                                        return;
                                    }
                                };

                                if state.tls_only {
                                    warn!("TLS-only mode: rejected V2 from {}", addr);
                                    return;
                                }

                                if state.tcp_mux {
                                    // Wrap in yamux BEFORE handshake (matches Go frp flow).
                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(inner_stream, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!("Yamux over V2 session established for {:?}", addr);

                                            // Consume V2 magic on yamux stream if present.
                                            // Go frp writes magic on the yamux stream (after yamux wrap).
                                            // If magic is absent (backward compat), replay the bytes
                                            // before the handshake.
                                            {
                                                let mut magic_buf = [0u8; 7];
                                                match tokio::io::AsyncReadExt::read_exact(&mut io, &mut magic_buf).await {
                                                    Ok(_) => {
                                                        if magic_buf != frp_core::protocol::V2_MAGIC_BYTES {
                                                            // Replay non-magic bytes before handshake
                                                            io = IoStream::BufferedRead(magic_buf.to_vec(), 0, Box::new(io));
                                                        }
                                                        // Magic consumed — continue
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to read V2 magic from yamux stream: {}", e);
                                                        return;
                                                    }
                                                }
                                            }

                                            // V2 handshake: may receive ClientHello or first message
                                            let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                Ok((Some(p), crypto)) => (p, crypto),
                                                Ok((None, crypto)) => {
                                                    // Read Login in plaintext. AEAD wrapping happens in
                                                    // handle_control after LoginResp (matching Go frp flow).
                                                    match io.read_raw_v2_frame().await {
                                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                        Ok((ft, _, _)) => {
                                                            warn!("Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                            return;
                                                        }
                                                        Err(e) => {
                                                            warn!("Failed to read V2 message after handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!("V2 handshake error from {}: {}", addr, e);
                                                    return;
                                                }
                                            };

                                            crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                        }
                                        Err(e) => {
                                            warn!("Failed to start yamux over V2 for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    // No tcp_mux: V2 directly on raw TCP
                                    let mut io = IoStream::Tcp(inner_stream);

                                    // V2 handshake: may receive ClientHello or first message
                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                        Ok((Some(p), crypto)) => (p, crypto),
                                        Ok((None, crypto)) => {
                                            // Read Login in plaintext. AEAD wrapping happens in
                                            // handle_control after LoginResp (matching Go frp flow).
                                            match io.read_raw_v2_frame().await {
                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                Ok((ft, _, _)) => {
                                                    warn!("Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                    return;
                                                }
                                                Err(e) => {
                                                    warn!("Failed to read V2 message after handshake from {}: {}", addr, e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("V2 handshake error from {}: {}", addr, e);
                                            return;
                                        }
                                    };

                                    crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, None, Some(addr.to_string()), crypto_ctx).await;
                                }
                            }

                            ConnectionType::V1(_byte) => {
                                if state.tls_only {
                                    warn!("TLS-only mode: rejected plain TCP from {}", addr);
                                    return;
                                }
                                if state.tcp_mux {
                                    // Extract inner TcpStream and pre-read bytes.
                                    // Wrap in PreReadStream so yamux sees the full byte stream
                                    // (including the type byte consumed by detect_and_strip_magic).
                                    let (pre_read, inner_tcp) = match stream_io {
                                        IoStream::PreRead(buf, s) => (buf, s),
                                        _ => {
                                            warn!(
                                                "Expected PreRead stream after detect_and_strip_magic from {}, got unexpected stream type",
                                                addr
                                            );
                                            return;
                                        }
                                    };
                                    let stream = PreReadStream::new(pre_read, inner_tcp);

                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(stream, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!("Yamux session established for {:?}", addr);

                                            // Try V2 detection: read 7 magic bytes from yamux stream.
                                            // Go frp sends V2 magic on yamux stream (not raw TCP) when tcpMux.
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                Ok(_) => magic == frp_core::protocol::V2_MAGIC_BYTES,
                                                Err(_) => false,
                                            };
                                            if is_v2 {
                                                // V2 detected on yamux stream! Do V2 handshake + dispatch
                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        // Read Login in plaintext. AEAD wrapping happens in
                                                        // handle_control after LoginResp (matching Go frp flow).
                                                        match io.read_raw_v2_frame().await {
                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                            Ok((ft, _, _)) => {
                                                                warn!("Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                                warn!("Failed to read V2 message after handshake from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("V2 handshake error from {}: {}", addr, e);
                                                        return;
                                                    }
                                                };
                                                crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                            } else {
                                                // Not V2. Replay consumed bytes and process as V1.
                                                let mut io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                                match read_msg_v1(&mut io).await {
                                                    Ok(FrpMessage::Login(login)) => {
                                                        control::handle_control(io, login, state, Some(addr), Some(incoming), false, None).await;
                                                    }
                                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                        crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                                    }
                                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                        crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                                    }
                                                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                        crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                    }
                                                    Ok(other) => {
                                                        warn!("Unexpected yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to read yamux first message from {}: {}", addr, e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("Failed to start yamux server for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    // stream_io is IoStream::PreRead — its AsyncRead replays
                                    // the consumed bytes (including type byte) before reading
                                    // the rest from the TcpStream.
                                    match read_msg_v1(&mut stream_io).await {
                                        Ok(FrpMessage::Login(login)) => {
                                            control::handle_control(stream_io, login, state, Some(addr), None, false, None).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            crate::handlers::handle_work_conn_inner(stream_io, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            crate::handlers::handle_visitor_conn_inner(stream_io, nvc, state, false).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            let visitor_addr = Some(addr.to_string());
                                            crate::handlers::handle_nat_hole_visitor(stream_io, nhv, state, visitor_addr, false).await;
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
                #[cfg(feature = "oidc")]
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

