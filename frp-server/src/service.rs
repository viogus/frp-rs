use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;

use tokio_util::sync::CancellationToken;

use tracing::{info, error, warn, debug, instrument};

use frp_core::config::ServerConfig;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::unsafe_features::UnsafeFeatures;
#[cfg(feature = "oidc")]
use frp_core::auth::OidcVerifier;
use frp_core::msg::FrpMessage;
use frp_core::protocol::read_msg_v1;
use frp_core::mux;
use frp_core::transport::{IoStream, ConnectionType, detect_and_strip_magic, PreReadStream};
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_or_generate;
#[cfg(feature = "websocket")]
use frp_core::transport::{accept_websocket, accept_websocket_from_peeked};
use frp_core::format_socket_addr;

use crate::control;
use crate::lock::RwLockExt;

// Re-export state types for backward compatibility.
// All existing `use crate::service::*` imports continue to work.
pub use crate::state::{InternalMsg, ControlTx, ReloadableState, AppState};

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Check if a 7-byte buffer matches the V2 protocol magic bytes.
/// This check is repeated across all transport paths (TCP, KCP, QUIC, WS,
/// with/without TLS, with/without yamux) — ~16 locations total.
/// See V2_MAGIC_BYTES in frp_core::protocol.
#[inline]
fn is_v2_magic(buf: &[u8]) -> bool {
    buf.len() >= 7 && buf[..7] == frp_core::protocol::V2_MAGIC_BYTES
}

/// Run V2 handshake then read the first message frame. Returns `None` on error
/// (already logged). `addr` is `None` for listeners that don't capture peer addr.
async fn v2_handshake_and_read(
    io: &mut IoStream,
    addr: Option<std::net::SocketAddr>,
    log_prefix: &str,
) -> Option<(Vec<u8>, Option<frp_core::v2_handshake::CryptoContext>)> {
    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(io).await {
        Ok((Some(p), crypto)) => (p, crypto),
        Ok((None, crypto)) => match io.read_raw_v2_frame().await {
            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
            Ok((ft, _, _)) => {
                tracing::warn!(frame_type = ?ft, peer = ?addr, "{}: unexpected frame type {} after handshake", log_prefix, ft);
                return None;
            }
            Err(e) => {
                tracing::warn!(peer = ?addr, error = %e, "{}: failed to read message after handshake: {}", log_prefix, e);
                return None;
            }
        },
        Err(e) => {
            tracing::warn!(peer = ?addr, error = %e, "{} handshake error: {}", log_prefix, e);
            return None;
        }
    };
    Some((msg_payload, crypto_ctx))
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
    #[allow(dead_code)]
    max_connections: usize,
}

impl Service {
    pub async fn new(cfg: ServerConfig, config_file: Option<String>) -> Result<Self, String> {
        let auth_cfg = AuthConfig {
            method: match cfg.auth.method.to_lowercase().as_str() {
                #[cfg(feature = "oidc")]
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: frp_core::auth::resolve_dynamic_token_checked(&cfg.auth.token, &UnsafeFeatures::default()).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
                String::new()
            }),
            oidc_issuer: cfg.auth.oidc_issuer.clone(),
            oidc_audience: cfg.auth.oidc_audience.clone(),
            oidc_skip_expiry: cfg.auth.oidc_skip_expiry,
            oidc_skip_issuer: cfg.auth.oidc_skip_issuer,
            additional_data: None,
            oidc_proxy_url: cfg.auth.oidc_proxy_url.clone(),
            additional_auth_scopes: cfg.auth.additional_auth_scopes.clone(),
            authentication_timeout: cfg.auth.authentication_timeout,
            use_encryption: cfg.auth.use_encryption,
        };
        auth_cfg
            .check_startup()
            .map_err(|e| format!("security misconfiguration: {e}"))?;

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
                    info!(issuer = %auth_cfg.oidc_issuer, "OIDC verifier initialized (issuer: {})", auth_cfg.oidc_issuer);
                    let v = Arc::new(v);
                    v.start_background_refresh();
                    Some(v)
                }
                Err(e) => {
                    error!(error = %e, "OIDC verifier initialization failed: {e}");
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
        let max_connections: usize = match cfg.max_connections {
            Some(0) => usize::MAX, // 0 = unlimited
            Some(n) => n as usize,
            None => 10000, // default
        };
        let mut state = AppState::new(
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
            max_connections,
        );

        // Initialize prometheus registry when enabled
        #[cfg(feature = "dashboard")]
        if cfg.web_server.port > 0 && cfg.web_server.enable_prometheus {
            crate::metrics::prom::register_all();
        }

        // Load persisted proxy configs from the store file
        let store_path = crate::store::resolve_store_path(&config_file);
        let loaded = crate::store::load_store(&store_path);
        if !loaded.is_empty() {
            let mut store = state.proxy_config_store.write().await;
            for (name, config) in loaded {
                store.entry(name).or_insert(config);
            }
            info!(count = store.len(), path = %store_path.display(),
                "loaded {} stored proxy configs", store.len());
        }
        state.store_path = Some(store_path);

        Ok(Self {
            state: Arc::new(state),
            cfg,
            config_file,
            max_connections,
        })
    }

    /// Get a clone of the shared AppState (for tests and introspection).
    pub fn state(&self) -> std::sync::Arc<AppState> {
        self.state.clone()
    }

    #[instrument(skip(self), fields(bind_addr = %self.cfg.bind_addr, bind_port = %self.cfg.bind_port))]
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let bind_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.bind_port);
        info!(bind_addr = %bind_addr, "frps starting on {}", bind_addr);

        #[cfg(feature = "tls")]
        {
            let ca_file = if self.cfg.tls_ca_file.is_empty() { None } else { Some(self.cfg.tls_ca_file.as_str()) };
            let acceptor = match build_tls_acceptor_or_generate(&self.cfg.tls_cert_file, &self.cfg.tls_key_file, ca_file) {
                Ok(acc) => {
                    if self.cfg.tls_cert_file.is_empty() {
                        info!("TLS enabled with auto-generated self-signed certificate");
                    } else {
                        info!(cert_file = %self.cfg.tls_cert_file, "TLS enabled with cert: {}", self.cfg.tls_cert_file);
                    }
                    acc
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize TLS: {}", e);
                    return Err(e.into());
                }
            };
            // Store in shared state for hot-reload access.
            *self.state.tls_acceptor.write_ok() = Some(acceptor);
        }
        #[cfg(not(feature = "tls"))]
        let _tls_acceptor: Option<()> = None;

        let listener = TcpListener::bind(&bind_addr).await?;
        info!(bind_addr = %bind_addr, "frps listener started on {}", bind_addr);

        // Optional WebSocket listener
        #[cfg(feature = "websocket")]
        if self.cfg.websocket_port > 0 {
            let ws_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.websocket_port);
            let ws_addr2 = ws_addr.clone();
            let ws_state = self.state.clone();
            tokio::spawn(async move {
                if let Ok(listener) = TcpListener::bind(&ws_addr2).await {
                    info!(addr = %ws_addr2, "WebSocket listener ready on {}", ws_addr2);
                    loop {
                        tokio::select! {
                            result = listener.accept() => {
                                if let Ok((stream, addr)) = result {
                            info!(addr = %addr, "New WebSocket connection from {}", addr);
                            let state = ws_state.clone();
                            let permit = state.conn_semaphore.as_ref()
                                .and_then(|s| s.clone().try_acquire_owned().ok());
                            if permit.is_none() && state.conn_semaphore.is_some() {
                                warn!(addr = %addr, "Max connections reached, rejecting WebSocket from {}", addr);
                                continue;
                            }
                            tokio::spawn(async move {
                                let _permit = permit;
                                match frp_core::transport::accept_websocket(IoStream::Tcp(stream)).await {
                                    Ok(mut ws) => {
                                        info!(addr = %addr, "WebSocket upgrade completed for {}", addr);

                                        // Try V2 magic detection
                                        let mut magic = [0u8; 7];
                                        let is_v2 = match ws.read_exact(&mut magic).await {
                                            Ok(_) => is_v2_magic(&magic),
                                            Err(_) => false,
                                        };

                                        if is_v2 {
                                            // V2 path: ClientHello/ServerHello handshake
                                            let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut ws, Some(addr), "WS V2").await {
                                                Some(v) => v,
                                                None => return,
                                            };
                                            crate::handlers::dispatch_v2_message(ws, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                        } else if magic[0] == 0x16 {
                                            #[cfg(feature = "tls")]
                                            {
                                                let tls_acceptor = match state.tls_acceptor.read_ok().clone() {
                                                    Some(a) => a,
                                                    None => {
                                                        tracing::warn!(addr = %addr, "TLS ClientHello in WS frame but TLS not configured");
                                                        return;
                                                    }
                                                };
                                                let stream = frp_core::transport::IoStream::BufferedRead(
                                                    magic.to_vec(), 0, Box::new(ws),
                                                );
                                                let tls_stream = match tls_acceptor.accept(stream).await {
                                                    Ok(s) => s,
                                                    Err(e) => {
                                                        tracing::warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                                        return;
                                                    }
                                                };
                                                tracing::info!(addr = %addr, "TLS-over-WebSocket connection from {}", addr);

                                                // When tcp_mux is enabled, wrap TLS stream in yamux before
                                                // reading the first message (matches Go frp — Go frpc uses
                                                // tcp_mux by default over all transports).
                                                if state.tcp_mux {
                                                    let mux_cfg = mux::TcpMuxConfig {
                                                        keepalive_interval: std::time::Duration::from_secs(
                                                            state.tcp_mux_keepalive.max(1) as u64
                                                        ),
                                                    };
                                                    match mux::server_mux(tls_stream, &mux_cfg).await {
                                                        Ok((control_stream, incoming)) => {
                                                            let mut io = IoStream::Yamux(control_stream);
                                                            tracing::info!(addr = ?addr, "Yamux over WS+TLS session established for {:?}", addr);

                                                            // V2 detection on yamux stream
                                                            let mut magic = [0u8; 7];
                                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                                Ok(_) => is_v2_magic(&magic),
                                                                Err(_) => false,
                                                            };
                                                            if is_v2 {
                                                                let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut io, Some(addr), "WS+TLS+yamux V2").await {
                                                                    Some(v) => v,
                                                                    None => return,
                                                                };
                                                                crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                            } else {
                                                                // V1 over WS+TLS+yamux
                                                                let mut io = frp_core::transport::IoStream::BufferedRead(
                                                                    magic.to_vec(), 0, Box::new(io),
                                                                );
                                                                match read_msg_v1(&mut io).await {
                                                                    Ok(FrpMessage::Login(login)) => {
                                                                        control::handle_control(io, login, state.clone(), Some(addr), Some(incoming), false, None).await;
                                                                    }
                                                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                                        crate::handlers::handle_work_conn_inner(io, nwc, state.clone()).await;
                                                                    }
                                                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                                        crate::handlers::handle_visitor_conn_inner(io, nvc, state.clone(), false).await;
                                                                    }
                                                                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                                        crate::handlers::handle_nat_hole_visitor(io, nhv, state.clone(), None, false).await;
                                                                    }
                                                                    Ok(other) => {
                                                                        tracing::warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after WS+TLS+yamux from {}: {:?}", addr, other.v1_type_byte());
                                                                    }
                                                                    Err(e) => {
                                                                        tracing::warn!(addr = %addr, error = %e, "V1 read error after WS+TLS+yamux from {}: {}", addr, e);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                                                        }
                                                    }
                                                } else {
                                                    let mut io = IoStream::Tls(Box::new(tls_stream));

                                                    let mut chicken = [0u8; 7];
                                                    let is_tls_v2 = match io.read_exact(&mut chicken).await {
                                                        Ok(_) => is_v2_magic(&chicken),
                                                        Err(_) => false,
                                                    };
                                                    if is_tls_v2 {
                                                        let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut io, Some(addr), "WS+TLS+V2").await {
                                                            Some(v) => v,
                                                            None => return,
                                                        };
                                                        crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                                    } else {
                                                        let mut io = frp_core::transport::IoStream::BufferedRead(
                                                            chicken.to_vec(), 0, Box::new(io),
                                                        );
                                                        match read_msg_v1(&mut io).await {
                                                            Ok(FrpMessage::Login(login)) => {
                                                                control::handle_control(io, login, state.clone(), Some(addr), None, false, None).await;
                                                            }
                                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                                crate::handlers::handle_work_conn_inner(io, nwc, state.clone()).await;
                                                            }
                                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                                crate::handlers::handle_visitor_conn_inner(io, nvc, state.clone(), false).await;
                                                            }
                                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                                crate::handlers::handle_nat_hole_visitor(io, nhv, state.clone(), None, false).await;
                                                            }
                                                            Ok(other) => {
                                                                tracing::warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after WS+TLS from {}: {:?}", addr, other.v1_type_byte());
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(addr = %addr, error = %e, "V1 read error after WS+TLS from {}: {}", addr, e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "tls"))]
                                            {
                                                tracing::warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
                                            }
                                        } else {
                                            // V1 fallback: replay consumed 7 bytes
                                            let mut ws = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
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
                                                    warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "WS read error from {}: {}", addr, e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "WebSocket upgrade failed for {}: {}", addr, e);
                                    }
                                }
                            });
                                }
                            }
                            _ = ws_state.shutdown_token.cancelled() => break,
                        }
                    }
                }
            });
            info!(addr = %ws_addr, "WebSocket listener started on {}", ws_addr);
        }


        // Start HTTP VHost listener if configured
        if self.cfg.vhost_http_port > 0 {
            let http_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.vhost_http_port);
            let http_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::vhost::run_vhost_http_listener(http_addr, http_state).await {
                    error!(error = %e, "HTTP VHost listener failed: {}", e);
                }
            });
            info!(port = %self.cfg.vhost_http_port, "HTTP VHost listener starting on port {}", self.cfg.vhost_http_port);
        }

        // Start HTTPS VHost listener if configured
        if self.cfg.vhost_https_port > 0 && self.cfg.tls_enable {
            let https_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.vhost_https_port);
            let https_addr2 = https_addr.clone();
            let https_state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::vhost::run_vhost_https_listener(https_addr, https_state).await {
                    error!(error = %e, "HTTPS VHost listener failed: {}", e);
                }
            });
            info!(addr = %https_addr2, "HTTPS VHost listener starting on {}", https_addr2);
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
                    error!(error = %e, "TCPMux HTTP CONNECT listener failed: {}", e);
                }
            });
            info!(port = %self.cfg.tcpmux_httpconnect_port,
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
                let r = self.state.reloadable.read_ok();
                r.auth_cfg.token.clone()
            };
            tokio::spawn(async move {
                match crate::ssh_gateway::SshListener::new(&ssh_cfg, ssh_state, token).await {
                    Ok(Some(listener)) => {
                        if let Err(e) = listener.run().await {
                            tracing::error!(error = %e, "SSH tunnel gateway failed: {}", e);
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("SSH tunnel gateway disabled (bind_port=0)");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SSH tunnel gateway init failed: {}", e);
                    }
                }
            });
            tracing::info!(port = %self.cfg.ssh_tunnel_gateway.bind_port, "SSH tunnel gateway starting on port {}", self.cfg.ssh_tunnel_gateway.bind_port);
        }

        // Start KCP listener if configured
        #[cfg(feature = "kcp")]
        if self.cfg.kcp_bind_port > 0 {
            let kcp_state = self.state.clone();
            let kcp_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.kcp_bind_port);
            let kcp_addr2 = kcp_addr.clone();
            tokio::spawn(async move {
                let mut listener = match frp_core::kcp::KcpListener::bind(&kcp_addr2, frp_core::kcp::default_kcp_config()).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(error = %e, "KCP listener bind failed: {}", e);
                        return;
                    }
                };
                tracing::info!(addr = %kcp_addr2, "KCP listener started on {}", kcp_addr2);
                'kcp_accept: loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok(stream) => {
                                    tracing::debug!("KCP ACCEPT: got stream, spawning handler");
                                    let state = kcp_state.clone();
                                    let addr = stream.peer_addr;
                                    let permit = state.conn_semaphore.as_ref()
                                        .and_then(|s| s.clone().try_acquire_owned().ok());
                                    if permit.is_none() && state.conn_semaphore.is_some() {
                                        warn!(addr = %addr, "Max connections reached, rejecting KCP from {}", addr);
                                        continue;
                                    }
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        let peer = stream.peer_addr;
                                let conv = stream.conv();
                                tracing::debug!("KCP HANDLER: spawned peer={} conv={}", peer, conv);
                                tracing::info!(peer = %peer, conv = conv, "KCP handler: spawned for {} conv={}", peer, conv);
                                let mut ctl = frp_core::transport::IoStream::Kcp(stream);

                                // Try V2 magic detection
                                let mut magic = [0u8; 7];
                                let is_v2 = match ctl.read_exact(&mut magic).await {
                                    Ok(_) => is_v2_magic(&magic),
                                    Err(e) => {
                                        tracing::debug!(peer = %peer, error = %e, "KCP: failed to read initial 7 bytes from {}", peer);
                                        false
                                    }
                                };
                                tracing::info!(peer = %peer, first_byte = ?format_args!("0x{:02x}", magic[0]), is_v2, "KCP: new session from {} (first_byte=0x{:02x}, is_v2={})", peer, magic[0], is_v2);

                                if is_v2 {
                                    // V2 path: ClientHello/ServerHello handshake
                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                        Ok((Some(p), crypto)) => (p, crypto),
                                        Ok((None, crypto)) => {
                                            match ctl.read_raw_v2_frame().await {
                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                Ok((ft, _, _)) => {
                                                    tracing::warn!(frame_type = ?ft, "KCP V2: unexpected frame type {} after handshake", ft);
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::warn!(error = %e, "KCP V2: failed to read message after handshake: {}", e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "KCP V2 handshake error: {}", e);
                                            return;
                                        }
                                    };
                                    // KCP listener doesn't capture peer addr (matching V1 behavior).
                                    // Use unspecified addr for dispatch_v2_message logging.
                                    let peer_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
                                    crate::handlers::dispatch_v2_message(ctl, msg_payload, state, peer_addr, None, None, crypto_ctx).await;
                                } else {
                                    let first_byte = magic[0];

                                    #[cfg(feature = "tls")]
                                    let is_tls = state.tls_acceptor.read_ok().is_some()
                                        && (first_byte == 0x16 || first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE);
                                    #[cfg(not(feature = "tls"))]
                                    let is_tls = false;

                                    if is_tls {
                                        #[cfg(feature = "tls")]
                                        {
                                            // TLS over KCP: Go frpc performs TLS handshake inside the KCP
                                            // stream before sending any FRP protocol data. Strip the
                                            // Go frp 0x17 prefix byte if present, replay remaining
                                            // pre-read bytes, then do TLS accept.
                                            let tls_pre_read = if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
                                                magic[1..].to_vec()
                                            } else {
                                                magic.to_vec()
                                            };
                                            let pre_read_len = tls_pre_read.len();
                                            let ctl = frp_core::transport::IoStream::BufferedRead(
                                                tls_pre_read, 0, Box::new(ctl),
                                            );
                                            let acceptor = match state.tls_acceptor.read_ok().clone() {
                                                Some(a) => a,
                                                None => {
                                                    tracing::warn!("KCP TLS connection but no TLS acceptor configured");
                                                    return;
                                                }
                                            };
                                            tracing::info!(peer = %peer, pre_read_len, "KCP TLS: starting TLS accept ({} bytes pre-read)", pre_read_len);
                                            let tls_stream = match tokio::time::timeout(
                                                std::time::Duration::from_secs(10),
                                                acceptor.accept(ctl),
                                            ).await {
                                                Ok(Ok(s)) => {
                                                    tracing::info!(peer = %peer, "KCP TLS handshake succeeded from {}", peer);
                                                    s
                                                }
                                                Ok(Err(e)) => {
                                                    tracing::warn!(error = %e, "KCP TLS handshake failed: {}", e);
                                                    return;
                                                }
                                                Err(_elapsed) => {
                                                    tracing::warn!(peer = %peer, "KCP TLS handshake timed out after 10s");
                                                    return;
                                                }
                                            };
                                            let tls_io = frp_core::transport::IoStream::Tls(Box::new(tls_stream));

                                            // After TLS: if tcpMux, wrap in yamux before V2/V1
                                            // (matching Go frps: TLS accept → yamux → V2/V1 on yamux stream).
                                            if state.tcp_mux {
                                                let mux_cfg = frp_core::mux::TcpMuxConfig {
                                                    keepalive_interval: std::time::Duration::from_secs(
                                                        state.tcp_mux_keepalive.max(1) as u64
                                                    ),
                                                };
                                                match frp_core::mux::server_mux(tls_io, &mux_cfg).await {
                                                    Ok((control_stream, incoming)) => {
                                                        let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                        tracing::info!(peer = %peer, "KCP TLS+yamux session established for {}", peer);

                                                        let mut yamux_magic = [0u8; 7];
                                                        let is_v2 = match io.read_exact(&mut yamux_magic).await {
                                                            Ok(_) => is_v2_magic(&yamux_magic),
                                                            Err(_) => false,
                                                        };
                                                        if is_v2 {
                                                            let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                                Ok((Some(p), crypto)) => (p, crypto),
                                                                Ok((None, crypto)) => {
                                                                    match io.read_raw_v2_frame().await {
                                                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                        Ok((ft, _, _)) => {
                                                                            tracing::warn!(frame_type = ?ft, peer = %peer, "KCP TLS+yamux V2: unexpected frame type {}", ft);
                                                                            return;
                                                                        }
                                                                        Err(e) => {
                                                                            tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux V2: read error: {}", e);
                                                                            return;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux V2 handshake error: {}", e);
                                                                    return;
                                                                }
                                                            };
                                                            let peer_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state, peer_addr, Some(incoming), None, crypto_ctx).await;
                                                        } else {
                                                            let mut io = frp_core::transport::IoStream::BufferedRead(yamux_magic.to_vec(), 0, Box::new(io));
                                                            match frp_core::protocol::read_msg_v1(&mut io).await {
                                                                Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                                                    tracing::info!(peer = %peer, "KCP TLS+yamux Login from {}", peer);
                                                                    control::handle_control(io, login, state, Some(peer), Some(incoming), false, None).await;
                                                                }
                                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                    tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP TLS+yamux NewWorkConn from {}", peer);
                                                                    crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                                                }
                                                                Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc)) => {
                                                                    tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP TLS+yamux NewVisitorConn from {}", peer);
                                                                    crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                                                }
                                                                Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv)) => {
                                                                    tracing::info!(peer = %peer, "KCP TLS+yamux NatHoleVisitor from {}", peer);
                                                                    crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                                }
                                                                Ok(other) => {
                                                                    tracing::warn!(peer = %peer, other = ?other.v1_type_byte(), "Unexpected KCP TLS+yamux message: {:?}", other.v1_type_byte());
                                                                }
                                                                Err(e) => {
                                                                    tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux read error: {}", e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(peer = %peer, error = %e, "KCP TLS+yamux server error: {}", e);
                                                    }
                                                }
                                                return;
                                            }

                                            // tcpMux disabled: V2/V1 directly on TLS-decrypted stream
                                            let mut ctl = tls_io;

                                            // After TLS: detect V2 then V1 on the decrypted stream
                                            let mut tls_magic = [0u8; 7];
                                            let is_v2 = match ctl.read_exact(&mut tls_magic).await {
                                                Ok(_) => is_v2_magic(&tls_magic),
                                                Err(_) => false,
                                            };
                                            if is_v2 {
                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        match ctl.read_raw_v2_frame().await {
                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                            Ok((ft, _, _)) => {
                                                                tracing::warn!(frame_type = ?ft, "KCP TLS V2: unexpected frame type {} after handshake", ft);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(error = %e, "KCP TLS V2: failed to read message after handshake: {}", e);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(error = %e, "KCP TLS V2 handshake error: {}", e);
                                                        return;
                                                    }
                                                };
                                                let peer_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0);
                                                crate::handlers::dispatch_v2_message(ctl, msg_payload, state, peer_addr, None, None, crypto_ctx).await;
                                            } else {
                                                // After KCP TLS handshake, Go frpc's decrypted stream
                                                // starts with non-FRP bytes (TLS Finished verify_data
                                                // or other post-handshake data that rustls doesn't
                                                // fully consume). The actual V1 Login/NewWorkConn
                                                // message follows in subsequent TLS records.
                                                //
                                                // Accumulate data across TLS records until we find
                                                // a valid V1 header or reach 2 KiB without one.
                                                let mut scan_data = tls_magic.to_vec();
                                                fn is_v1_type_byte(b: u8) -> bool {
                                                    b.is_ascii_alphanumeric() || matches!(b, 0x40..=0x42)
                                                }
                                                let find_v1 = |data: &[u8]| -> Option<usize> {
                                                    data.windows(9).position(|w| {
                                                        is_v1_type_byte(w[0])
                                                            && u64::from_be_bytes([
                                                                w[1], w[2], w[3], w[4],
                                                                w[5], w[6], w[7], w[8],
                                                            ]) <= frp_core::protocol::V1_MAX_MSG_LENGTH as u64
                                                    })
                                                };

                                                // Keep reading TLS records until we find a V1 header
                                                // or run out of data. Each read() returns one TLS
                                                // record's plaintext; Go frpc sends a small prefix
                                                // record (~12 bytes) then the Login record (~200 bytes).
                                                let v1_offset = loop {
                                                    if let Some(off) = find_v1(&scan_data) {
                                                        break Some(off);
                                                    }
                                                    if scan_data.len() > 2048 {
                                                        break None;
                                                    }
                                                    let mut buf = vec![0u8; 1024];
                                                    match ctl.read(&mut buf).await {
                                                        Ok(n) if n > 0 => {
                                                            scan_data.extend_from_slice(&buf[..n]);
                                                        }
                                                        Ok(_) => break None, // EOF
                                                        Err(e) => {
                                                            tracing::debug!(peer = %peer, error = %e, "KCP TLS: read error during scan");
                                                            break None;
                                                        }
                                                    }
                                                };

                                                let scan_len = scan_data.len();
                                                match v1_offset {
                                                    Some(off) => {
                                                        tracing::debug!(peer = %peer, offset = off, scan_len, "KCP TLS: found V1 message at offset {} ({} bytes scanned)", off, scan_len);
                                                        let mut ctl = frp_core::transport::IoStream::BufferedRead(
                                                            scan_data[off..].to_vec(), 0, Box::new(ctl),
                                                        );
                                                        match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                                            Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                                                tracing::info!(peer = %peer, "KCP TLS Login from {}", peer);
                                                                control::handle_control(ctl, login, state, None, None, false, None).await;
                                                            }
                                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                                tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP TLS NewWorkConn from {}", peer);
                                                                crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                                                            }
                                                            Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc)) => {
                                                                tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP TLS NewVisitorConn from {}", peer);
                                                                crate::handlers::handle_visitor_conn_inner(ctl, nvc, state, false).await;
                                                            }
                                                            Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv)) => {
                                                                tracing::info!(peer = %peer, "KCP TLS NatHoleVisitor from {}", peer);
                                                                crate::handlers::handle_nat_hole_visitor(ctl, nhv, state, None, false).await;
                                                            }
                                                            Ok(other) => {
                                                                tracing::warn!(other = ?other.v1_type_byte(), "Unexpected KCP TLS message: {:?}", other.v1_type_byte());
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(error = %e, "KCP TLS read error: {}", e);
                                                            }
                                                        }
                                                    }
                                                    None => {
                                                        tracing::warn!(peer = %peer, scan_len, scan_hex = %data_encoding::HEXLOWER.encode(&scan_data[..scan_len.min(128)]), "KCP TLS: no valid V1 header found in {} bytes", scan_len);
                                                    }
                                                }
                                            }
                                        }
                                        #[cfg(not(feature = "tls"))]
                                        {
                                            tracing::warn!("KCP TLS connection requires TLS feature (disabled in this build)");
                                        }
                                    } else if state.tcp_mux {
                                        // tcp_mux enabled: Go frpc wraps KCP conn in yamux
                                        // before sending Login (matching Go frps flow).
                                        // Replay the 7 bytes consumed by magic check —
                                        // they are part of the yamux SYN header.
                                        let stream = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));
                                        let mux_cfg = frp_core::mux::TcpMuxConfig {
                                            keepalive_interval: std::time::Duration::from_secs(
                                                state.tcp_mux_keepalive.max(1) as u64
                                            ),
                                        };
                                        match frp_core::mux::server_mux(stream, &mux_cfg).await {
                                            Ok((control_stream, incoming)) => {
                                                let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                tracing::info!(peer = %peer, "KCP yamux session established for {}", peer);

                                                // V2 magic detection on yamux stream
                                                let mut yamux_magic = [0u8; 7];
                                                let is_v2 = match io.read_exact(&mut yamux_magic).await {
                                                    Ok(_) => is_v2_magic(&yamux_magic),
                                                    Err(_) => false,
                                                };
                                                if is_v2 {
                                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                        Ok((None, crypto)) => {
                                                            match io.read_raw_v2_frame().await {
                                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                Ok((ft, _, _)) => {
                                                                    tracing::warn!(frame_type = ?ft, peer = %peer, "KCP yamux V2: unexpected frame type {}", ft);
                                                                    return;
                                                                }
                                                                Err(e) => {
                                                                    tracing::warn!(peer = %peer, error = %e, "KCP yamux V2: read error: {}", e);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(peer = %peer, error = %e, "KCP yamux V2 handshake error: {}", e);
                                                            return;
                                                        }
                                                    };
                                                    crate::handlers::dispatch_v2_message(io, msg_payload, state, peer, Some(incoming), None, crypto_ctx).await;
                                                } else {
                                                    // V1 on yamux: replay consumed bytes, read Login/NewWorkConn
                                                    let mut io = frp_core::transport::IoStream::BufferedRead(yamux_magic.to_vec(), 0, Box::new(io));
                                                    match frp_core::protocol::read_msg_v1(&mut io).await {
                                                        Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                                            tracing::info!(peer = %peer, "KCP yamux Login from {}", peer);
                                                            control::handle_control(io, login, state, Some(peer), Some(incoming), false, None).await;
                                                        }
                                                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                            tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP yamux NewWorkConn from {}", peer);
                                                            crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                                        }
                                                        Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc)) => {
                                                            tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP yamux NewVisitorConn from {}", peer);
                                                            crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                                        }
                                                        Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv)) => {
                                                            tracing::info!(peer = %peer, "KCP yamux NatHoleVisitor from {}", peer);
                                                            crate::handlers::handle_nat_hole_visitor(io, nhv, state, None, false).await;
                                                        }
                                                        Ok(other) => {
                                                            tracing::warn!(peer = %peer, other = ?other.v1_type_byte(), "Unexpected KCP yamux message: {:?}", other.v1_type_byte());
                                                        }
                                                        Err(e) => {
                                                            tracing::warn!(peer = %peer, error = %e, "KCP yamux read error: {}", e);
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(peer = %peer, error = %e, "KCP yamux server error: {}", e);
                                            }
                                        }
                                    } else {
                                        // No tcp_mux: replay consumed 7 bytes, read V1 frame directly
                                        let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));
                                        match frp_core::protocol::read_msg_v1(&mut ctl).await {
                                            Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                                tracing::info!(peer = %peer, "KCP Login from {}", peer);
                                                control::handle_control(ctl, login, state, None, None, false, None).await;
                                            }
                                            Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                tracing::info!(peer = %peer, run_id = ?nwc.run_id, "KCP NewWorkConn from {}", peer);
                                                crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                                            }
                                            Ok(frp_core::msg::FrpMessage::NewVisitorConn(nvc)) => {
                                                tracing::info!(peer = %peer, proxy_name = %nvc.proxy_name, "KCP NewVisitorConn from {}", peer);
                                                crate::handlers::handle_visitor_conn_inner(ctl, nvc, state, false).await;
                                            }
                                            Ok(frp_core::msg::FrpMessage::NatHoleVisitor(nhv)) => {
                                                tracing::info!(peer = %peer, "KCP NatHoleVisitor from {}", peer);
                                                crate::handlers::handle_nat_hole_visitor(ctl, nhv, state, None, false).await;
                                            }
                                            Ok(other) => {
                                                tracing::warn!(other = ?other.v1_type_byte(), "Unexpected KCP message: {:?}", other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                tracing::warn!(error = %e, "KCP read error: {}", e);
                                            }
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "KCP accept error: {}", e);
                            break 'kcp_accept;
                        }
                    }
                    }
                    _ = kcp_state.shutdown_token.cancelled() => break 'kcp_accept,
                }
                }
            });
            tracing::info!(addr = %kcp_addr, "KCP listener starting on {}", kcp_addr);
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
                        tracing::error!(cert_path = %cert_path, error = %e, "QUIC: failed to read cert file {}: {}", cert_path, e);
                        return;
                    }
                };
                let key_pem = match std::fs::read_to_string(&key_path) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(key_path = %key_path, error = %e, "QUIC: failed to read key file {}: {}", key_path, e);
                        return;
                    }
                };
                let sockaddr: std::net::SocketAddr = match quic_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(addr = %quic_addr, error = %e, "QUIC: invalid bind address {}: {}", quic_addr, e);
                        return;
                    }
                };
                let listener = match frp_core::quic::QuicListener::new(sockaddr, &cert_pem, &key_pem) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(error = %e, "QUIC listener bind failed: {}", e);
                        return;
                    }
                };
                tracing::info!(addr = %quic_addr, "QUIC listener started on {}", quic_addr);
                'quic_accept: loop {
                    tokio::select! {
                        result = listener.accept() => {
                            match result {
                                Ok(conn) => {
                                    let state = quic_state.clone();
                                    let quic_addr = conn.remote_address();
                                    let permit = state.conn_semaphore.as_ref()
                                        .and_then(|s| s.clone().try_acquire_owned().ok());
                                    if permit.is_none() && state.conn_semaphore.is_some() {
                                        warn!(addr = %quic_addr, "Max connections reached, rejecting QUIC from {}", quic_addr);
                                        continue;
                                    }
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        // Accept first bidirectional stream (control channel).
                                        // This is inside the handler, not in the accept loop —
                                        // matching Go frp's HandleQUICListener pattern where
                                        // the accept loop never blocks on a stream.
                                        let stream = match conn.accept_bi().await {
                                            Ok(s) => s,
                                            Err(e) => {
                                                tracing::warn!(error = %e, "QUIC: failed to accept first stream: {e}");
                                                return;
                                            }
                                        };
                                        handle_quic_stream(stream, conn, state).await;
                                    });
                                }
                        Err(e) => {
                            tracing::error!(error = %e, "QUIC accept error: {e}");
                            tracing::info!("QUIC accept loop shut down due to error");
                            break 'quic_accept;
                        }
                    }
                    }
                    _ = quic_state.shutdown_token.cancelled() => {
                        tracing::debug!("QUIC accept loop: shutdown requested");
                        break 'quic_accept;
                    }
                }
                }
                tracing::info!("QUIC accept loop shut down gracefully");
            });
            tracing::info!(addr = %quic_addr2, "QUIC listener starting on {}", quic_addr2);
        }

        /// Handle a QUIC stream (control or work connection).
        /// Accepts the first bidirectional stream from `conn`, then runs
        /// V1/V2 protocol detection and dispatch. Spawns a drain task to
        /// accept additional streams as work connections.
        #[cfg(feature = "quic")]
        async fn handle_quic_stream(
            first_stream: frp_core::quic::QuicStream,
            conn: frp_core::quic::QuicConnection,
            state: Arc<AppState>,
        ) {
            let mut ctl = frp_core::transport::IoStream::Quic(first_stream);

            // Try V2 magic detection on first stream.
            // Per-stream independence: each QUIC stream gets its own
            // V2 detection, matching Go frp's WriteMagicIfV2() per stream.
            let mut magic = [0u8; 7];
            let is_v2 = match ctl.read_exact(&mut magic).await {
                Ok(_) => is_v2_magic(&magic),
                Err(_) => false,
            };

            if is_v2 {
                // --- V2 path ---
                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                    Ok((Some(p), crypto)) => (p, crypto),
                    Ok((None, crypto)) => {
                        match ctl.read_raw_v2_frame().await {
                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                            Ok((ft, _, _)) => {
                                tracing::warn!(frame_type = ?ft, "QUIC V2: unexpected frame type {} after handshake", ft);
                                return;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "QUIC V2: failed to read message after handshake: {}", e);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "QUIC V2 handshake error: {}", e);
                        return;
                    }
                };

                let addr: std::net::SocketAddr = conn.remote_address();
                let cancel = spawn_quic_drain(conn, Arc::clone(&state), "V2");
                crate::handlers::dispatch_v2_message(ctl, msg_payload, state, addr, None, None, crypto_ctx).await;
                cancel.cancel();
            } else {
                // --- V1 fallback ---
                let mut ctl = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));

                match frp_core::protocol::read_msg_v1(&mut ctl).await {
                    Ok(frp_core::msg::FrpMessage::Login(login)) => {
                        let cancel = spawn_quic_drain(conn, Arc::clone(&state), "V1");
                        control::handle_control(ctl, login, state, None, None, false, None).await;
                        cancel.cancel();
                    }
                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                        crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                    }
                    Ok(other) => {
                        tracing::warn!(other = ?other.v1_type_byte(), "Unexpected QUIC message: {:?}", other.v1_type_byte());
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "QUIC read error: {}", e);
                    }
                }
            }
        }

        /// Spawn a drain task that accepts additional QUIC streams as work connections.
        /// Returns a `CancellationToken` — call `.cancel()` to stop the drain loop.
        #[cfg(feature = "quic")]
        fn spawn_quic_drain(
            conn: frp_core::quic::QuicConnection,
            state: Arc<AppState>,
            tag: &'static str,
        ) -> CancellationToken {
            let cancel = CancellationToken::new();
            let drain_cancel = cancel.clone();
            let drain_conn = conn;
            tokio::spawn(async move {
                tracing::debug!(tag, "QUIC drain ({tag}) started");
                loop {
                    tokio::select! {
                        _ = drain_cancel.cancelled() => {
                            tracing::debug!(tag, "QUIC drain ({tag}) cancelled");
                            break;
                        }
                        result = drain_conn.accept_bi() => {
                            match result {
                                Ok(work_stream) => {
                                    tracing::debug!(tag, "QUIC drain ({tag}): accepted new stream");
                                    let s = Arc::clone(&state);
                                    tokio::spawn(async move {
                                        let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                        let mut wmagic = [0u8; 7];
                                        let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                            Ok(_) => is_v2_magic(&wmagic),
                                            Err(_) => false,
                                        };
                                        if w_is_v2 {
                                            match wc.read_v2_frame().await {
                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                }
                                                Ok(other) => {
                                                    tracing::warn!(msg_type_id = ?other.v2_type_id(), "QUIC drain: unexpected V2 msg type_id={:?}", other.v2_type_id());
                                                }
                                                Err(e) => {
                                                    tracing::warn!(error = %e, "QUIC drain: V2 read error: {}", e);
                                                }
                                            }
                                        } else {
                                            let mut wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                            match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                                                    crate::handlers::handle_work_conn_inner(wc, nwc, s).await;
                                                }
                                                Ok(other) => {
                                                    tracing::warn!(msg_type_byte = ?other.v1_type_byte(), "QUIC drain: unexpected V1 msg type_byte={:?}", other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    tracing::warn!(error = %e, "QUIC drain: V1 read error: {}", e);
                                                }
                                            }
                                        }
                                    });
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, tag, "QUIC drain ({tag}) done: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            cancel
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
            let enable_prom = self.cfg.web_server.enable_prometheus;
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(
                    dash_addr, dash_state, dash_user, dash_pwd,
                    enable_prom, dash_tls_cert, dash_tls_key,
                ).await {
                    tracing::error!(error = %e, "Dashboard server failed: {}", e);
                }
            });
            tracing::info!(addr = %dash_addr2, "Dashboard web UI starting on {}", dash_addr2);
        }

        // Background cleanup for stale NAT hole punch sessions.
        // Sessions should normally be completed by the provider's NatHoleReport,
        // but if the provider crashes or the network drops, this ensures sessions
        // older than 2 minutes don't leak memory.
        let nat_hole = self.state.xtcp.nat_hole.clone();
        let nat_shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        nat_hole.expire_sessions(Duration::from_secs(120)).await;
                        // Clean expired analyzer entries to prevent unbounded memory growth.
                        let (removed, total) = nat_hole.analyzer.clean();
                        if removed > 0 {
                            tracing::debug!(removed = %removed, total = %total, "Analyzer cleanup: removed {}/{} expired entries", removed, total);
                        }
                    }
                    _ = nat_shutdown_token.cancelled() => {
                        tracing::debug!("NAT cleanup task: shutdown requested, stopping");
                        break;
                    }
                }
            }
        });

        // Periodic TLS certificate hot-reload: stat cert/key files every 60 seconds.
        // When mtimes change (e.g., certbot/cert-manager renews in-place), rebuild
        // the acceptor and atomically swap so new connections use the new cert
        // without a restart.
        #[cfg(feature = "tls")]
        {
            let poll_state = self.state.clone();
            let cert_file = self.cfg.tls_cert_file.clone();
            let key_file = self.cfg.tls_key_file.clone();
            let ca_file = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.clone())
            };
            tokio::spawn(async move {
                let mut last_cert_mtime: Option<std::time::SystemTime> = None;
                let mut last_key_mtime: Option<std::time::SystemTime> = None;
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                // Skip the first tick (fires immediately).
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            // Stat cert and key files. If either mtime changed, rebuild.
                            let cert_meta = match std::fs::metadata(&cert_file) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let key_meta = match std::fs::metadata(&key_file) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let cert_mtime = cert_meta.modified().ok();
                            let key_mtime = key_meta.modified().ok();
                            let cert_changed = cert_mtime != last_cert_mtime;
                            let key_changed = key_mtime != last_key_mtime;
                            if cert_changed || key_changed {
                                last_cert_mtime = cert_mtime;
                                last_key_mtime = key_mtime;
                                let ca = ca_file.as_deref();
                                match build_tls_acceptor_or_generate(&cert_file, &key_file, ca) {
                                    Ok(new_acceptor) => {
                                        let mut guard = poll_state.tls_acceptor.write_ok();
                                        *guard = Some(new_acceptor);
                                        tracing::info!(
                                            "TLS certificate hot-reloaded (cert: {}, key: {})",
                                            cert_file,
                                            key_file
                                        );
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to reload TLS certificate: {} (keeping old config)",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        _ = poll_state.shutdown_token.cancelled() => {
                            tracing::debug!("TLS hot-reload task: shutdown requested, stopping");
                            break;
                        }
                    }
                }
            });
        }

        // Main accept loop — mixed-mode: TLS, WebSocket, and V1 on same port.
        // Uses MSG_PEEK to detect connection type without consuming bytes,
        // matching Go frp v0.69.1 behavior.

        // Spawn ctrl_c listener for graceful shutdown.
        // tokio::signal::ctrl_c() catches both SIGINT and SIGTERM on Unix.
        let shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            info!("Received SIGINT/SIGTERM, initiating graceful shutdown...");
            shutdown_token.cancel();
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                Ok((stream, addr)) => {
                    let state = self.state.clone();
                    #[cfg(feature = "tls")]
                    let acceptor = state.tls_acceptor.read_ok().clone();

                    let permit = state.conn_semaphore.as_ref()
                        .and_then(|s| s.clone().try_acquire_owned().ok());
                    if permit.is_none() && state.conn_semaphore.is_some() {
                        warn!(addr = %addr, "Max connections reached, rejecting connection from {}", addr);
                        continue;
                    }
                    tokio::spawn(async move {
                        let _permit = permit;
                        let (ct, mut stream_io) = match detect_and_strip_magic(stream).await {
                            Ok((c, s)) => (c, s),
                            Err(e) => {
                                warn!(addr = %addr, error = %e, "Failed to detect connection type from {}: {}", addr, e);
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
                                        warn!(addr = %addr, "Expected PreRead for TLS connection from {}", addr);
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
                                        warn!(addr = %addr, "TLS read timeout from {} during SNI check", addr);
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
                                        debug!(addr = %addr, sni_host = %sni_host, "SNI from {}: {}", addr, sni_host);
                                        if let Some(route) = state.vhost_manager.lookup(&sni_host).await {
                                            let ctl_tx = {
                                                let map = state.run_id_to_ctl_tx.read().await;
                                                map.get(&route.run_id).cloned()
                                            };
                                            if let Some(ctl) = ctl_tx {
                                                info!(sni_host = %sni_host, proxy_name = %route.proxy_name, addr = %addr,
                                                    "SNI route '{}' → HTTPS proxy '{}' from {}",
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

                                // No SNI match — check acceptor before creating stream.
                                let acceptor = match acceptor {
                                    Some(a) => a,
                                    None => {
                                        // Go frp compat: Go frpc sends 0x17 (FRP_TLS_HEAD_BYTE)
                                        // by default even without TLS configured. Go frps
                                        // falls back to plain TCP via CheckAndEnableTLSServerConnWithTimeout.
                                        // Match that behavior: when the first byte is 0x17 and TLS
                                        // is not configured, strip 0x17 (already done above) and
                                        // treat the remaining data as V1.
                                        if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
                                            info!(addr = %addr, "TLS head byte (0x17) but TLS not configured, falling back to V1");
                                            // sni_data contains the bytes after 0x17 (pre_read
                                            // minus 0x17 + SNI peek). Replay them via PreRead
                                            // and dispatch as V1.
                                            let mut stream = IoStream::PreRead(sni_data, inner_stream);
                                            match read_msg_v1(&mut stream).await {
                                                Ok(FrpMessage::Login(login)) => {
                                                    control::handle_control(stream, login, state, Some(addr), None, false, None).await;
                                                }
                                                Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                    crate::handlers::handle_work_conn_inner(stream, nwc, state).await;
                                                }
                                                Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                    crate::handlers::handle_visitor_conn_inner(stream, nvc, state, false).await;
                                                }
                                                Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                    crate::handlers::handle_nat_hole_visitor(stream, nhv, state, Some(addr.to_string()), false).await;
                                                }
                                                Ok(other) => {
                                                    warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after 0x17 fallback from {}: {:?}", addr, other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "V1 read error after 0x17 fallback from {}: {}", addr, e);
                                                }
                                            }
                                            return;
                                        }
                                        // 0x16 (standard TLS ClientHello) — genuine TLS,
                                        // can't fall back to V1.
                                        warn!(addr = %addr, "TLS connection from {} but TLS not configured", addr);
                                        return;
                                    }
                                };

                                // TLS acceptor exists — wrap stream to replay consumed bytes
                                // for the TLS handshake.
                                let stream = PreReadStream::new(sni_data, inner_stream);
                                let tls_stream = match acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "TLS handshake failed from {}: {}", addr, e);
                                        return;
                                    }
                                };
                                info!(addr = %addr, "TLS connection from {}", addr);

                                // Wrap TLS stream for unified V2/V1/WS handling.
                                let mut io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls_stream)));

                                // Peek for WebSocket upgrade inside TLS (Go frp 'ws'
                                // transport sends TLS ClientHello first, then WebSocket
                                // upgrade inside the TLS tunnel).
                                //
                                // Two-phase detection to avoid false positives from
                                // health checks, scanners, and other non-frp HTTP
                                // clients that connect to the frps TLS port.
                                let mut ws_peek = vec![0u8; 4];
                                let got_http = match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    io.read_exact(&mut ws_peek[..4]),
                                ).await {
                                    Ok(Ok(n)) if n >= 4 => &ws_peek[..4] == b"GET ",
                                    _ => false,
                                };

                                // Secondary validation: read more bytes and confirm
                                // WebSocket upgrade headers are present before committing
                                // to the WS path (which sends a 101 response and cannot
                                // be undone).
                                #[cfg(feature = "websocket")]
                                let is_ws_tls = if got_http {
                                    ws_peek.resize(1024, 0);
                                    let extra = match tokio::time::timeout(
                                        std::time::Duration::from_millis(500),
                                        io.read(&mut ws_peek[4..]),
                                    ).await {
                                        Ok(Ok(n)) => n,
                                        _ => 0,
                                    };
                                    ws_peek.truncate(4 + extra);
                                    let data = String::from_utf8_lossy(&ws_peek);
                                    let lower = data.to_lowercase();
                                    lower.contains("upgrade: websocket")
                                        && lower.contains("sec-websocket-key:")
                                } else {
                                    false
                                };
                                #[cfg(not(feature = "websocket"))]
                                let is_ws_tls = false;

                                #[cfg(feature = "websocket")]
                                if is_ws_tls {
                                    // WebSocket upgrade over TLS (Go frpc ws transport).
                                    // accept_websocket_from_peeked replays pipelined bytes
                                    // through a single BufferedRead layer (no BufReader),
                                    // which preserves the read position on TLS streams —
                                    // `ws_peek` here is already TLS-decrypted plaintext.
                                    match accept_websocket_from_peeked(ws_peek, io).await {
                                        Ok(mut ws) => {
                                            info!(addr = %addr, "WebSocket upgrade over TLS for {}", addr);
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match ws.read_exact(&mut magic).await {
                                                Ok(_) => {
                                                    is_v2_magic(&magic)
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "WS+TLS failed to read first 7 bytes: {}", e);
                                                    return;
                                                }
                                            };
                                            if is_v2 {
                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ws).await {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        match ws.read_raw_v2_frame().await {
                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                            Ok((ft, _, _)) => {
                                                                warn!(frame_type = ?ft, addr = %addr, "WS+TLS V2: unexpected frame type {} from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "WS+TLS V2: failed to read message: {}", e);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "WS+TLS V2 handshake error: {}", e);
                                                        return;
                                                    }
                                                };
                                                crate::handlers::dispatch_v2_message(ws, msg_payload, state, addr, None, None, crypto_ctx).await;
                                            } else if magic[0] == 0x00 {
                                                // yamux over WebSocket (Go frp tcpMux + wss).
                                                // First byte 0x00 = yamux version; the 7-byte peek
                                                // contains the start of a yamux WindowUpdate+SYN frame.
                                                let ws = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                let mux_cfg = mux::TcpMuxConfig {
                                                    keepalive_interval: std::time::Duration::from_secs(
                                                        state.tcp_mux_keepalive.max(1) as u64
                                                    ),
                                                };
                                                match mux::server_mux(ws, &mux_cfg).await {
                                                    Ok((control_stream, incoming)) => {
                                                        let mut io = IoStream::Yamux(control_stream);
                                                        info!(addr = %addr, "Yamux over WS+TLS session established for {}", addr);

                                                        // Try V2 detection on yamux stream
                                                        let mut v2_magic = [0u8; 7];
                                                        let is_v2 = match io.read_exact(&mut v2_magic).await {
                                                            Ok(_) => is_v2_magic(&v2_magic),
                                                            Err(_) => false,
                                                        };
                                                        if is_v2 {
                                                            let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                                Ok((Some(p), crypto)) => (p, crypto),
                                                                Ok((None, crypto)) => {
                                                                    match io.read_raw_v2_frame().await {
                                                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                        Ok((ft, _, _)) => {
                                                                            warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                            return;
                                                                        }
                                                                        Err(e) => {
                                                                            warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message: {}", e);
                                                                            return;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                    return;
                                                                }
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                                        } else {
                                                            let mut io = IoStream::BufferedRead(v2_magic.to_vec(), 0, Box::new(io));
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
                                                                    warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 after WS+TLS+yamux: {:?}", other.v1_type_byte());
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "V1 read error after WS+TLS+yamux: {}", e);
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "Failed to start yamux over WS+TLS for {}: {}", addr, e);
                                                    }
                                                }
                                            } else {
                                                let mut ws = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                match read_msg_v1(&mut ws).await {
                                                    Ok(FrpMessage::Login(login)) => {
                                                        control::handle_control(ws, login, state, Some(addr), None, false, None).await;
                                                    }
                                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                        crate::handlers::handle_work_conn_inner(ws, nwc, state).await;
                                                    }
                                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                        crate::handlers::handle_visitor_conn_inner(ws, nvc, state, false).await;
                                                    }
                                                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                        crate::handlers::handle_nat_hole_visitor(ws, nhv, state, None, false).await;
                                                    }
                                                    Ok(other) => {
                                                        warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 after WS+TLS: {:?}", other.v1_type_byte());
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "V1 read error after WS+TLS: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "WebSocket upgrade over TLS failed: {}", e);
                                        }
                                    }
                                    return;
                                }

                                // Not WebSocket — replay peeked bytes.
                                let mut io = IoStream::BufferedRead(ws_peek, 0, Box::new(io));

                                // When tcp_mux is enabled, wrap TLS stream in yamux
                                // before reading the first message (matches Go frp).
                                if state.tcp_mux {
                                    let mux_cfg = mux::TcpMuxConfig {
                                        keepalive_interval: std::time::Duration::from_secs(
                                            state.tcp_mux_keepalive.max(1) as u64
                                        ),
                                    };
                                    match mux::server_mux(io, &mux_cfg).await {
                                        Ok((control_stream, incoming)) => {
                                            let mut io = IoStream::Yamux(control_stream);
                                            info!(addr = ?addr, "Yamux over TLS session established for {:?}", addr);

                                            // Try V2 detection on yamux stream (Go frp: magic on stream)
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                Ok(_) => is_v2_magic(&magic),
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
                                                                warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 TLS+yamux handshake from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                            warn!(addr = %addr, error = %e, "Failed to read V2 message after TLS+yamux handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "V2 TLS+yamux handshake error from {}: {}", addr, e);
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
                                                        warn!(addr = ?addr, other = ?other.v1_type_byte(), "Unexpected TLS+yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "TLS+yamux read error from {}: {}", addr, e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = ?addr, error = %e, "Failed to start yamux over TLS for {:?}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    // io already includes peeked bytes via BufferedRead.
                                    // Proceed with V2/V1 detection on the TLS stream.
                                    // Try V2 magic detection
                                    let mut magic = [0u8; 7];
                                    let is_v2 = match io.read_exact(&mut magic).await {
                                        Ok(_) => is_v2_magic(&magic),
                                        Err(_) => false,
                                    };

                                    if is_v2 {
                                        // V2 path: ClientHello/ServerHello handshake
                                        let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                            Ok((Some(p), crypto)) => (p, crypto),
                                            Ok((None, crypto)) => {
                                                match io.read_raw_v2_frame().await {
                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                    Ok((ft, _, _)) => {
                                                        tracing::warn!(frame_type = ?ft, addr = %addr, "TLS V2: unexpected frame type {} after handshake from {}", ft, addr);
                                                        return;
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(addr = %addr, error = %e, "TLS V2: failed to read message after handshake from {}: {}", addr, e);
                                                        return;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::warn!(addr = %addr, error = %e, "TLS V2 handshake error from {}: {}", addr, e);
                                                return;
                                            }
                                        };
                                        // Pass visitor_addr to match V1 TLS plain behavior for NatHoleVisitor
                                        crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, None, Some(addr.to_string()), crypto_ctx).await;
                                    } else {
                                        // V1 fallback: replay consumed 7 bytes
                                        let mut io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                        match read_msg_v1(&mut io).await {
                                            Ok(FrpMessage::Login(login)) => {
                                                control::handle_control(io, login, state, Some(addr), None, false, None).await;
                                            }
                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                crate::handlers::handle_work_conn_inner(io, nwc, state).await;
                                            }
                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                crate::handlers::handle_visitor_conn_inner(io, nvc, state, false).await;
                                            }
                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                let visitor_addr = Some(addr.to_string());
                                                crate::handlers::handle_nat_hole_visitor(io, nhv, state, visitor_addr, false).await;
                                            }
                                            Ok(other) => {
                                                debug!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected TLS first message from {}: {:?}", addr, other.v1_type_byte());
                                            }
                                            Err(e) => {
                                                debug!(addr = %addr, error = %e, "TLS read error from {}: {}", addr, e);
                                            }
                                        }
                                    }
                                }
                            }

                            #[cfg(not(feature = "tls"))]
                            ConnectionType::Tls(first_byte) => {
                                // Go frp compat: when TLS feature is not compiled in
                                // but frpc sends 0x17 prefix, fall back to V1.
                                if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE {
                                    let (mut pre_read_bytes, inner_stream) = match stream_io {
                                        IoStream::PreRead(buf, s) => (buf, s),
                                        _ => {
                                            warn!(addr = %addr, "Expected PreRead for 0x17 connection from {}", addr);
                                            return;
                                        }
                                    };
                                    // Strip 0x17 (Go frp TLS head byte).
                                    if !pre_read_bytes.is_empty() {
                                        pre_read_bytes.remove(0);
                                    }
                                    info!(addr = %addr, "TLS head byte (0x17) but TLS feature not enabled, falling back to V1");
                                    let mut stream = IoStream::PreRead(pre_read_bytes, inner_stream);
                                    match read_msg_v1(&mut stream).await {
                                        Ok(FrpMessage::Login(login)) => {
                                            control::handle_control(stream, login, state, Some(addr), None, false, None).await;
                                        }
                                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                                            crate::handlers::handle_work_conn_inner(stream, nwc, state).await;
                                        }
                                        Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                            crate::handlers::handle_visitor_conn_inner(stream, nvc, state, false).await;
                                        }
                                        Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                            crate::handlers::handle_nat_hole_visitor(stream, nhv, state, Some(addr.to_string()), false).await;
                                        }
                                        Ok(other) => {
                                            warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after 0x17 fallback from {}: {:?}", addr, other.v1_type_byte());
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "V1 read error after 0x17 fallback from {}: {}", addr, e);
                                        }
                                    }
                                    return;
                                }
                                warn!(addr = %addr, "TLS connection from {} but TLS feature not enabled", addr);
                            }

                            #[cfg(feature = "websocket")]
                            ConnectionType::WebSocket => {
                                if state.tls_only {
                                    warn!(addr = %addr, "TLS-only mode: rejected WebSocket from {}", addr);
                                    return;
                                }
                                // stream_io is IoStream::PreRead — its AsyncRead replays
                                // the 7 consumed bytes (starting with 'G' for GET).
                                match accept_websocket(stream_io).await {
                                    Ok(mut ws) => {
                                        info!(addr = %addr, "WebSocket upgrade on main port for {}", addr);

                                        // Try V2 magic detection
                                        let mut magic = [0u8; 7];
                                        let is_v2 = match ws.read_exact(&mut magic).await {
                                            Ok(_) => {
                                                let matches = is_v2_magic(&magic);
                                                debug!(
                                                    addr = %addr,
                                                    magic_hex = %magic.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""),
                                                    is_v2 = matches,
                                                    "WS post-upgrade first 7 bytes"
                                                );
                                                matches
                                            }
                                            Err(_) => false,
                                        };

                                        if is_v2 {
                                            // V2 path: ClientHello/ServerHello handshake
                                            let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ws).await {
                                                Ok((Some(p), crypto)) => (p, crypto),
                                                Ok((None, crypto)) => {
                                                    match ws.read_raw_v2_frame().await {
                                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                        Ok((ft, _, _)) => {
                                                            warn!(frame_type = ?ft, addr = %addr, "WS V2 (main): unexpected frame type {} after handshake from {}", ft, addr);
                                                            return;
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "WS V2 (main): failed to read message after handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "WS V2 (main) handshake error from {}: {}", addr, e);
                                                    return;
                                                }
                                            };
                                            crate::handlers::dispatch_v2_message(ws, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                        } else if magic[0] == 0x16 {
                                            // TLS-over-WebSocket: Go frpc (Docker default) sends
                                            // TLS ClientHello as first WebSocket frame payload.
                                            // Replay consumed bytes and wrap in TLS, matching
                                            // Go frps auto-generated cert behavior.
                                            #[cfg(feature = "tls")]
                                            {
                                                let tls_acceptor = match state.tls_acceptor.read_ok().clone() {
                                                    Some(a) => a,
                                                    None => {
                                                        warn!(addr = %addr, "TLS ClientHello in WS frame but TLS not configured");
                                                        return;
                                                    }
                                                };
                                                // Replay the 7 consumed payload bytes (TLS ClientHello
                                                // prefix), then delegate to WsByteStream for subsequent
                                                // WebSocket frames. The TLS handshake runs INSIDE the
                                                // WebSocket framing — ServerHello/Certificate/etc. are
                                                // wrapped in WS frames by WsByteStream.
                                                let stream = frp_core::transport::IoStream::BufferedRead(
                                                    magic.to_vec(), 0, Box::new(ws),
                                                );
                                                let tls_stream = match tls_acceptor.accept(stream).await {
                                                    Ok(s) => s,
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                                        return;
                                                    }
                                                };
                                                info!(addr = %addr, "TLS-over-WebSocket connection from {}", addr);

                                                // When tcp_mux is enabled, wrap TLS stream in yamux before
                                                // reading the first message (matches Go frp — Go frpc uses
                                                // tcp_mux by default over all transports, including
                                                // WebSocket-tunneled TLS).
                                                if state.tcp_mux {
                                                    let mux_cfg = mux::TcpMuxConfig {
                                                        keepalive_interval: std::time::Duration::from_secs(
                                                            state.tcp_mux_keepalive.max(1) as u64
                                                        ),
                                                    };
                                                    match mux::server_mux(tls_stream, &mux_cfg).await {
                                                        Ok((control_stream, incoming)) => {
                                                            let mut io = IoStream::Yamux(control_stream);
                                                            info!(addr = ?addr, "Yamux over WS+TLS session established for {:?}", addr);

                                                            // V2 detection on yamux stream
                                                            let mut magic = [0u8; 7];
                                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                                Ok(_) => is_v2_magic(&magic),
                                                                Err(_) => false,
                                                            };
                                                            if is_v2 {
                                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                                    Ok((None, crypto)) => {
                                                                        match io.read_raw_v2_frame().await {
                                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                            Ok((ft, _, _)) => {
                                                                                warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                return;
                                                                            }
                                                                            Err(e) => {
                                                                                warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message from {}: {}", addr, e);
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                };
                                                                crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                            } else {
                                                                // V1 over WS+TLS+yamux
                                                                let mut io = frp_core::transport::IoStream::BufferedRead(
                                                                    magic.to_vec(), 0, Box::new(io),
                                                                );
                                                                match read_msg_v1(&mut io).await {
                                                                    Ok(FrpMessage::Login(login)) => {
                                                                        control::handle_control(io, login, state.clone(), Some(addr), Some(incoming), false, None).await;
                                                                    }
                                                                    Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                                        crate::handlers::handle_work_conn_inner(io, nwc, state.clone()).await;
                                                                    }
                                                                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                                        crate::handlers::handle_visitor_conn_inner(io, nvc, state.clone(), false).await;
                                                                    }
                                                                    Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                                        crate::handlers::handle_nat_hole_visitor(io, nhv, state.clone(), None, false).await;
                                                                    }
                                                                    Ok(other) => {
                                                                        warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after WS+TLS+yamux from {}: {:?}", addr, other.v1_type_byte());
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "V1 read error after WS+TLS+yamux from {}: {}", addr, e);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                                                        }
                                                    }
                                                } else {
                                                    let mut io = IoStream::Tls(Box::new(tls_stream));

                                                    // V2 chicken check on the decrypted TLS stream
                                                    let mut chicken = [0u8; 7];
                                                    let is_tls_v2 = match io.read_exact(&mut chicken).await {
                                                        Ok(_) => is_v2_magic(&chicken),
                                                        Err(_) => false,
                                                    };
                                                    if is_tls_v2 {
                                                        let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                            Ok((Some(p), crypto)) => (p, crypto),
                                                            Ok((None, crypto)) => {
                                                                match io.read_raw_v2_frame().await {
                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                    Ok((ft, _, _)) => {
                                                                        warn!(frame_type = ?ft, addr = %addr, "WS+TLS+V2: unexpected frame type {} from {}", ft, addr);
                                                                        return;
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "WS+TLS+V2: failed to read message from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "WS+TLS+V2 handshake error from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        };
                                                        crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                                    } else {
                                                        // V1 over TLS-over-WS
                                                        let mut io = frp_core::transport::IoStream::BufferedRead(
                                                            chicken.to_vec(), 0, Box::new(io),
                                                        );
                                                        match read_msg_v1(&mut io).await {
                                                            Ok(FrpMessage::Login(login)) => {
                                                                control::handle_control(io, login, state.clone(), Some(addr), None, false, None).await;
                                                            }
                                                            Ok(FrpMessage::NewWorkConn(nwc)) => {
                                                                crate::handlers::handle_work_conn_inner(io, nwc, state.clone()).await;
                                                            }
                                                            Ok(FrpMessage::NewVisitorConn(nvc)) => {
                                                                crate::handlers::handle_visitor_conn_inner(io, nvc, state.clone(), false).await;
                                                            }
                                                            Ok(FrpMessage::NatHoleVisitor(nhv)) => {
                                                                crate::handlers::handle_nat_hole_visitor(io, nhv, state.clone(), None, false).await;
                                                            }
                                                            Ok(other) => {
                                                                warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected V1 message after WS+TLS from {}: {:?}", addr, other.v1_type_byte());
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "V1 read error after WS+TLS from {}: {}", addr, e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "tls"))]
                                            {
                                                warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
                                            }
                                        } else {
                                            // V1 fallback: replay consumed 7 bytes
                                            let mut ws = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
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
                                                    warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected WS message from {}: {:?}", addr, other.v1_type_byte());
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "WS read error from {}: {}", addr, e);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(addr = %addr, error = %e, "WebSocket upgrade failed for {}: {}", addr, e);
                                    }
                                }
                            }

                            ConnectionType::V2 => {
                                // Already consumed V2 magic. Extract TcpStream.
                                let inner_stream = match stream_io {
                                    IoStream::Tcp(s) => s,
                                    _other => {
                                        warn!(addr = %addr, "Expected TcpStream for V2 connection from {}, got unexpected stream type", addr);
                                        return;
                                    }
                                };

                                if state.tls_only {
                                    warn!(addr = %addr, "TLS-only mode: rejected V2 from {}", addr);
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
                                            info!(addr = ?addr, "Yamux over V2 session established for {:?}", addr);

                                            match frp_core::protocol::read_v2_magic_or_replay(&mut io).await {
                                                Ok(None) => {} // magic consumed
                                                Ok(Some(bytes)) => {
                                                    // Older V2 client without per-stream magic —
                                                    // replay bytes as start of next frame.
                                                    io = IoStream::BufferedRead(bytes, 0, Box::new(io));
                                                }
                                                Err(e) => {
                                                    warn!(error = %e, "Failed to read V2 magic from yamux stream: {}", e);
                                                    return;
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
                                                            warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                            return;
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                                    return;
                                                }
                                            };

                                            crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                        }
                                        Err(e) => {
                                            warn!(addr = ?addr, error = %e, "Failed to start yamux over V2 for {:?}: {}", addr, e);
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
                                                    warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                    return;
                                                }
                                                Err(e) => {
                                                    warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                            return;
                                        }
                                    };

                                    crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, None, Some(addr.to_string()), crypto_ctx).await;
                                }
                            }

                            ConnectionType::V1(_byte) => {
                                if state.tls_only {
                                    warn!(addr = %addr, "TLS-only mode: rejected plain TCP from {}", addr);
                                    return;
                                }
                                if state.tcp_mux {
                                    // Extract inner TcpStream and pre-read bytes.
                                    // Wrap in PreReadStream so yamux sees the full byte stream
                                    // (including the type byte consumed by detect_and_strip_magic).
                                    let (pre_read, inner_tcp) = match stream_io {
                                        IoStream::PreRead(buf, s) => (buf, s),
                                        _ => {
                                            warn!(addr = %addr,
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
                                            info!(addr = ?addr, "Yamux session established for {:?}", addr);

                                            // Try V2 detection: read 7 magic bytes from yamux stream.
                                            // Go frp sends V2 magic on yamux stream (not raw TCP) when tcpMux.
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match io.read_exact(&mut magic).await {
                                                Ok(_) => is_v2_magic(&magic),
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
                                                                warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
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
                                                        warn!(addr = ?addr, other = ?other.v1_type_byte(), "Unexpected yamux first message from {:?}: {:?}", addr, other.v1_type_byte());
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "Failed to read yamux first message from {}: {}", addr, e);
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = ?addr, error = %e, "Failed to start yamux server for {:?}: {}", addr, e);
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
                                            warn!(addr = %addr, other = ?other.v1_type_byte(), "Unexpected first message from {}: {:?}", addr, other.v1_type_byte());
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "Failed to read first message from {}: {}", addr, e);
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
                }
                _ = self.state.shutdown_token.cancelled() => {
                    info!("Accept loop stopped for graceful shutdown");
                    break;
                }
            }
        }

        // --- Graceful drain phase ---
        // Accept loop has stopped. Let existing bridge connections finish.
        let drain_timeout = Duration::from_secs(self.cfg.graceful_shutdown_timeout);
        let drain_start = std::time::Instant::now();
        let initial = self.state.active_connections.load(std::sync::atomic::Ordering::Relaxed);
        info!(active = %initial, timeout_secs = %drain_timeout.as_secs(),
            "Draining {} active connections (timeout {}s)",
            initial, drain_timeout.as_secs());

        loop {
            let remaining = self.state.active_connections.load(std::sync::atomic::Ordering::Relaxed);
            if remaining == 0 {
                info!(elapsed_secs = %drain_start.elapsed().as_secs_f32(),
                    "All connections drained in {:.1}s", drain_start.elapsed().as_secs_f32());
                break;
            }
            if drain_start.elapsed() > drain_timeout {
                warn!(remaining = %remaining, timeout_secs = %drain_timeout.as_secs(),
                    "Drain timeout — {} connections still active, forcing shutdown", remaining);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    /// Reload configuration from the config file (SIGUSR1 handler).
    /// Re-reads the TOML config and applies safe-to-reload settings
    /// (allow_ports, auth token, encryption key, TLS certificates).
    /// Returns a summary of changes, or an error if the config cannot be read.
    pub async fn reload(&self) -> Result<String, String> {
        let config_path = match &self.config_file {
            Some(p) => p.clone(),
            None => return Err("No config file path stored".into()),
        };
        let new_cfg: ServerConfig = frp_core::config::load_server_config(&config_path, false)
            .map_err(|e| format!("Failed to reload config: {e}"))?;

        let mut changes: Vec<String> = Vec::new();

        // Build new reloadable state
        let new_auth_cfg = AuthConfig {
            method: match new_cfg.auth.method.to_lowercase().as_str() {
                #[cfg(feature = "oidc")]
                "oidc" => AuthMethod::Oidc,
                _ => AuthMethod::Token,
            },
            token: frp_core::auth::resolve_dynamic_token_checked(&new_cfg.auth.token, &UnsafeFeatures::default()).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
                String::new()
            }),
            oidc_issuer: new_cfg.auth.oidc_issuer.clone(),
            oidc_audience: new_cfg.auth.oidc_audience.clone(),
            oidc_skip_expiry: new_cfg.auth.oidc_skip_expiry,
            oidc_skip_issuer: new_cfg.auth.oidc_skip_issuer,
            additional_data: None,
            oidc_proxy_url: new_cfg.auth.oidc_proxy_url.clone(),
            additional_auth_scopes: new_cfg.auth.additional_auth_scopes.clone(),
            authentication_timeout: new_cfg.auth.authentication_timeout,
            use_encryption: new_cfg.auth.use_encryption,
        };
        new_auth_cfg
            .check_startup()
            .map_err(|e| format!("security misconfiguration: {e}"))?;
        let new_enc_key = frp_core::encryption::derive_key(&new_auth_cfg.token);
        let new_allow_ports = if !new_cfg.allow_ports.is_empty() {
            frp_core::config::parse_allow_ports(&new_cfg.allow_ports)
        } else {
            vec![(new_cfg.allow_port_start, new_cfg.allow_port_end)]
        };

        // Apply under write lock
        {
            let mut r = self.state.reloadable.write_ok();
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
        // TLS certificate hot-reload: if cert/key/ca paths changed, rebuild
        // acceptor and swap atomically. Existing connections keep old config;
        // new connections pick up the new cert immediately.
        #[cfg(feature = "tls")]
        if self.cfg.tls_cert_file != new_cfg.tls_cert_file
            || self.cfg.tls_key_file != new_cfg.tls_key_file
            || self.cfg.tls_ca_file != new_cfg.tls_ca_file
        {
            let ca = if new_cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(new_cfg.tls_ca_file.as_str())
            };
            match build_tls_acceptor_or_generate(&new_cfg.tls_cert_file, &new_cfg.tls_key_file, ca) {
                Ok(acceptor) => {
                    *self.state.tls_acceptor.write_ok() = Some(acceptor);
                    changes.push(format!(
                        "TLS certificate reloaded (cert: {}, key: {})",
                        new_cfg.tls_cert_file, new_cfg.tls_key_file
                    ));
                }
                Err(e) => {
                    changes.push(format!(
                        "TLS certificate reload FAILED: {} (keeping old config)",
                        e
                    ));
                }
            }
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
            info!(changes = %changes.join("; "), "Config reloaded: {}", changes.join("; "));
            Ok(changes.join("; "))
        }
    }

}

