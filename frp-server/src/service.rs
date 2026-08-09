use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
#[cfg(any(feature = "websocket", feature = "kcp"))]
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use tracing::{error, info, instrument, warn};

#[cfg(feature = "oidc")]
use frp_core::auth::OidcVerifier;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::ServerConfig;
use frp_core::format_socket_addr;
#[cfg(feature = "websocket")]
use frp_core::mux;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_or_generate;
#[cfg(feature = "websocket")]
use frp_core::transport::IoStream;
use frp_core::transport::{detect_and_strip_magic, ConnectionType};
use frp_core::unsafe_features::UnsafeFeatures;

#[allow(unused_imports)]
use crate::control;
use crate::lock::RwLockExt;

// Re-export state types for backward compatibility.
// All existing `use crate::service::*` imports continue to work.
pub use crate::state::{AppState, ControlTx, InternalMsg, ReloadableState};

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Build an `AuthConfig` from a server config's `auth` sub-struct.
/// Shared by `Service::new()` and `Service::reload()`.
fn build_auth_config(
    auth: &frp_core::config::AuthServerConfig,
    unsafe_features: &UnsafeFeatures,
) -> Result<AuthConfig, String> {
    let token_source = auth.token_source.clone();
    let token = if let Some(ref source) = token_source {
        frp_core::config::validate_auth_token_source(&auth.token, &auth.token_source)?;
        frp_core::auth::validate_token_source_unsafe(source, unsafe_features)?;
        source
            .resolve()
            .map_err(|e| format!("failed to resolve auth.tokenSource: {e}"))?
    } else {
        frp_core::auth::resolve_dynamic_token_checked(&auth.token, unsafe_features).unwrap_or_else(
            |e| {
                tracing::warn!(error = %e, "resolve_dynamic_token error: {e}");
                String::new()
            },
        )
    };
    Ok(AuthConfig {
        method: match auth.method.to_lowercase().as_str() {
            #[cfg(feature = "oidc")]
            "oidc" => AuthMethod::Oidc,
            _ => AuthMethod::Token,
        },
        token,
        token_source,
        oidc_issuer: auth.oidc_issuer.clone(),
        oidc_audience: auth.oidc_audience.clone(),
        oidc_skip_expiry: auth.oidc_skip_expiry,
        oidc_skip_issuer: auth.oidc_skip_issuer,
        oidc_skip_nbf: auth.oidc_skip_nbf,
        oidc_skip_audience: auth.oidc_skip_audience,
        oidc_additional_audience: auth.oidc_additional_audience.clone(),
        oidc_tls_trusted_ca_file: auth.oidc_tls_trusted_ca_file.clone(),
        additional_data: None,
        oidc_proxy_url: auth.oidc_proxy_url.clone(),
        additional_auth_scopes: auth.additional_auth_scopes.clone(),
        authentication_timeout: auth.authentication_timeout,
        token_auth_timeout: auth.token_auth_timeout,
        use_encryption: auth.use_encryption,
    })
}

/// Resolve the allow-ports ranges from a server config: explicit `allow_ports`
/// spec if present, otherwise the `[allow_port_start, allow_port_end]` range.
/// Shared by `Service::new()` and `Service::reload()`.
fn resolve_allow_ports(cfg: &ServerConfig) -> Vec<frp_core::config::PortsRange> {
    if !cfg.allow_ports.is_empty() {
        // Invalid entries were already rejected by config validation.
        frp_core::config::parse_allow_ports(&cfg.allow_ports).unwrap_or_default()
    } else if cfg.allow_port_start == 0 && cfg.allow_port_end == 0 {
        // Default: no restriction — allow all ports.
        // Go frp compat: when both limits are unset, any port is allowed.
        vec![frp_core::config::PortsRange {
            start: 1,
            end: 65535,
            single: 0,
        }]
    } else {
        vec![frp_core::config::PortsRange {
            start: cfg.allow_port_start,
            end: cfg.allow_port_end,
            single: 0,
        }]
    }
}

/// Record a "restart required" change entry when `old != new`. Used by
/// `reload()` for settings that only take effect on a full restart.
fn note_restart_change<T: PartialEq + std::fmt::Display>(
    old: &T,
    new: &T,
    name: &str,
    changes: &mut Vec<String>,
) {
    if *old != *new {
        changes.push(format!("{name}: {old} -> {new} (restart required)"));
    }
}

/// Spawn a boxed future with type erasure. Reduces binary size by
/// preventing monomorphization of `tokio::spawn` for every concrete
/// future type — the unsizing coercion from `Pin<Box<ConcreteFut>>`
/// to `Pin<Box<dyn Future<...> + Send>>` ensures `tokio::spawn` is
/// specialized for the single pointer-sized `dyn` type.
fn spawn_boxed(fut: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
    tokio::spawn(fut);
}

// ---------------------------------------------------------------
// Service
// ---------------------------------------------------------------

pub struct Service {
    cfg: ServerConfig,
    state: Arc<AppState>,
    /// Path to config file for SIGUSR1 reload.
    config_file: Option<String>,
    unsafe_features: UnsafeFeatures,
}

impl Service {
    /// Create a new Service with default unsafe features (all blocked).
    pub async fn new(cfg: ServerConfig, config_file: Option<String>) -> Result<Self, String> {
        Self::with_unsafe_features(cfg, config_file, UnsafeFeatures::default()).await
    }

    /// Create a new Service with a custom unsafe features allowlist.
    /// Use this when `--allow-unsafe` CLI flag is provided.
    pub async fn with_unsafe_features(
        cfg: ServerConfig,
        config_file: Option<String>,
        unsafe_features: UnsafeFeatures,
    ) -> Result<Self, String> {
        let auth_cfg = build_auth_config(&cfg.auth, &unsafe_features)?;
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
                auth_cfg.oidc_skip_nbf,
                auth_cfg.oidc_skip_audience,
                auth_cfg.oidc_additional_audience.clone(),
                Some(auth_cfg.oidc_tls_trusted_ca_file.clone()).filter(|s| !s.is_empty()),
                Some(auth_cfg.oidc_proxy_url.clone()).filter(|s| !s.is_empty()),
            )
            .await
            {
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
        let allow_ports = resolve_allow_ports(&cfg);
        let sub_host = cfg.sub_domain_host.clone();
        let max_connections: usize = match cfg.max_connections {
            Some(0) => usize::MAX, // 0 = unlimited
            Some(n) => n as usize,
            None => 512, // default
        };
        let max_accept_rate = cfg.max_accept_rate.unwrap_or(0);
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
            cfg.transport.tcp_mux.unwrap_or(true),
            cfg.transport.tcp_mux_keepalive_interval,
            cfg.transport.tcp_keepalive,
            cfg.transport.heartbeat_timeout,
            cfg.udp_packet_size,
            cfg.tls_only,
            oidc_verifier,
            cfg.sudp_port,
            cfg.vhost_http_timeout,
            cfg.user_conn_timeout,
            cfg.tcp_mux_passthrough,
            {
                // Go frp compat: custom_404_page is a file path, not inline HTML.
                // Try to read the file; if it doesn't exist, log a warning and
                // treat the value as inline HTML (backward-compatible fallback).
                let page_path = cfg.web_server.custom_404_page.clone();
                if page_path.is_empty() {
                    String::new()
                } else {
                    match std::fs::read_to_string(&page_path) {
                        Ok(content) => content,
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::NotFound {
                                tracing::warn!(
                                    path = %page_path,
                                    "custom_404_page file not found, using value as inline HTML"
                                );
                            } else {
                                tracing::warn!(
                                    path = %page_path,
                                    error = %e,
                                    "failed to read custom_404_page file, using value as inline HTML"
                                );
                            }
                            page_path
                        }
                    }
                }
            },
            Arc::new(crate::plugin::HttpPluginManager::new(
                cfg.http_plugins.clone(),
            )),
            cfg.max_ports_per_client,
            cfg.max_conns_per_proxy,
            cfg.nat_hole_analysis_data_reserve_hours,
            cfg.detailed_errors_to_client,
            max_connections,
            max_accept_rate,
            frp_core::config::ServerConfigSnapshot::from_config(&cfg),
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
            unsafe_features,
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
            // Always initialize a TLS acceptor — Go frp auto-generates a
            // self-signed cert even without explicit TLS config, because
            // Go frpc may send TLS ClientHello (0x16/0x17) by default.
            let ca_file = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.as_str())
            };
            let acceptor = match build_tls_acceptor_or_generate(
                &self.cfg.tls_cert_file,
                &self.cfg.tls_key_file,
                ca_file,
            ) {
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

        let max_accept_rate = self.cfg.max_accept_rate.unwrap_or(0);
        // Hoisted accept-rate-limiter gate: when max_accept_rate == 0 the
        // limiter is a no-op (rate 0.0 → try_acquire always Ok), so skip
        // taking the mutex on every accept. The limiter never changes after
        // startup, so this is computed once per listener task.
        let rate_limiter_enabled = max_accept_rate > 0;
        let listener = TcpListener::bind(&bind_addr).await?;
        info!(bind_addr = %bind_addr, "frps listener started on {}", bind_addr);

        // Optional WebSocket listener
        #[cfg(feature = "websocket")]
        if self.cfg.websocket_port > 0 {
            let ws_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.websocket_port);
            let ws_addr2 = ws_addr.clone();
            let ws_state = self.state.clone();
            let (ws_bind_tx, ws_bind_rx) = tokio::sync::oneshot::channel::<()>();
            spawn_boxed(Box::pin(async move {
                match TcpListener::bind(&ws_addr2).await {
                    Ok(listener) => {
                        let _ = ws_bind_tx.send(());
                        info!(addr = %ws_addr2, "WebSocket listener ready on {}", ws_addr2);
                        loop {
                            tokio::select! {
                                result = listener.accept() => {
                                    match result {
                                        Ok((stream, addr)) => {
                                // Disable Nagle for low-latency small-message RTT
                                // (Go frp parity: control path uses NoDelay(true)).
                                frp_core::transport::set_nodelay(&stream);
                                if ws_state.tcp_keepalive > 0 {
                                    frp_core::transport::set_keepalive(
                                        &stream,
                                        ws_state.tcp_keepalive as u64,
                                    );
                                }
                                info!(addr = %addr, "New WebSocket connection from {}", addr);
                                let state = ws_state.clone();
                                let permit = state.conn_semaphore.as_ref()
                                    .and_then(|s| s.clone().try_acquire_owned().ok());
                                if permit.is_none() && state.conn_semaphore.is_some() {
                                    warn!(addr = %addr, "Max connections reached, rejecting WebSocket from {}", addr);
                                    continue;
                                }
                                let rate_wait = if rate_limiter_enabled {
                                    state.accept_rate_limiter.try_acquire().err()
                                } else {
                                    None
                                };
                                if let Some(wait) = rate_wait {
                                    warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying WebSocket {}ms", wait.as_millis());
                                    drop(permit);
                                    tokio::time::sleep(wait).await;
                                    continue;
                                }
                                spawn_boxed(Box::pin(async move {
                                    let _permit = permit;
                                    // Single absolute deadline covering the initial read phase
                                    // (V2 handshake + first frame) after the WS upgrade, matching
                                    // Go frp's single SetReadDeadline(10s) connReadTimeout
                                    // semantics. The upgrade itself is bounded by accept_websocket's
                                    // internal HANDSHAKE_TIMEOUT.
                                    let accept_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                                    match frp_core::transport::accept_websocket(IoStream::Tcp(stream)).await {
                                        Ok(mut ws) => {
                                            info!(addr = %addr, "WebSocket upgrade completed for {}", addr);

                                            // Reject plain WebSocket when tls_only is set.
                                            // The main TCP accept loop enforces this for all
                                            // connection types, but the dedicated WS listener
                                            // on proxy_bind_addr bypasses that check.
                                            if state.tls_only {
                                                warn!(addr = %addr, "TLS-only mode: rejected WebSocket on dedicated WS port from {}", addr);
                                                return;
                                            }

                                            // Try V2 magic detection
                                            let mut magic = [0u8; 7];
                                            let is_v2 = match ws.read_exact(&mut magic).await {
                                                Ok(_) => crate::handlers::is_v2_magic(&magic),
                                                Err(_) => false,
                                            };

                                            if magic[0] == 0x16 {
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
                                                    let tls_stream = match tokio::time::timeout_at(accept_deadline, tls_acceptor.accept(stream)).await {
                                                        Ok(r) => match r {
                                                            Ok(s) => s,
                                                            Err(e) => {
                                                                tracing::warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        },
                                                        Err(_elapsed) => {
                                                            tracing::warn!(addr = %addr, "TLS handshake timeout from {}", addr);
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

                                                        ..Default::default()
                                                        };
                                                        match mux::server_mux(tls_stream, &mux_cfg).await {
                                                            Ok((control_stream, incoming)) => {
                                                                let mut io = IoStream::Yamux(control_stream);
                                                                tracing::info!(addr = ?addr, "Yamux over WS+TLS session established for {:?}", addr);

                                                                // V2 detection on yamux stream
                                                                let mut magic = [0u8; 7];
                                                                let is_v2 = match io.read_exact(&mut magic).await {
                                                                    Ok(_) => crate::handlers::is_v2_magic(&magic),
                                                                    Err(_) => false,
                                                                };
                                                                if is_v2 {
                                                                    let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+TLS+yamux V2").await {
                                                                        Some(v) => v,
                                                                        None => return,
                                                                    };
                                                                    crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                                } else {
                                                                    // V1 over WS+TLS+yamux
                                                                    let io = frp_core::transport::IoStream::BufferedRead(
                                                                        magic.to_vec(), 0, Box::new(io),
                                                                    );
                                                                    crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), Some(incoming), None, accept_deadline).await;
                                                                }
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                                                            }
                                                        }
                                                    } else {
                                                        let mut io = IoStream::Tls(Box::new(tls_stream), addr);

                                                        let mut chicken = [0u8; 7];
                                                        let is_tls_v2 = match io.read_exact(&mut chicken).await {
                                                            Ok(_) => crate::handlers::is_v2_magic(&chicken),
                                                            Err(_) => false,
                                                        };
                                                        if is_tls_v2 {
                                                            let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+TLS+V2").await {
                                                                Some(v) => v,
                                                                None => return,
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                                        } else {
                                                            let io = frp_core::transport::IoStream::BufferedRead(
                                                                chicken.to_vec(), 0, Box::new(io),
                                                            );
                                                            crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), None, None, accept_deadline).await;
                                                        }
                                                    }
                                                }
                                                #[cfg(not(feature = "tls"))]
                                                {
                                                    tracing::warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
                                                }
                                            } else if state.tcp_mux {
                                                // Plain WebSocket + tcp_mux: Go frp v0.70.1 wraps the
                                                // upgraded stream in yamux before any FRP bytes, so
                                                // wrap here and run V2/V1 detection on the yamux stream.
                                                let stream = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                let mux_cfg = mux::TcpMuxConfig {
                                                    keepalive_interval: std::time::Duration::from_secs(
                                                        state.tcp_mux_keepalive.max(1) as u64
                                                    ),

                                                ..Default::default()
                                                };
                                                match mux::server_mux(stream, &mux_cfg).await {
                                                    Ok((control_stream, incoming)) => {
                                                        let mut io = IoStream::Yamux(control_stream);
                                                        tracing::info!(addr = ?addr, "Yamux over WebSocket session established for {:?}", addr);

                                                        // V2 detection on yamux stream
                                                        let mut mux_magic = [0u8; 7];
                                                        let is_v2 = match io.read_exact(&mut mux_magic).await {
                                                            Ok(_) => crate::handlers::is_v2_magic(&mux_magic),
                                                            Err(_) => false,
                                                        };
                                                        if is_v2 {
                                                            let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+yamux V2").await {
                                                                Some(v) => v,
                                                                None => return,
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, Some(incoming), None, crypto_ctx).await;
                                                        } else {
                                                            // V1 over plain WS+yamux
                                                            let io = IoStream::BufferedRead(
                                                                mux_magic.to_vec(), 0, Box::new(io),
                                                            );
                                                            crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), Some(incoming), None, accept_deadline).await;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(addr = ?addr, error = %e, "Failed to start yamux over WebSocket for {:?}: {}", addr, e);
                                                    }
                                                }
                                            } else if is_v2 {
                                                // V2 path: ClientHello/ServerHello handshake
                                                let (msg_payload, crypto_ctx) = match crate::handlers::v2_handshake_and_read(&mut ws, Some(addr), accept_deadline, "WS V2").await {
                                                    Some(v) => v,
                                                    None => return,
                                                };
                                                crate::handlers::dispatch_v2_message(ws, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                            } else {
                                                // V1 fallback: replay consumed 7 bytes
                                                let ws = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                crate::handlers::dispatch_v1_message(ws, state.clone(), Some(addr), None, None, accept_deadline).await;
                                            }
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "WebSocket upgrade failed for {}: {}", addr, e);
                                        }
                                    }
                                }));
                                        }
                                        Err(e) => {
                                            tracing::warn!(error = %e, "WS accept error, retrying...");
                                            tokio::time::sleep(Duration::from_millis(100)).await;
                                            continue;
                                        }
                                    }
                                }
                                _ = ws_state.shutdown_token.cancelled() => break,
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(addr = %ws_addr2, error = %e, "WebSocket listener bind failed: {}", e);
                    }
                }
            }));
            match ws_bind_rx.await {
                Ok(_) => info!(addr = %ws_addr, "WebSocket listener started on {}", ws_addr),
                Err(_) => tracing::error!(addr = %ws_addr, "WebSocket listener failed to start"),
            }
        }

        // Start HTTP VHost listener if configured. Go frp binds vhost
        // listeners on proxyBindAddr when set (pkg/server/service.go).
        if self.cfg.vhost_http_port > 0 {
            let vhost_bind = if self.cfg.proxy_bind_addr.is_empty() {
                &self.cfg.bind_addr
            } else {
                &self.cfg.proxy_bind_addr
            };
            let http_addr = format_socket_addr(vhost_bind, self.cfg.vhost_http_port);
            let http_state = self.state.clone();
            let http_shutdown = self.state.shutdown_token.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::vhost::run_vhost_http_listener(http_addr, http_state, http_shutdown)
                        .await
                {
                    error!(error = %e, "HTTP VHost listener failed: {}", e);
                }
            });
            info!(port = %self.cfg.vhost_http_port, "HTTP VHost listener starting on port {}", self.cfg.vhost_http_port);
        }

        // Start HTTPS VHost listener if configured
        // Go frp starts the HTTPS vhost listener whenever vhostHTTPSPort is
        // configured; the shared TLS acceptor auto-generates a server identity
        // when no cert/key files are set.
        if self.cfg.vhost_https_port > 0 {
            let vhost_bind = if self.cfg.proxy_bind_addr.is_empty() {
                &self.cfg.bind_addr
            } else {
                &self.cfg.proxy_bind_addr
            };
            let https_addr = format_socket_addr(vhost_bind, self.cfg.vhost_https_port);
            let https_addr2 = https_addr.clone();
            let https_state = self.state.clone();
            let https_shutdown = self.state.shutdown_token.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::vhost::run_vhost_https_listener(https_addr, https_state, https_shutdown)
                        .await
                {
                    error!(error = %e, "HTTPS VHost listener failed: {}", e);
                }
            });
            info!(addr = %https_addr2, "HTTPS VHost listener starting on {}", https_addr2);
        }

        // Start TCPMux HTTP CONNECT listener if configured
        if self.cfg.tcpmux_httpconnect_port > 0 {
            let mux_bind = if self.cfg.proxy_bind_addr.is_empty() {
                &self.cfg.bind_addr
            } else {
                &self.cfg.proxy_bind_addr
            };
            let tcpmux_addr = format_socket_addr(mux_bind, self.cfg.tcpmux_httpconnect_port);
            let tcpmux_state = self.state.clone();
            let tcpmux_shutdown = self.state.shutdown_token.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::tcpmux::run_tcpmux_listener(tcpmux_addr, tcpmux_state, tcpmux_shutdown)
                        .await
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
            let (kcp_bind_tx, kcp_bind_rx) = tokio::sync::oneshot::channel::<()>();
            spawn_boxed(Box::pin(async move {
                let mut listener = match frp_core::kcp::KcpListener::bind(
                    &kcp_addr2,
                    frp_core::kcp::default_kcp_config(),
                )
                .await
                {
                    Ok(l) => {
                        let _ = kcp_bind_tx.send(());
                        l
                    }
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
                                        let rate_wait = if rate_limiter_enabled {
                                            state.accept_rate_limiter.try_acquire().err()
                                        } else {
                                            None
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying KCP {}ms", wait.as_millis());
                                            drop(permit);
                                            tokio::time::sleep(wait).await;
                                            continue;
                                        }
                                        spawn_boxed(Box::pin(async move {
                                            let _permit = permit;
                                            let peer = stream.peer_addr;
                                    let conv = stream.conv();
                                    tracing::debug!(peer = %peer, conv = conv, "KCP HANDLER: spawned");
                                    tracing::info!(peer = %peer, conv = conv, "KCP handler: spawned for {} conv={}", peer, conv);
                                    let mut ctl = frp_core::transport::IoStream::Kcp(stream);

                                    // Try V2 magic detection with a 30s timeout.
                                    // Without a timeout, an attacker sending only
                                    // KCP ACKs (no app data) can hold a session
                                    // slot indefinitely, exhausting the 1024-slot
                                    // session table. 30s = same as unaccepted timeout.
                                    const KCP_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
                                    let mut magic = [0u8; 7];
                                    let is_v2 = match tokio::time::timeout(
                                        KCP_AUTH_TIMEOUT,
                                        ctl.read_exact(&mut magic),
                                    )
                                    .await
                                    {
                                        Ok(Ok(_)) => crate::handlers::is_v2_magic(&magic),
                                        Ok(Err(e)) => {
                                            tracing::debug!(peer = %peer, error = %e, "KCP: failed to read initial 7 bytes from {}", peer);
                                            false
                                        }
                                        Err(_elapsed) => {
                                            tracing::warn!(peer = %peer, conv = conv, "KCP: auth timeout ({}s) — no data from peer", KCP_AUTH_TIMEOUT.as_secs());
                                            return;
                                        }
                                    };
                                    tracing::info!(peer = %peer, first_byte = ?format_args!("0x{:02x}", magic[0]), is_v2, "KCP: new session from {} (first_byte=0x{:02x}, is_v2={})", peer, magic[0], is_v2);

                                    if is_v2 {
                                        // V2 path: ClientHello/ServerHello handshake
                                        let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                            Ok((Some(p), crypto)) => (p, crypto),
                                            Ok((None, crypto)) => {
                                                match frp_core::v2_handshake::read_first_frame_after_handshake(&mut ctl).await {
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
                                        crate::handlers::dispatch_v2_message(ctl, msg_payload, state, peer, None, None, crypto_ctx).await;
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
                                                let tls_io = frp_core::transport::IoStream::Tls(Box::new(tls_stream), peer);

                                                // After TLS: if tcpMux, wrap in yamux before V2/V1
                                                // (matching Go frps: TLS accept → yamux → V2/V1 on yamux stream).
                                                if state.tcp_mux {
                                                    let mux_cfg = frp_core::mux::TcpMuxConfig {
                                                        keepalive_interval: std::time::Duration::from_secs(
                                                            state.tcp_mux_keepalive.max(1) as u64
                                                        ),

                                                    ..Default::default()
                                                    };
                                                    match frp_core::mux::server_mux(tls_io, &mux_cfg).await {
                                                        Ok((control_stream, incoming)) => {
                                                            let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                            tracing::info!(peer = %peer, "KCP TLS+yamux session established for {}", peer);

                                                            let mut yamux_magic = [0u8; 7];
                                                            let is_v2 = match io.read_exact(&mut yamux_magic).await {
                                                                Ok(_) => crate::handlers::is_v2_magic(&yamux_magic),
                                                                Err(_) => false,
                                                            };
                                                            if is_v2 {
                                                                let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                                    Ok((None, crypto)) => {
                                                                        match frp_core::v2_handshake::read_first_frame_after_handshake(&mut io).await {
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
                                                                crate::handlers::dispatch_v2_message(io, msg_payload, state, peer, Some(incoming), None, crypto_ctx).await;
                                                            } else {
                                                                let mut io = frp_core::transport::IoStream::BufferedRead(yamux_magic.to_vec(), 0, Box::new(io));
                                                                match frp_core::protocol::read_msg_v1(&mut io).await {
                                                                    Ok(frp_core::msg::FrpMessage::Login(login)) => {
                                                                        tracing::info!(peer = %peer, "KCP TLS+yamux Login from {}", peer);
                                                                        control::handle_control(io, *login, state, Some(peer), Some(incoming), false, None, false).await;
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
                                                    Ok(_) => crate::handlers::is_v2_magic(&tls_magic),
                                                    Err(_) => false,
                                                };
                                                if is_v2 {
                                                    let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                        Ok((None, crypto)) => {
                                                            match frp_core::v2_handshake::read_first_frame_after_handshake(&mut ctl).await {
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
                                                    crate::handlers::dispatch_v2_message(ctl, msg_payload, state, peer, None, None, crypto_ctx).await;
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
                                                    let find_v1 = |data: &[u8]| -> Option<usize> {
                                                        data.windows(9).position(|w| {
                                                            crate::handlers::is_v1_type_byte(w[0])
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
                                                                    control::handle_control(ctl, *login, state, Some(peer), None, false, None, false).await;
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
                                                            tracing::warn!(peer = %peer, scan_len, scan_hex = %frp_core::hex_encode(&scan_data[..scan_len.min(128)]), "KCP TLS: no valid V1 header found in {} bytes", scan_len);
                                                        }
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "tls"))]
                                            {
                                                tracing::warn!("KCP TLS connection requires TLS feature (disabled in this build)");
                                            }
                                        } else {
                                            // Reject plain KCP when tls_only is set
                                            if state.tls_only {
                                                warn!(peer = %peer, "TLS-only mode: rejected plain KCP from {}", peer);
                                                return;
                                            }
                                            // tcp_mux enabled: Go frpc and frp-rs wrap KCP conns in
                                            // yamux before sending Login (matching Go frps flow).
                                            // If the first byte is a V1 type byte (e.g. 0x6f Login),
                                            // this is a legacy Rust frpc or custom client sending raw
                                            // V1; keep handling it directly so those clients work.
                                            if state.tcp_mux && !crate::handlers::is_v1_type_byte(first_byte) {
                                            // Replay the 7 bytes consumed by magic check —
                                            // they are part of the yamux SYN header.
                                            let stream = frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));
                                            let mux_cfg = frp_core::mux::TcpMuxConfig {
                                                keepalive_interval: std::time::Duration::from_secs(
                                                    state.tcp_mux_keepalive.max(1) as u64
                                                ),

                                            ..Default::default()
                                            };
                                            match frp_core::mux::server_mux(stream, &mux_cfg).await {
                                                Ok((control_stream, incoming)) => {
                                                    let mut io = frp_core::transport::IoStream::Yamux(control_stream);
                                                    tracing::info!(peer = %peer, "KCP yamux session established for {}", peer);

                                                    // V2 magic detection on yamux stream
                                                    let mut yamux_magic = [0u8; 7];
                                                    let is_v2 = match io.read_exact(&mut yamux_magic).await {
                                                        Ok(_) => crate::handlers::is_v2_magic(&yamux_magic),
                                                        Err(_) => false,
                                                    };
                                                    if is_v2 {
                                                        let (msg_payload, crypto_ctx) = match frp_core::v2_handshake::v2_handshake_server(&mut io).await {
                                                            Ok((Some(p), crypto)) => (p, crypto),
                                                            Ok((None, crypto)) => {
                                                                match frp_core::v2_handshake::read_first_frame_after_handshake(&mut io).await {
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
                                                                control::handle_control(io, *login, state, Some(peer), Some(incoming), false, None, false).await;
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
                                                                    control::handle_control(ctl, *login, state, Some(peer), None, false, None, false).await;
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
                                    }
                                }));
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "KCP accept error, retrying...");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                        }
                        _ = kcp_state.shutdown_token.cancelled() => break 'kcp_accept,
                    }
                }
            }));
            match kcp_bind_rx.await {
                Ok(_) => tracing::info!(addr = %kcp_addr, "KCP listener started on {}", kcp_addr),
                Err(_) => tracing::error!(addr = %kcp_addr, "KCP listener failed to start"),
            }
        }

        // Start QUIC listener if configured (auto-generates self-signed TLS cert if needed)
        #[cfg(feature = "quic")]
        if self.cfg.quic_bind_port > 0 {
            let quic_state = self.state.clone();
            let quic_options = self.cfg.transport.quic_options.clone().unwrap_or_default();
            let quic_params = frp_core::quic::quic_params_from_option_values(
                quic_options.keepalive_period,
                quic_options.max_idle_timeout,
                quic_options.max_incoming_streams,
            );
            let authenticated_stream_limit = quic_params.max_incoming_streams as usize;
            let mut listener_quic_params = quic_params.clone();
            listener_quic_params.max_incoming_streams = quic_params
                .max_incoming_streams
                .min(crate::handlers::QUIC_PREAUTH_STREAM_LIMIT as u32)
                .max(1);
            let quic_addr = format_socket_addr(&self.cfg.bind_addr, self.cfg.quic_bind_port);
            let quic_addr2 = quic_addr.clone();
            let (quic_bind_tx, quic_bind_rx) = tokio::sync::oneshot::channel::<()>();
            let cert_path = self.cfg.tls_cert_file.clone();
            let key_path = self.cfg.tls_key_file.clone();
            let ca_path = if self.cfg.tls_ca_file.is_empty() {
                None
            } else {
                Some(self.cfg.tls_ca_file.clone())
            };
            spawn_boxed(Box::pin(async move {
                let sockaddr: std::net::SocketAddr = match quic_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(addr = %quic_addr, error = %e, "QUIC: invalid bind address");
                        return;
                    }
                };

                // Build a TLS server config that honors `trustedCaFile`
                // (mTLS) exactly like the TCP/TLS path, then hand it to the
                // QUIC listener. Go frp reuses NewServerTLSConfig for QUIC.
                let tls_config = if !cert_path.is_empty() && !key_path.is_empty() {
                    frp_core::transport::build_tls_server_config(
                        &cert_path,
                        &key_path,
                        ca_path.as_deref(),
                    )
                } else {
                    tracing::info!(
                        "QUIC: no TLS cert/key configured, \
                         auto-generating self-signed certificate"
                    );
                    frp_core::transport::generate_self_signed_tls_config_with_ca(ca_path.as_deref())
                };
                let tls_config = match tls_config {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "QUIC: failed to build TLS config"
                        );
                        return;
                    }
                };
                let listener = match frp_core::quic::QuicListener::new_with_tls_config(
                    sockaddr,
                    tls_config,
                    listener_quic_params.clone(),
                ) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "QUIC: listen failed with built TLS config"
                        );
                        return;
                    }
                };
                let _ = quic_bind_tx.send(());

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
                                        let rate_wait = if rate_limiter_enabled {
                                            state.accept_rate_limiter.try_acquire().err()
                                        } else {
                                            None
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %quic_addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying QUIC {}ms", wait.as_millis());
                                            drop(permit);
                                            tokio::time::sleep(wait).await;
                                            continue;
                                        }
                                        spawn_boxed(Box::pin(async move {
                                            let _permit = permit;
                                            // Accept first bidirectional stream (control channel).
                                            // This is inside the handler, not in the accept loop —
                                            // matching Go frp's HandleQUICListener pattern where
                                            // the accept loop never blocks on a stream.
                                            let stream = match crate::handlers::await_quic_preauth(
                                                conn.accept_bi(),
                                                tokio::time::Instant::now()
                                                    + crate::handlers::QUIC_FIRST_FRAME_TIMEOUT,
                                                &state.shutdown_token,
                                            )
                                            .await
                                            {
                                                Ok(Ok(stream)) => stream,
                                                Ok(Err(e)) => {
                                                    tracing::warn!(error = %e, "QUIC: failed to accept first stream: {e}");
                                                    return;
                                                }
                                                Err(crate::handlers::QuicPreauthError::TimedOut) => {
                                                    tracing::warn!(addr = %quic_addr, "QUIC connection timed out before opening control stream");
                                                    conn.close(b"control stream timeout");
                                                    return;
                                                }
                                                Err(crate::handlers::QuicPreauthError::Cancelled) => {
                                                    conn.close(b"server shutdown");
                                                    return;
                                                }
                                            };
                                            // The first-frame budget starts after the stream is
                                            // accepted, not while we are waiting for the peer to
                                            // open it (Go frp applies the read deadline post-accept).
                                            let deadline = tokio::time::Instant::now()
                                                + crate::handlers::QUIC_FIRST_FRAME_TIMEOUT;
                                            crate::handlers::handle_quic_stream(
                                                stream,
                                                conn,
                                                state,
                                                deadline,
                                                authenticated_stream_limit,
                                            ).await;
                                        }));
                                    }
                            Err(e) => {
                                tracing::warn!(error = %e, "QUIC accept error, retrying...");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
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
            }));
            match quic_bind_rx.await {
                Ok(_) => {
                    tracing::info!(addr = %quic_addr2, "QUIC listener started on {}", quic_addr2)
                }
                Err(_) => tracing::error!(addr = %quic_addr2, "QUIC listener failed to start"),
            }
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
            let dash_assets = self.cfg.web_server.assets_dir.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::dashboard::run_dashboard(
                    dash_addr,
                    dash_state,
                    dash_user,
                    dash_pwd,
                    enable_prom,
                    dash_tls_cert,
                    dash_tls_key,
                    dash_assets,
                )
                .await
                {
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

        // Periodic port-reservation pruner: sweep 24h-expired entries so stale
        // reservations don't block port reuse. Same 60s cadence as NAT cleanup.
        self.state
            .clone()
            .spawn_port_reservation_pruner(self.state.shutdown_token.clone());

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

        // Spawn signal listener for graceful shutdown.
        // ctrl_c() only catches SIGINT; SIGTERM needs an explicit unix signal
        // handler (docker stop / systemctl stop send SIGTERM).
        let shutdown_token = self.state.shutdown_token.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                // SIGTERM → graceful shutdown (docker stop / systemctl stop
                // send SIGTERM; ctrl_c() alone only catches SIGINT).
                let mut term_sig =
                    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        Ok(s) => Some(s),
                        Err(e) => {
                            tracing::warn!(error = %e, "SIGTERM handler unavailable: {}", e);
                            None
                        }
                    };
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received SIGINT, initiating graceful shutdown...");
                    }
                    _ = async {
                        if let Some(sig) = term_sig.as_mut() {
                            sig.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        info!("Received SIGTERM, initiating graceful shutdown...");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
                info!("Received SIGINT, initiating graceful shutdown...");
            }
            shutdown_token.cancel();
        });

        // Stale-control reaper: run_id_to_ctl_tx entries whose receiver has
        // been dropped (control handler panicked / exited without running
        // unregister_control) would otherwise linger forever and dispatch
        // work-conns into a dead channel. Sweep every 60s.
        let state = self.state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let stale: Vec<(String, u64)> = state
                    .run_id_to_ctl_tx
                    .iter()
                    .filter(|r| r.tx.is_closed())
                    .map(|r| (r.key().clone(), r.control_id))
                    .collect();
                for (run_id, control_id) in stale {
                    // Atomically remove only if the entry still belongs to the
                    // same generation: remove_if compares inside the shard
                    // lock, so a superseding control that registered a fresh
                    // sender for this run_id is never removed by this sweep
                    // (a get-then-remove would race with re-login).
                    let removed = state
                        .run_id_to_ctl_tx
                        .remove_if(&run_id, |_, cur| cur.control_id == control_id);
                    if removed.is_some() {
                        state
                            .client_registry
                            .mark_offline_by_run_id_and_control_id(&run_id, control_id);
                        tracing::info!(
                            run_id = %run_id,
                            "removed stale control entry (handler died)"
                        );
                    }
                }
            }
        });

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                Ok((stream, addr)) => {
                    frp_core::transport::set_nodelay(&stream);
                    if self.state.tcp_keepalive > 0 {
                        frp_core::transport::set_keepalive(
                            &stream,
                            self.state.tcp_keepalive as u64,
                        );
                    }
                    let state = self.state.clone();

                    let permit = state.conn_semaphore.as_ref()
                        .and_then(|s| s.clone().try_acquire_owned().ok());
                    if permit.is_none() && state.conn_semaphore.is_some() {
                        warn!(addr = %addr, "Max connections reached, rejecting connection from {}", addr);
                        continue;
                    }
                    // Rate limit: the limiter is lock-free (AtomicU64 CAS),
                    // so no guard is held across any .await boundary. When
                    // disabled (max_accept_rate == 0) skip the call entirely
                    // — the limiter is a no-op.
                    let rate_wait = if rate_limiter_enabled {
                        state.accept_rate_limiter.try_acquire().err()
                    } else {
                        None
                    };
                    if let Some(wait) = rate_wait {
                        warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached ({} conn/s), delaying {}ms", max_accept_rate, wait.as_millis());
                        // The connection is being delayed, not accepted — do not
                        // hold a conn_semaphore slot while we wait (parity with
                        // the vhost/tcpmux accept loops).
                        drop(permit);
                        tokio::time::sleep(wait).await;
                        continue;
                    }
                    spawn_boxed(Box::pin(async move {
                        // Connection read deadline: wrap the initial message
                        // detection (detect_and_strip_magic) with a timeout.
                        // Matches Go frp's SetReadDeadline(10s) before reading
                        // any data from a new connection (server/service.go:557).
                        // Single absolute deadline from task start covering the whole
                        // initial read phase (magic + TLS detection + first message),
                        // matching Go's single connReadTimeout deadline.
                        let accept_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                        let _permit = permit;
                        let (ct, stream_io) = match tokio::time::timeout_at(
                            accept_deadline,
                            detect_and_strip_magic(stream),
                        )
                        .await
                        {
                            Ok(Ok((c, s))) => (c, s),
                            Ok(Err(e)) => {
                                warn!(addr = %addr, error = %e, "Failed to detect connection type from {}: {}", addr, e);
                                return;
                            }
                            Err(_elapsed) => {
                                warn!(addr = %addr, read_timeout_secs = 10,
                                    "Initial read timeout (10s) before message detection from {}, dropping connection",
                                    addr
                                );
                                return;
                            }
                        };

                        Box::pin(async move {
                        match ct {
                                #[cfg(feature = "tls")]
                                ConnectionType::Tls(first_byte) => {
                                    crate::handlers::handle_tls_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        first_byte,
                                        stream_io,
                                    )
                                    .await;
                                }
                                #[cfg(not(feature = "tls"))]
                                ConnectionType::Tls(first_byte) => {
                                    crate::handlers::handle_tls_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        first_byte,
                                        stream_io,
                                    )
                                    .await;
                                }
                                #[cfg(feature = "websocket")]
                                ConnectionType::WebSocket => {
                                    crate::handlers::handle_websocket_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        stream_io,
                                    )
                                    .await;
                                }
                                ConnectionType::V2 => {
                                    crate::handlers::handle_v2_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        stream_io,
                                    )
                                    .await;
                                }
                                ConnectionType::V1(_) => {
                                    crate::handlers::handle_v1_connection(
                                        state,
                                        addr,
                                        accept_deadline,
                                        stream_io,
                                    )
                                    .await;
                                }
                        }
                        }).await;
                    }));
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
        let initial = self
            .state
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed);
        info!(active = %initial, timeout_secs = %drain_timeout.as_secs(),
            "Draining {} active connections (timeout {}s)",
            initial, drain_timeout.as_secs());

        loop {
            let remaining = self
                .state
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed);
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

        // Stop the OIDC background JWKS refresh before exiting — the verifier
        // itself is dropped with AppState, but aborting the refresh task here
        // gives it a deterministic stop point during graceful shutdown
        // (audit round 5, LOW 2.4). cfg-gated: without the `oidc` feature the
        // verifier is a method-less stub type.
        #[cfg(feature = "oidc")]
        if let Some(verifier) = &self.state.oidc.verifier {
            verifier.stop_background_refresh();
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
        let new_auth_cfg = build_auth_config(&new_cfg.auth, &self.unsafe_features)?;
        new_auth_cfg
            .check_startup()
            .map_err(|e| format!("security misconfiguration: {e}"))?;
        let new_enc_key = frp_core::encryption::derive_key(&new_auth_cfg.token);
        let new_allow_ports = resolve_allow_ports(&new_cfg);

        // Apply under write lock
        {
            let mut r = self.state.reloadable.write_ok();
            if *r.allow_ports != new_allow_ports {
                changes.push(format!(
                    "allow_ports: {:?} -> {:?}",
                    r.allow_ports, new_allow_ports
                ));
                r.allow_ports = Arc::new(new_allow_ports);
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
        note_restart_change(
            &self.cfg.bind_port,
            &new_cfg.bind_port,
            "bind_port",
            &mut changes,
        );
        note_restart_change(
            &self.cfg.bind_addr,
            &new_cfg.bind_addr,
            "bind_addr",
            &mut changes,
        );
        note_restart_change(
            &self.cfg.tls_enable,
            &new_cfg.tls_enable,
            "tls_enable",
            &mut changes,
        );
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
            match build_tls_acceptor_or_generate(&new_cfg.tls_cert_file, &new_cfg.tls_key_file, ca)
            {
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
            || self.cfg.auth.oidc_skip_audience != new_cfg.auth.oidc_skip_audience
            || self.cfg.auth.oidc_additional_audience != new_cfg.auth.oidc_additional_audience
            || self.cfg.auth.oidc_tls_trusted_ca_file != new_cfg.auth.oidc_tls_trusted_ca_file
        {
            changes.push("OIDC settings changed (restart required)".to_string());
        }

        if changes.is_empty() {
            Ok("config reloaded: no changes detected".into())
        } else {
            info!(changes = %changes.join("; "), "Config reloaded: {}", changes.join("; "));
            Ok(changes.join("; "))
        }
    }
}
