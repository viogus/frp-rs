use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

#[cfg(feature = "quic")]
use tokio_util::sync::CancellationToken;

#[cfg(any(
    feature = "ssh",
    feature = "kcp",
    feature = "quic",
    feature = "tls",
    feature = "websocket"
))]
use tracing::debug;
use tracing::{error, info, instrument, warn};

#[cfg(feature = "oidc")]
use frp_core::auth::OidcVerifier;
use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::ServerConfig;
use frp_core::format_socket_addr;
use frp_core::mux;
#[cfg(feature = "tls")]
use frp_core::transport::build_tls_acceptor_or_generate;
#[cfg(feature = "websocket")]
use frp_core::transport::{accept_websocket, accept_websocket_from_peeked};
use frp_core::transport::{detect_and_strip_magic, ConnectionType, IoStream, PreReadStream};
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

/// Check if a 7-byte buffer matches the V2 protocol magic bytes.
/// This check is repeated across all transport paths (TCP, KCP, QUIC, WS,
/// with/without TLS, with/without yamux) — ~16 locations total.
/// See V2_MAGIC_BYTES in frp_core::protocol.
#[inline]
fn is_v2_magic(buf: &[u8]) -> bool {
    buf.len() >= 7 && buf[..7] == frp_core::protocol::V2_MAGIC_BYTES
}

/// Check if a byte could be a V1 protocol type byte.
/// All V1 type bytes are ASCII alphanumeric (e.g., 'o'=Login, '1'=LoginResp,
/// 'w'=NewWorkConn, 'h'=Ping). Used to distinguish raw V1 data from yamux
/// headers (which start with 0x00).
#[cfg(all(test, feature = "quic"))]
mod quic_admission_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn simulated_silent_first_frame(
        limiter: Arc<tokio::sync::Semaphore>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
    ) {
        let _permit = limiter.acquire_owned().await.unwrap();
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        max_active.fetch_max(now, Ordering::SeqCst);
        let _ = tokio::time::timeout(Duration::from_millis(10), std::future::pending::<()>()).await;
        active.fetch_sub(1, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn unauthenticated_silent_streams_are_bounded_and_timeout_releases_permits() {
        let limit = 4;
        let limiter = Arc::new(tokio::sync::Semaphore::new(limit));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..64 {
            tasks.spawn(simulated_silent_first_frame(
                limiter.clone(),
                active.clone(),
                max_active.clone(),
            ));
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(max_active.load(Ordering::SeqCst), limit);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.available_permits(), limit);
    }

    #[tokio::test]
    async fn drain_preauth_limiter_bounds_concurrent_first_frame_waits() {
        // Mirrors the drain loop: the stream is already accepted, then the
        // preauth permit is acquired before the first-frame read. The
        // limiter must cap concurrent waits at QUIC_PREAUTH_STREAM_LIMIT.
        let limiter = new_quic_preauth_stream_limiter();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();

        for _ in 0..(QUIC_PREAUTH_STREAM_LIMIT * 4) {
            let limiter = limiter.clone();
            let active = active.clone();
            let max_active = max_active.clone();
            tasks.spawn(async move {
                let _permit = limiter.acquire_owned().await.unwrap();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while tasks.join_next().await.is_some() {}

        assert_eq!(max_active.load(Ordering::SeqCst), QUIC_PREAUTH_STREAM_LIMIT);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(limiter.available_permits(), QUIC_PREAUTH_STREAM_LIMIT);
    }

    #[tokio::test]
    async fn preauth_stream_admission_uses_small_safety_cap() {
        let limiter = new_quic_preauth_stream_limiter();
        let mut permits = Vec::new();
        for _ in 0..QUIC_PREAUTH_STREAM_LIMIT {
            permits.push(limiter.clone().try_acquire_owned().unwrap());
        }
        assert!(limiter.clone().try_acquire_owned().is_err());
        drop(permits.pop());
        assert!(limiter.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn authenticated_stream_admission_preserves_configured_boundary_above_256() {
        let configured = 1_024usize;
        let limiter = new_quic_authenticated_stream_limiter(configured);
        let mut permits = Vec::new();
        for _ in 0..configured {
            permits.push(limiter.clone().try_acquire_owned().unwrap());
        }
        assert!(limiter.clone().try_acquire_owned().is_err());
        drop(permits.pop());
        assert!(limiter.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn first_control_accept_obeys_absolute_preauth_deadline() {
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
        let result = await_quic_preauth(std::future::pending::<()>(), deadline, &cancel).await;
        assert!(matches!(result, Err(QuicPreauthError::TimedOut)));
    }

    #[tokio::test]
    async fn real_quic_connection_without_first_stream_times_out() {
        let tls = frp_core::transport::generate_self_signed_tls_config().unwrap();
        let listener = frp_core::quic::QuicListener::new_with_tls_config(
            "127.0.0.1:0".parse().unwrap(),
            tls,
            frp_core::quic::QuicTransportParams::default(),
        )
        .unwrap();
        let address = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            frp_core::quic::dial_quic_connection_with_params(
                &address.to_string(),
                "localhost",
                None,
                None,
                None,
                frp_core::quic::QuicTransportParams::default(),
            )
            .await
            .unwrap()
        });
        let server = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("server should complete QUIC handshake")
            .unwrap();
        let _client = tokio::time::timeout(Duration::from_secs(2), client)
            .await
            .expect("client should complete QUIC handshake")
            .unwrap();
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);

        let result = await_quic_preauth(server.accept_bi(), deadline, &cancel).await;
        assert!(matches!(result, Err(QuicPreauthError::TimedOut)));
        server.close(b"test timeout");
    }

    #[tokio::test]
    async fn cancelling_stream_tasks_reclaims_all_admission_permits() {
        let limit = 8;
        let limiter = Arc::new(tokio::sync::Semaphore::new(limit));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..limit {
            let permit = limiter.clone().acquire_owned().await.unwrap();
            tasks.spawn(async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            });
        }
        assert_eq!(limiter.available_permits(), 0);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(limiter.available_permits(), limit);
    }
}

#[inline]
#[allow(dead_code)] // only used in TLS/WS/KCP accept paths, not in every feature set
fn is_v1_type_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

#[cfg(feature = "quic")]
const QUIC_FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "quic")]
const QUIC_PREAUTH_STREAM_LIMIT: usize = 32;

#[cfg(feature = "quic")]
fn new_quic_preauth_stream_limiter() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(QUIC_PREAUTH_STREAM_LIMIT))
}

#[cfg(feature = "quic")]
fn new_quic_authenticated_stream_limiter(configured: usize) -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(configured.max(1)))
}

#[cfg(feature = "quic")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicPreauthError {
    TimedOut,
    Cancelled,
}

#[cfg(feature = "quic")]
async fn await_quic_preauth<F, T>(
    future: F,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<T, QuicPreauthError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(QuicPreauthError::Cancelled),
        result = tokio::time::timeout_at(deadline, future) => {
            result.map_err(|_| QuicPreauthError::TimedOut)
        }
    }
}

/// Run V2 handshake then read the first message frame. Returns `None` on error
/// (already logged). `addr` is `None` for listeners that don't capture peer addr.
#[cfg(feature = "websocket")]
async fn v2_handshake_and_read(
    io: &mut IoStream,
    addr: Option<std::net::SocketAddr>,
    deadline: tokio::time::Instant,
    log_prefix: &str,
) -> Option<(Vec<u8>, Option<frp_core::v2_handshake::CryptoContext>)> {
    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(
        deadline,
        frp_core::v2_handshake::v2_handshake_server(io),
    )
    .await
    {
        Ok(r) => match r {
            Ok((Some(p), crypto)) => (p, crypto),
            Ok((None, crypto)) => {
                match tokio::time::timeout_at(
                    deadline,
                    frp_core::v2_handshake::read_first_frame_after_handshake(io),
                )
                .await
                {
                    Ok(r) => match r {
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
                    Err(_elapsed) => {
                        tracing::warn!(peer = ?addr, "{}: read first frame after handshake timeout", log_prefix);
                        return None;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(peer = ?addr, error = %e, "{} handshake error: {}", log_prefix, e);
                return None;
            }
        },
        Err(_elapsed) => {
            tracing::warn!(peer = ?addr, "{} handshake timeout", log_prefix);
            return None;
        }
    };
    Some((msg_payload, crypto_ctx))
}

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
                                let rate_wait = {
                                    let mut rl = state.accept_rate_limiter.lock().unwrap();
                                    rl.try_acquire().err()
                                };
                                if let Some(wait) = rate_wait {
                                    warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying WebSocket {}ms", wait.as_millis());
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
                                                Ok(_) => is_v2_magic(&magic),
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
                                                                    Ok(_) => is_v2_magic(&magic),
                                                                    Err(_) => false,
                                                                };
                                                                if is_v2 {
                                                                    let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+TLS+yamux V2").await {
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
                                                            Ok(_) => is_v2_magic(&chicken),
                                                            Err(_) => false,
                                                        };
                                                        if is_tls_v2 {
                                                            let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+TLS+V2").await {
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
                                                            Ok(_) => is_v2_magic(&mux_magic),
                                                            Err(_) => false,
                                                        };
                                                        if is_v2 {
                                                            let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut io, Some(addr), accept_deadline, "WS+yamux V2").await {
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
                                                let (msg_payload, crypto_ctx) = match v2_handshake_and_read(&mut ws, Some(addr), accept_deadline, "WS V2").await {
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
                                        let rate_wait = {
                                            let mut rl = state.accept_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                                            rl.try_acquire().err()
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying KCP {}ms", wait.as_millis());
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
                                        Ok(Ok(_)) => is_v2_magic(&magic),
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
                                                                Ok(_) => is_v2_magic(&yamux_magic),
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
                                                    Ok(_) => is_v2_magic(&tls_magic),
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
                                                            tracing::warn!(peer = %peer, scan_len, scan_hex = %data_encoding::HEXLOWER.encode(&scan_data[..scan_len.min(128)]), "KCP TLS: no valid V1 header found in {} bytes", scan_len);
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
                                            if state.tcp_mux && !is_v1_type_byte(first_byte) {
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
                                                        Ok(_) => is_v2_magic(&yamux_magic),
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
                .min(QUIC_PREAUTH_STREAM_LIMIT as u32)
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
                                        let rate_wait = {
                                            let mut rl = state.accept_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
                                            rl.try_acquire().err()
                                        };
                                        if let Some(wait) = rate_wait {
                                            warn!(addr = %quic_addr, wait_ms = wait.as_millis(), "accept rate limit reached, delaying QUIC {}ms", wait.as_millis());
                                            tokio::time::sleep(wait).await;
                                            continue;
                                        }
                                        spawn_boxed(Box::pin(async move {
                                            let _permit = permit;
                                            // Accept first bidirectional stream (control channel).
                                            // This is inside the handler, not in the accept loop —
                                            // matching Go frp's HandleQUICListener pattern where
                                            // the accept loop never blocks on a stream.
                                            let stream = match await_quic_preauth(
                                                conn.accept_bi(),
                                                tokio::time::Instant::now()
                                                    + QUIC_FIRST_FRAME_TIMEOUT,
                                                &state.shutdown_token,
                                            )
                                            .await
                                            {
                                                Ok(Ok(stream)) => stream,
                                                Ok(Err(e)) => {
                                                    tracing::warn!(error = %e, "QUIC: failed to accept first stream: {e}");
                                                    return;
                                                }
                                                Err(QuicPreauthError::TimedOut) => {
                                                    tracing::warn!(addr = %quic_addr, "QUIC connection timed out before opening control stream");
                                                    conn.close(b"control stream timeout");
                                                    return;
                                                }
                                                Err(QuicPreauthError::Cancelled) => {
                                                    conn.close(b"server shutdown");
                                                    return;
                                                }
                                            };
                                            // The first-frame budget starts after the stream is
                                            // accepted, not while we are waiting for the peer to
                                            // open it (Go frp applies the read deadline post-accept).
                                            let deadline = tokio::time::Instant::now()
                                                + QUIC_FIRST_FRAME_TIMEOUT;
                                            handle_quic_stream(
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

        /// Handle a QUIC stream (control or work connection).
        /// Accepts the first bidirectional stream from `conn`, then runs
        /// V1/V2 protocol detection and dispatch. Spawns a drain task to
        /// accept additional streams as work connections.
        #[cfg(feature = "quic")]
        async fn handle_quic_stream(
            first_stream: frp_core::quic::QuicStream,
            conn: frp_core::quic::QuicConnection,
            state: Arc<AppState>,
            first_frame_deadline: tokio::time::Instant,
            authenticated_stream_limit: usize,
        ) {
            let mut ctl = frp_core::transport::IoStream::Quic(first_stream);

            // Try V2 magic detection on first stream.
            // Per-stream independence: each QUIC stream gets its own
            // V2 detection, matching Go frp's WriteMagicIfV2() per stream.
            let mut magic = [0u8; 7];
            let is_v2 =
                match tokio::time::timeout_at(first_frame_deadline, ctl.read_exact(&mut magic))
                    .await
                {
                    Ok(Ok(_)) => is_v2_magic(&magic),
                    Ok(Err(_)) => false,
                    Err(_) => {
                        tracing::warn!("QUIC control stream timed out before protocol magic");
                        conn.close(b"control stream timeout");
                        return;
                    }
                };

            if is_v2 {
                // --- V2 path ---
                let first_message = tokio::time::timeout_at(first_frame_deadline, async {
                    match frp_core::v2_handshake::v2_handshake_server(&mut ctl).await {
                    Ok((Some(p), crypto)) => (p, crypto),
                    Ok((None, crypto)) => match ctl.read_raw_v2_frame().await {
                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                        Ok((ft, _, _)) => {
                            tracing::warn!(frame_type = ?ft, "QUIC V2: unexpected frame type {} after handshake", ft);
                            return None;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "QUIC V2: failed to read message after handshake: {}", e);
                            return None;
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "QUIC V2 handshake error: {}", e);
                        return None;
                    }
                    }.into()
                }).await;
                let (msg_payload, crypto_ctx) = match first_message {
                    Ok(Some(message)) => message,
                    Ok(None) => {
                        conn.close(b"control stream error");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("QUIC V2 control stream timed out before first message");
                        conn.close(b"control stream timeout");
                        return;
                    }
                };

                let addr: std::net::SocketAddr = conn.remote_address();
                let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();
                let control = crate::handlers::dispatch_v2_message_with_auth_signal(
                    ctl,
                    msg_payload,
                    Arc::clone(&state),
                    addr,
                    None,
                    None,
                    crypto_ctx,
                    auth_tx,
                );
                tokio::pin!(control);
                tokio::select! {
                    biased;
                    _ = &mut control => {}
                    auth = auth_rx => {
                        if auth.is_err() {
                            return;
                        }
                        conn.set_max_concurrent_bi_streams(
                            authenticated_stream_limit.min(u32::MAX as usize) as u32,
                        );
                        let cancel = spawn_quic_drain(
                            conn,
                            Arc::clone(&state),
                            "V2",
                            authenticated_stream_limit,
                        );
                        control.await;
                        cancel.cancel();
                    }
                }
            } else {
                // --- V1 fallback ---
                let mut ctl =
                    frp_core::transport::IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ctl));

                match tokio::time::timeout_at(
                    first_frame_deadline,
                    frp_core::protocol::read_msg_v1(&mut ctl),
                )
                .await
                {
                    Err(_) => {
                        tracing::warn!("QUIC V1 control stream timed out before Login");
                        conn.close(b"control stream timeout");
                    }
                    Ok(result) => match result {
                        Ok(frp_core::msg::FrpMessage::Login(login)) => {
                            let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();
                            let control = control::handle_control_with_auth_signal(
                                ctl,
                                *login,
                                Arc::clone(&state),
                                Some(conn.remote_address()),
                                None,
                                false,
                                None,
                                false,
                                auth_tx,
                            );
                            tokio::pin!(control);
                            tokio::select! {
                                biased;
                                _ = &mut control => {}
                                auth = auth_rx => {
                                    if auth.is_err() {
                                        return;
                                    }
                                    conn.set_max_concurrent_bi_streams(
                                        authenticated_stream_limit.min(u32::MAX as usize) as u32,
                                    );
                                    let cancel = spawn_quic_drain(
                                        conn,
                                        Arc::clone(&state),
                                        "V1",
                                        authenticated_stream_limit,
                                    );
                                    control.await;
                                    cancel.cancel();
                                }
                            }
                        }
                        Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => {
                            crate::handlers::handle_work_conn_inner(ctl, nwc, state).await;
                        }
                        Ok(other) => {
                            tracing::warn!(other = ?other.v1_type_byte(), "Unexpected QUIC message: {:?}", other.v1_type_byte());
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "QUIC read error: {}", e);
                            conn.close(b"control stream error");
                        }
                    },
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
            authenticated_stream_limit: usize,
        ) -> CancellationToken {
            let cancel = CancellationToken::new();
            let drain_cancel = cancel.clone();
            let drain_conn = conn;
            tokio::spawn(async move {
                tracing::debug!(tag, "QUIC drain ({tag}) started");
                let preauth_limiter = new_quic_preauth_stream_limiter();
                let authenticated_limiter =
                    new_quic_authenticated_stream_limiter(authenticated_stream_limit);
                let mut stream_tasks = tokio::task::JoinSet::new();
                let accept_next = drain_conn.accept_bi();
                tokio::pin!(accept_next);
                loop {
                    tokio::select! {
                        biased;
                        _ = drain_cancel.cancelled() => {
                            tracing::debug!(tag, "QUIC drain ({tag}) cancelled");
                            break;
                        }
                        Some(result) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                            if let Err(e) = result {
                                tracing::debug!(error = %e, tag, "QUIC stream task ended with error");
                            }
                        }
                        result = &mut accept_next => {
                            let result = if drain_cancel.is_cancelled() {
                                break;
                            } else {
                                result
                            };
                            match result {
                                Ok(work_stream) => {
                                    tracing::debug!(tag, "QUIC drain ({tag}): accepted new stream");
                                    let s = Arc::clone(&state);
                                    let authenticated_limiter = authenticated_limiter.clone();
                                    let preauth_limiter = preauth_limiter.clone();
                                    stream_tasks.spawn(async move {
                                        // Bound concurrent unauthenticated first-frame waits:
                                        // acquire only after the stream was accepted so the
                                        // limiter caps actual reads, not the accept backlog.
                                        let preauth_permit = match preauth_limiter.acquire_owned().await {
                                            Ok(permit) => permit,
                                            Err(_) => return,
                                        };
                                        let mut wc = frp_core::transport::IoStream::Quic(work_stream);
                                        let request = tokio::time::timeout(QUIC_FIRST_FRAME_TIMEOUT, async {
                                            let mut wmagic = [0u8; 7];
                                            let w_is_v2 = match wc.read_exact(&mut wmagic).await {
                                                Ok(_) => is_v2_magic(&wmagic),
                                                Err(e) => return Err(e.into()),
                                            };
                                            if w_is_v2 {
                                                match wc.read_v2_frame().await {
                                                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc)),
                                                    Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V2 message {:?}", other.v2_type_id()).into())),
                                                    Err(e) => Err(e),
                                                }
                                            } else {
                                                wc = frp_core::transport::IoStream::BufferedRead(wmagic.to_vec(), 0, Box::new(wc));
                                                match frp_core::protocol::read_msg_v1(&mut wc).await {
                                                    Ok(frp_core::msg::FrpMessage::NewWorkConn(nwc)) => Ok((wc, nwc)),
                                                    Ok(other) => Err(frp_core::Error::Protocol(format!("unexpected QUIC V1 message {:?}", other.v1_type_byte()).into())),
                                                    Err(e) => Err(e),
                                                }
                                            }
                                        }).await;
                                        match request {
                                            Ok(Ok((wc, nwc))) => {
                                                drop(preauth_permit);
                                                let Ok(_authenticated_permit) =
                                                    authenticated_limiter.acquire_owned().await
                                                else {
                                                    return;
                                                };
                                                crate::handlers::handle_work_conn_inner(wc, nwc, s).await
                                            },
                                            Ok(Err(e)) => tracing::warn!(error = %e, "QUIC drain: invalid first frame"),
                                            Err(_) => tracing::warn!(timeout_secs = QUIC_FIRST_FRAME_TIMEOUT.as_secs(), "QUIC work stream first-frame timeout"),
                                        }
                                    });
                                    accept_next.set(drain_conn.accept_bi());
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, tag, "QUIC drain ({tag}) done: {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
                stream_tasks.abort_all();
                while stream_tasks.join_next().await.is_some() {}
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
                    dash_addr,
                    dash_state,
                    dash_user,
                    dash_pwd,
                    enable_prom,
                    dash_tls_cert,
                    dash_tls_key,
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
                    frp_core::transport::set_nodelay(&stream);
                    if self.state.tcp_keepalive > 0 {
                        frp_core::transport::set_keepalive(
                            &stream,
                            self.state.tcp_keepalive as u64,
                        );
                    }
                    let state = self.state.clone();
                    #[cfg(feature = "tls")]
                    let acceptor = state.tls_acceptor.read_ok().clone();

                    let permit = state.conn_semaphore.as_ref()
                        .and_then(|s| s.clone().try_acquire_owned().ok());
                    if permit.is_none() && state.conn_semaphore.is_some() {
                        warn!(addr = %addr, "Max connections reached, rejecting connection from {}", addr);
                        continue;
                    }
                    // Rate limit: extract into non-async scope so MutexGuard
                    // doesn't live across any .await boundary.
                    let rate_wait = {
                        let mut rl = state.accept_rate_limiter.lock().unwrap();
                        rl.try_acquire().err()
                    };
                    if let Some(wait) = rate_wait {
                        warn!(addr = %addr, wait_ms = wait.as_millis(), "accept rate limit reached ({} conn/s), delaying {}ms", max_accept_rate, wait.as_millis());
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
                                // 10s timeout matches Go frp's connReadTimeout, which
                                // CheckAndEnableTLSServerConnWithTimeout applies during
                                // TLS detection (server/service.go constant, 10s).
                                let mut sni_buf = vec![0u8; 4096];
                                let sni_peek_n = match tokio::time::timeout_at(
                                    accept_deadline,
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
                                        // SNI routing: no HTTP auth, so http_user is empty string.
                                        // SNI routing: no HTTP path, so pass empty string.
                                        // Routes with empty locations (HTTPS SNI) match any path.
                                        if let Some(route) = state.vhost_manager.lookup_wildcard(&sni_host, "", "").await {
                                            let ctl_tx = {
                                                let map = state.run_id_to_ctl_tx.read().await;
                                                map.get(&route.run_id).cloned()
                                            };
                                            if let Some(ctl) = ctl_tx {
                                                info!(sni_host = %sni_host, proxy_name = %route.proxy_name, addr = %addr,
                                                    "SNI route '{}' → HTTPS proxy '{}' from {}",
                                                    sni_host, route.proxy_name, addr);
                                                // send().await: backpressure is correct —
                                                // silently dropping the connection after
                                                // consuming TLS ClientHello bytes would
                                                // confuse the client.
                                                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                                                    proxy_name: route.proxy_name.clone(),
                                                    user_conn: IoStream::Tcp(inner_stream),
                                                    pre_read: sni_data,
                                                }).await;
                                                return;
                                            }
                                        }
                                    }
                                }

                                // No SNI match — check acceptor before creating stream.
                                let acceptor = match acceptor {
                                    Some(a) => a,
                                    None => {
                                        // TLS.Force mode: if tls_only is set, reject connections
                                        // that attempt TLS without a configured acceptor.
                                        if state.tls_only {
                                            warn!(addr = %addr,
                                                "TLS-only mode: TLS byte (0x{:02x}) but TLS not configured, rejecting",
                                                first_byte);
                                            return;
                                        }
                                        // Go frp compat: Go frpc sends 0x17 (FRP_TLS_HEAD_BYTE)
                                        // or 0x16 (FRP_TLS_DIRECT_BYTE) as the first byte when
                                        // TLS is enabled on the client but not on the server.
                                        // Go frps falls back to plain TCP via
                                        // CheckAndEnableTLSServerConnWithTimeout.
                                        // Match that behavior: strip the first byte and
                                        // treat the remaining data as V1.
                                        if first_byte == frp_core::transport::FRP_TLS_HEAD_BYTE
                                            || first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE
                                        {
                                            info!(addr = %addr, first_byte = first_byte,
                                                "TLS byte (0x{:02x}) but TLS not configured, falling back to V1",
                                                first_byte);
                                            // 0x17 is already stripped from pre_read_bytes above,
                                            // but 0x16 is not (kept for TLS handshake path).
                                            // Strip it here so V1 dispatch sees valid data.
                                            if first_byte == frp_core::transport::FRP_TLS_DIRECT_BYTE
                                                && !sni_data.is_empty()
                                            {
                                                sni_data.remove(0);
                                            }
                                            let stream = IoStream::PreRead(sni_data, inner_stream);
                                            crate::handlers::dispatch_v1_message(stream, state, Some(addr), None, Some(addr.to_string()), accept_deadline).await;
                                            return;
                                        }
                                        // first_byte is always 0x17 or 0x16 here
                                        // (ConnectionType::Tls only matches those),
                                        // but the compiler needs an explicit fallback.
                                        debug!(addr = %addr, first_byte = first_byte,
                                            "TLS byte (0x{:02x}) — unexpected, dropping",
                                            first_byte);
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
                                let mut io = IoStream::Tls(Box::new(tokio_rustls::TlsStream::Server(tls_stream)), addr);

                                // Peek for WebSocket upgrade inside TLS (Go frp 'ws'
                                // transport sends TLS ClientHello first, then WebSocket
                                // upgrade inside the TLS tunnel).
                                //
                                // Two-phase detection to avoid false positives from
                                // health checks, scanners, and other non-frp HTTP
                                // clients that connect to the frps TLS port.
                                // Two-phase WebSocket detection.
                                // Peek reads the first bytes of the post-TLS byte
                                // stream (i.e. the first message); Go frp reads this
                                // under its connReadTimeout = 10s deadline, so use
                                // the same value instead of a shorter hardcoded one.
                                let mut ws_peek = vec![0u8; 4];
                                #[cfg(feature = "websocket")]
                                let got_http = match tokio::time::timeout_at(
                                    accept_deadline,
                                    io.read_exact(&mut ws_peek[..4]),
                                ).await {
                                    Ok(Ok(n)) if n >= 4 => &ws_peek[..4] == b"GET ",
                                    _ => false,
                                };
                                #[cfg(not(feature = "websocket"))]
                                let _ = tokio::time::timeout_at(
                                    accept_deadline,
                                    io.read_exact(&mut ws_peek[..4]),
                                ).await;

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
                                                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut ws)).await {
                                                    Ok(r) => match r {
                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                        Ok((None, crypto)) => {
                                                            match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut ws)).await {
                                                                Ok(r) => match r {
                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                    Ok((ft, _, _)) => {
                                                                        warn!(frame_type = ?ft, addr = %addr, "WS+TLS V2: unexpected frame type {} from {}", ft, addr);
                                                                        return;
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "WS+TLS V2: failed to read message: {}", e);
                                                                        return;
                                                                    }
                                                                },
                                                                Err(_elapsed) => {
                                                                    warn!(addr = %addr, "WS+TLS V2: read first frame after handshake timeout from {}", addr);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "WS+TLS V2 handshake error: {}", e);
                                                            return;
                                                        }
                                                    },
                                                    Err(_elapsed) => {
                                                        warn!(addr = %addr, "WS+TLS V2 handshake timeout from {}", addr);
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

                                                ..Default::default()
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
                                                            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                                Ok(r) => match r {
                                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                                    Ok((None, crypto)) => {
                                                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                            Ok(r) => match r {
                                                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                                Ok((ft, _, _)) => {
                                                                                    warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                    return;
                                                                                }
                                                                                Err(e) => {
                                                                                    warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message: {}", e);
                                                                                    return;
                                                                                }
                                                                            },
                                                                            Err(_elapsed) => {
                                                                                warn!(addr = %addr, "WS+TLS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                                return;
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                },
                                                                Err(_elapsed) => {
                                                                    warn!(addr = %addr, "WS+TLS+yamux V2 handshake timeout from {}", addr);
                                                                    return;
                                                                }
                                                            };
                                                            crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                                        } else {
                                                            let io = IoStream::BufferedRead(v2_magic.to_vec(), 0, Box::new(io));
                                                            crate::handlers::dispatch_v1_message(io, state, Some(addr), Some(incoming), None, accept_deadline).await;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "Failed to start yamux over WS+TLS for {}: {}", addr, e);
                                                    }
                                                }
                                            } else {
                                                let ws = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(ws));
                                                crate::handlers::dispatch_v1_message(ws, state, Some(addr), None, None, accept_deadline).await;
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

                                    ..Default::default()
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
                                                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                    Ok(r) => match r {
                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                        Ok((None, crypto)) => {
                                                            // Read Login in plaintext. AEAD wrapping happens in
                                                            // handle_control after LoginResp (matching Go frp flow).
                                                            match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                Ok(r) => match r {
                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                    Ok((ft, _, _)) => {
                                                                        warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 TLS+yamux handshake from {}", ft, addr);
                                                                        return;
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "Failed to read V2 message after TLS+yamux handshake from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                },
                                                                Err(_elapsed) => {
                                                                    warn!(addr = %addr, "V2 TLS+yamux: read first frame after handshake timeout from {}", addr);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "V2 TLS+yamux handshake error from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    },
                                                    Err(_elapsed) => {
                                                        warn!(addr = %addr, "V2 TLS+yamux handshake timeout from {}", addr);
                                                        return;
                                                    }
                                                };
                                                crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                            } else {
                                                // Not V2. Replay consumed bytes for V1 processing.
                                                let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                                crate::handlers::dispatch_v1_message(io, state, Some(addr), Some(incoming), None, accept_deadline).await;
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
                                        let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                            Ok(r) => match r {
                                                Ok((Some(p), crypto)) => (p, crypto),
                                                Ok((None, crypto)) => {
                                                    match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                        Ok(r) => match r {
                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                            Ok((ft, _, _)) => {
                                                                tracing::warn!(frame_type = ?ft, addr = %addr, "TLS V2: unexpected frame type {} after handshake from {}", ft, addr);
                                                                return;
                                                            }
                                                            Err(e) => {
                                                                tracing::warn!(addr = %addr, error = %e, "TLS V2: failed to read message after handshake from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        },
                                                        Err(_elapsed) => {
                                                            tracing::warn!(addr = %addr, "TLS V2: read first frame after handshake timeout from {}", addr);
                                                            return;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tracing::warn!(addr = %addr, error = %e, "TLS V2 handshake error from {}: {}", addr, e);
                                                    return;
                                                }
                                            },
                                            Err(_elapsed) => {
                                                tracing::warn!(addr = %addr, "TLS V2 handshake timeout from {}", addr);
                                                return;
                                            }
                                        };
                                        // Pass visitor_addr to match V1 TLS plain behavior for NatHoleVisitor
                                        crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, None, Some(addr.to_string()), crypto_ctx).await;
                                    } else {
                                        // V1 fallback: replay consumed 7 bytes
                                        let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                        crate::handlers::dispatch_v1_message(io, state, Some(addr), None, Some(addr.to_string()), accept_deadline).await;
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
                                    let stream = IoStream::PreRead(pre_read_bytes, inner_stream);
                                    crate::handlers::dispatch_v1_message(stream, state, Some(addr), None, Some(addr.to_string()), accept_deadline).await;
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

                                        if magic[0] == 0x16 {
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
                                                let tls_stream = match tokio::time::timeout_at(accept_deadline, tls_acceptor.accept(stream)).await {
                                                        Ok(r) => match r {
                                                            Ok(s) => s,
                                                            Err(e) => {
                                                                warn!(addr = %addr, error = %e, "TLS handshake failed on WS from {}: {}", addr, e);
                                                                return;
                                                            }
                                                        },
                                                        Err(_elapsed) => {
                                                            warn!(addr = %addr, "TLS handshake timeout from {}", addr);
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

                                                    ..Default::default()
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
                                                                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                                    Ok(r) => match r {
                                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                                        Ok((None, crypto)) => {
                                                                            match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                                Ok(r) => match r {
                                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                                    Ok((ft, _, _)) => {
                                                                                        warn!(frame_type = ?ft, addr = %addr, "WS+TLS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                        return;
                                                                                    }
                                                                                    Err(e) => {
                                                                                        warn!(addr = %addr, error = %e, "WS+TLS+yamux V2: failed to read message from {}: {}", addr, e);
                                                                                        return;
                                                                                    }
                                                                                },
                                                                                Err(_elapsed) => {
                                                                                    warn!(addr = %addr, "WS+TLS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                                    return;
                                                                                }
                                                                            }
                                                                        }
                                                                        Err(e) => {
                                                                            warn!(addr = %addr, error = %e, "WS+TLS+yamux V2 handshake error from {}: {}", addr, e);
                                                                            return;
                                                                        }
                                                                    },
                                                                    Err(_elapsed) => {
                                                                        warn!(addr = %addr, "WS+TLS+yamux V2 handshake timeout from {}", addr);
                                                                        return;
                                                                    }
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
                                                            warn!(addr = ?addr, error = %e, "Failed to start yamux over WS+TLS for {:?}: {}", addr, e);
                                                        }
                                                    }
                                                } else {
                                                    let mut io = IoStream::Tls(Box::new(tls_stream), addr);

                                                    // V2 chicken check on the decrypted TLS stream
                                                    let mut chicken = [0u8; 7];
                                                    let is_tls_v2 = match io.read_exact(&mut chicken).await {
                                                        Ok(_) => is_v2_magic(&chicken),
                                                        Err(_) => false,
                                                    };
                                                    if is_tls_v2 {
                                                        let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                            Ok(r) => match r {
                                                                Ok((Some(p), crypto)) => (p, crypto),
                                                                Ok((None, crypto)) => {
                                                                    match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                        Ok(r) => match r {
                                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                            Ok((ft, _, _)) => {
                                                                                warn!(frame_type = ?ft, addr = %addr, "WS+TLS+V2: unexpected frame type {} from {}", ft, addr);
                                                                                return;
                                                                            }
                                                                            Err(e) => {
                                                                                warn!(addr = %addr, error = %e, "WS+TLS+V2: failed to read message from {}: {}", addr, e);
                                                                                return;
                                                                            }
                                                                        },
                                                                        Err(_elapsed) => {
                                                                            warn!(addr = %addr, "WS+TLS+V2: read first frame after handshake timeout from {}", addr);
                                                                            return;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "WS+TLS+V2 handshake error from {}: {}", addr, e);
                                                                    return;
                                                                }
                                                            },
                                                            Err(_elapsed) => {
                                                                warn!(addr = %addr, "WS+TLS+V2 handshake timeout from {}", addr);
                                                                return;
                                                            }
                                                        };
                                                        crate::handlers::dispatch_v2_message(io, msg_payload, state.clone(), addr, None, None, crypto_ctx).await;
                                                    } else {
                                                        // V1 over TLS-over-WS
                                                        let io = frp_core::transport::IoStream::BufferedRead(
                                                            chicken.to_vec(), 0, Box::new(io),
                                                        );
                                                        crate::handlers::dispatch_v1_message(io, state.clone(), Some(addr), None, None, accept_deadline).await;
                                                    }
                                                }
                                            }
                                            #[cfg(not(feature = "tls"))]
                                            {
                                                warn!(addr = %addr, "TLS ClientHello in WebSocket frame but TLS feature not enabled, dropping connection from {}", addr);
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
                                                    info!(addr = ?addr, "Yamux over WebSocket session established for {:?}", addr);

                                                    // V2 detection on yamux stream
                                                    let mut mux_magic = [0u8; 7];
                                                    let is_v2 = match io.read_exact(&mut mux_magic).await {
                                                        Ok(_) => is_v2_magic(&mux_magic),
                                                        Err(_) => false,
                                                    };
                                                    if is_v2 {
                                                        let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                            Ok(r) => match r {
                                                                Ok((Some(p), crypto)) => (p, crypto),
                                                                Ok((None, crypto)) => {
                                                                    match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                        Ok(r) => match r {
                                                                            Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                            Ok((ft, _, _)) => {
                                                                                warn!(frame_type = ?ft, addr = %addr, "WS+yamux V2: unexpected frame type {} from {}", ft, addr);
                                                                                return;
                                                                            }
                                                                            Err(e) => {
                                                                                warn!(addr = %addr, error = %e, "WS+yamux V2: failed to read message from {}: {}", addr, e);
                                                                                return;
                                                                            }
                                                                        },
                                                                        Err(_elapsed) => {
                                                                            warn!(addr = %addr, "WS+yamux V2: read first frame after handshake timeout from {}", addr);
                                                                            return;
                                                                        }
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "WS+yamux V2 handshake error from {}: {}", addr, e);
                                                                    return;
                                                                }
                                                            },
                                                            Err(_elapsed) => {
                                                                warn!(addr = %addr, "WS+yamux V2 handshake timeout from {}", addr);
                                                                return;
                                                            }
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
                                                    warn!(addr = ?addr, error = %e, "Failed to start yamux over WebSocket for {:?}: {}", addr, e);
                                                }
                                            }
                                        } else if is_v2 {
                                            // V2 path: ClientHello/ServerHello handshake
                                            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut ws)).await {
                                                Ok(r) => match r {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut ws)).await {
                                                            Ok(r) => match r {
                                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                Ok((ft, _, _)) => {
                                                                    warn!(frame_type = ?ft, addr = %addr, "WS V2 (main): unexpected frame type {} after handshake from {}", ft, addr);
                                                                    return;
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "WS V2 (main): failed to read message after handshake from {}: {}", addr, e);
                                                                    return;
                                                                }
                                                            },
                                                            Err(_elapsed) => {
                                                                warn!(addr = %addr, "WS V2 (main): read first frame after handshake timeout from {}", addr);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "WS V2 (main) handshake error from {}: {}", addr, e);
                                                        return;
                                                    }
                                                },
                                                Err(_elapsed) => {
                                                    warn!(addr = %addr, "WS V2 (main) handshake timeout from {}", addr);
                                                    return;
                                                }
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

                                    ..Default::default()
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
                                            let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                Ok(r) => match r {
                                                    Ok((Some(p), crypto)) => (p, crypto),
                                                    Ok((None, crypto)) => {
                                                        // Read Login in plaintext. AEAD wrapping happens in
                                                        // handle_control after LoginResp (matching Go frp flow).
                                                        match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                            Ok(r) => match r {
                                                                Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                Ok((ft, _, _)) => {
                                                                    warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                                    return;
                                                                }
                                                                Err(e) => {
                                                                    warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                                    return;
                                                                }
                                                            },
                                                            Err(_elapsed) => {
                                                                warn!(addr = %addr, "V2 yamux: read first frame after handshake timeout from {}", addr);
                                                                return;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                                        return;
                                                    }
                                                },
                                                Err(_elapsed) => {
                                                    warn!(addr = %addr, "V2 yamux handshake timeout from {}", addr);
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
                                    let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                        Ok(r) => match r {
                                            Ok((Some(p), crypto)) => (p, crypto),
                                            Ok((None, crypto)) => {
                                                // Read Login in plaintext. AEAD wrapping happens in
                                                // handle_control after LoginResp (matching Go frp flow).
                                                match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                    Ok(r) => match r {
                                                        Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                        Ok((ft, _, _)) => {
                                                            warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                            return;
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    },
                                                    Err(_elapsed) => {
                                                        warn!(addr = %addr, "V2: read first frame after handshake timeout from {}", addr);
                                                        return;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                                return;
                                            }
                                        },
                                        Err(_elapsed) => {
                                            warn!(addr = %addr, "V2 handshake timeout from {}", addr);
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

                                    ..Default::default()
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
                                                let (msg_payload, crypto_ctx) = match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::v2_handshake_server(&mut io)).await {
                                                    Ok(r) => match r {
                                                        Ok((Some(p), crypto)) => (p, crypto),
                                                        Ok((None, crypto)) => {
                                                            // Read Login in plaintext. AEAD wrapping happens in
                                                            // handle_control after LoginResp (matching Go frp flow).
                                                            match tokio::time::timeout_at(accept_deadline, frp_core::v2_handshake::read_first_frame_after_handshake(&mut io)).await {
                                                                Ok(r) => match r {
                                                                    Ok((frp_core::protocol::V2_FRAME_TYPE_MESSAGE, _, p)) => (p, crypto),
                                                                    Ok((ft, _, _)) => {
                                                                        warn!(frame_type = ?ft, addr = %addr, "Unexpected frame type {} after V2 handshake from {}", ft, addr);
                                                                        return;
                                                                    }
                                                                    Err(e) => {
                                                                        warn!(addr = %addr, error = %e, "Failed to read V2 message after handshake from {}: {}", addr, e);
                                                                        return;
                                                                    }
                                                                },
                                                                Err(_elapsed) => {
                                                                    warn!(addr = %addr, "V2: read first frame after handshake timeout from {}", addr);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!(addr = %addr, error = %e, "V2 handshake error from {}: {}", addr, e);
                                                            return;
                                                        }
                                                    },
                                                    Err(_elapsed) => {
                                                        warn!(addr = %addr, "V2 handshake timeout from {}", addr);
                                                        return;
                                                    }
                                                };
                                                crate::handlers::dispatch_v2_message(io, msg_payload, state, addr, Some(incoming), None, crypto_ctx).await;
                                            } else {
                                                // Not V2. Replay consumed bytes and process as V1.
                                                let io = IoStream::BufferedRead(magic.to_vec(), 0, Box::new(io));
                                                crate::handlers::dispatch_v1_message(io, state, Some(addr), Some(incoming), None, accept_deadline).await;
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
                                    crate::handlers::dispatch_v1_message(stream_io, state, Some(addr), None, Some(addr.to_string()), accept_deadline).await;
                                }
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
