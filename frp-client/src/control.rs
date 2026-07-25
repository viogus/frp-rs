use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::config::{ProxyConfig, VisitorConfig};
use frp_core::msg::{self, ClientSpec, FrpMessage};
use frp_core::mux::{self, YamuxSession};
use frp_core::protocol::write_msg_v1;
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{dial_server, DialOptions, IoStream, TransportProtocol};
use frp_core::TransportError;
use frp_core::VERSION;

use crate::util::opt_if_empty;

#[cfg(feature = "quic")]
type LoginRet = (
    IoStream,
    String,
    Option<YamuxSession>,
    Option<QuicConnection>,
);
#[cfg(not(feature = "quic"))]
type LoginRet = (IoStream, String, Option<YamuxSession>);

use crate::proxy;

/// Control connection state for the client.
pub struct ControlConnection {
    server_addr: String,
    server_port: u16,
    auth_cfg: Arc<AuthConfig>,
    transport_protocol: TransportProtocol,
    pool_count: i32,
    user: String,
    client_id: String,
    run_id: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
    dns_server: Option<String>,
    tcp_mux: bool,
    disable_custom_tls_first_byte: bool,
    keepalive_secs: u64,
    tcp_mux_keepalive_interval: i64,
    bind_addr: Option<String>,
    v2: bool,
    oidc_client: Option<Arc<OidcClient>>,
    /// Server's additional auth scopes from LoginResp. Combined with client
    /// config to decide whether Ping/NewWorkConn need auth.
    pub server_auth_scopes: Vec<String>,
    metas: std::collections::HashMap<String, String>,
    proxy_url: String,
    /// Client spec passed in Login message (Go frp compat).
    client_spec: Option<ClientSpec>,
    /// Timeout in seconds for dialing the frp server.
    /// Go frp compat: dialServerTimeout. Default: 10.
    dial_server_timeout: i64,
}

impl ControlConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_addr: String,
        server_port: u16,
        auth_cfg: Arc<AuthConfig>,
        transport_protocol: TransportProtocol,
        pool_count: i32,
        user: String,
        client_id: String,
        tls_enable: bool,
        tls_server_name: String,
        tls_ca_file: Option<String>,
        tls_cert_file: Option<String>,
        tls_key_file: Option<String>,
        dns_server: Option<String>,
        tcp_mux: bool,
        disable_custom_tls_first_byte: bool,
        keepalive_secs: u64,
        tcp_mux_keepalive_interval: i64,
        bind_addr: Option<String>,
        v2: bool,
        oidc_client: Option<Arc<OidcClient>>,
        metas: std::collections::HashMap<String, String>,
        proxy_url: String,
        previous_run_id: String,
        client_spec: Option<ClientSpec>,
        dial_server_timeout: i64,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            auth_cfg,
            transport_protocol,
            pool_count,
            user,
            client_id,
            run_id: previous_run_id,
            tls_enable,
            tls_server_name,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            dns_server,
            tcp_mux,
            disable_custom_tls_first_byte,
            keepalive_secs,
            tcp_mux_keepalive_interval,
            bind_addr,
            v2,
            oidc_client,
            server_auth_scopes: Vec::new(),
            metas,
            proxy_url,
            client_spec,
            dial_server_timeout,
        }
    }

    /// Connect to the server and login.
    /// Returns the control stream, run_id, optional yamux session, and optional
    /// QUIC connection (for opening additional streams for work connections).
    pub async fn login(&mut self) -> Result<LoginRet, frp_core::Error> {
        // Go frp servers with tcpMux=true wrap every incoming TCP connection
        // in yamux immediately, so the client MUST wrap BEFORE sending Login.
        // Works over both plain TCP and TLS (yamux sits on top of TLS).
        let propose_mux = self.tcp_mux && matches!(self.transport_protocol, TransportProtocol::Tcp);

        let opts = DialOptions {
            server_addr: self.server_addr.clone(),
            server_port: self.server_port,
            protocol: self.transport_protocol.clone(),
            tls_enable: self.tls_enable,
            tls_server_name: self.tls_server_name.clone(),
            tls_ca_file: self.tls_ca_file.clone(),
            tls_cert_file: self.tls_cert_file.clone(),
            tls_key_file: self.tls_key_file.clone(),
            dns_server: self.dns_server.clone(),
            disable_custom_tls_first_byte: self.disable_custom_tls_first_byte,
            keepalive_secs: self.keepalive_secs,
            bind_addr: self.bind_addr.clone(),
            proxy_url: opt_if_empty!(self.proxy_url),
            v2: self.v2,
            dial_timeout_secs: self.dial_server_timeout as u64,
        };

        // Establish transport connection.
        // QUIC transport: dial directly via dial_quic() to capture the
        // QuicConnection handle. Other transports go through dial_server().
        #[cfg(feature = "quic")]
        let (mut io_stream, yamux_session, quic_conn): (
            IoStream,
            Option<YamuxSession>,
            Option<QuicConnection>,
        ) = {
            if self.transport_protocol == TransportProtocol::Quic {
                let addr = format!("{}:{}", self.server_addr, self.server_port);
                let server_name = if !self.tls_server_name.is_empty() {
                    &self.tls_server_name
                } else {
                    &self.server_addr
                };
                let ca_file = self.tls_ca_file.as_deref();
                let (stream, qc) = frp_core::quic::dial_quic(&addr, server_name, ca_file)
                    .await
                    .map_err(|e| frp_core::Error::Transport(format!("QUIC dial: {e}").into()))?;
                (IoStream::Quic(stream), None, Some(qc))
            } else {
                let raw_stream = dial_server(&opts).await?;
                // Wrap in yamux BEFORE V2 handshake (matches Go frp flow).
                // The server wraps its side on accept, so the client must wrap
                // before sending ClientHello.
                if propose_mux {
                    let mux_cfg = mux::TcpMuxConfig {
                        keepalive_interval: Duration::from_secs(
                            self.tcp_mux_keepalive_interval.max(1) as u64,
                        ),
                        max_stream_window_size: 6 * 1024 * 1024,
                    };
                    match raw_stream {
                        IoStream::Tcp(tcp_stream) => {
                            let (control_stream, session) =
                                mux::client_mux(tcp_stream, &mux_cfg).await?;
                            info!("Yamux session established");
                            (IoStream::Yamux(control_stream), Some(session), None)
                        }
                        #[cfg(feature = "tls")]
                        IoStream::Tls(tls_stream, _) => {
                            let (control_stream, session) =
                                mux::client_mux(tls_stream, &mux_cfg).await?;
                            info!("Yamux session established over TLS");
                            (IoStream::Yamux(control_stream), Some(session), None)
                        }
                        other => {
                            warn!(
                                transport = ?std::mem::discriminant(&other),
                                "Unexpected transport {:?} for mux proposal — yamux not applied",
                                std::mem::discriminant(&other)
                            );
                            (other, None, None)
                        }
                    }
                } else {
                    // No yamux: raw stream directly (V2 handshake happens below).
                    (raw_stream, None, None)
                }
            }
        };

        #[cfg(not(feature = "quic"))]
        let (mut io_stream, yamux_session): (IoStream, Option<YamuxSession>) = {
            let raw_stream = dial_server(&opts).await?;
            // Wrap in yamux BEFORE V2 handshake (matches Go frp flow).
            // The server wraps its side on accept, so the client must wrap
            // before sending ClientHello.
            if propose_mux {
                let mux_cfg = mux::TcpMuxConfig {
                    keepalive_interval: Duration::from_secs(
                        self.tcp_mux_keepalive_interval.max(1) as u64
                    ),
                    max_stream_window_size: 6 * 1024 * 1024,
                };
                match raw_stream {
                    IoStream::Tcp(tcp_stream) => {
                        let (control_stream, session) =
                            mux::client_mux(tcp_stream, &mux_cfg).await?;
                        info!("Yamux session established");
                        (IoStream::Yamux(control_stream), Some(session))
                    }
                    #[cfg(feature = "tls")]
                    IoStream::Tls(tls_stream, _) => {
                        let (control_stream, session) =
                            mux::client_mux(tls_stream, &mux_cfg).await?;
                        info!("Yamux session established over TLS");
                        (IoStream::Yamux(control_stream), Some(session))
                    }
                    other => {
                        warn!(
                            transport = ?std::mem::discriminant(&other),
                            "Unexpected transport {:?} for mux proposal — yamux not applied",
                            std::mem::discriminant(&other)
                        );
                        (other, None)
                    }
                }
            } else {
                // No yamux: raw stream directly (V2 handshake happens below).
                (raw_stream, None)
            }
        };

        // V2: ClientHello/ServerHello handshake on yamux-wrapped stream.
        // Go frp compat (v0.70.1): Login is pipelined after ClientHello,
        // BEFORE receiving ServerHello. This means the Login message goes
        // over the wire before the server's ServerHello response is read.
        // See /tmp/frp-source/client/control_session.go:140-203.
        let mut crypto_ctx = None;
        let mut client_hello_json: Option<Vec<u8>> = None;
        if self.v2 {
            // Write V2 magic on the fully-established transport stream.
            // dial_server() no longer writes magic — control.rs is the single
            // call site for all transports, matching Go frp v0.70 where
            // WriteMagicIfV2 happens on the connector result after TLS/WS/mux
            // (client/control_session.go:140-141).
            frp_core::protocol::write_v2_magic(&mut io_stream).await?;
            let transport_name = match self.transport_protocol {
                TransportProtocol::Tcp => "tcp",
                #[cfg(feature = "kcp")]
                TransportProtocol::Kcp => "kcp",
                #[cfg(feature = "quic")]
                TransportProtocol::Quic => "quic",
                #[cfg(feature = "websocket")]
                TransportProtocol::WebSocket => "websocket",
                #[cfg(feature = "websocket")]
                TransportProtocol::Wss => "wss",
                #[allow(unreachable_patterns)]
                _ => "tcp",
            };
            // Step 1: Send ClientHello only (don't wait for ServerHello yet).
            let ch_json = frp_core::v2_handshake::v2_handshake_client_send_hello(
                &mut io_stream,
                transport_name,
                self.tls_enable,
                self.tcp_mux,
                true, // with_crypto
            )
            .await?;
            client_hello_json = Some(ch_json);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut login = msg::Login {
            version: Some(VERSION.into()),
            hostname: Some(hostname().await),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            user: opt_if_empty!(self.user),
            run_id: if self.run_id.is_empty() {
                None
            } else {
                Some(self.run_id.clone())
            },
            client_id: opt_if_empty!(self.client_id),
            pool_count: Some(self.pool_count),
            timestamp: Some(timestamp),
            privilege_key: None,
            metas: opt_if_empty!(self.metas),
            client_spec: self.client_spec.clone(),
            multiplexer: if propose_mux {
                Some("yamux".into())
            } else {
                None
            },
        };

        // Set auth: OIDC path or token path
        if let Some(ref oidc) = self.oidc_client {
            oidc.set_login(&mut login)
                .await
                .map_err(|e| frp_core::Error::Auth(format!("OIDC login: {e}").into()))?;
        } else {
            login.privilege_key = self.auth_cfg.generate_login_key(timestamp);
        }

        let login = FrpMessage::Login(Box::new(login));

        // Step 2: Send Login frame immediately after ClientHello (Go frp compat:
        // pipelined before ServerHello).
        if self.v2 {
            io_stream.write_v2_frame(&login).await?;
        } else {
            io_stream.write_v1_frame(&login).await?;
        }
        info!("Login sent, waiting for response...");

        // Step 3: Read ServerHello (Go frp compat: ServerHello arrives after Login).
        if self.v2 {
            if let Some(ch_json) = client_hello_json.take() {
                crypto_ctx = frp_core::v2_handshake::v2_handshake_client_recv_hello(
                    &mut io_stream,
                    &ch_json,
                    match self.transport_protocol {
                        TransportProtocol::Tcp => "tcp",
                        #[cfg(feature = "kcp")]
                        TransportProtocol::Kcp => "kcp",
                        #[cfg(feature = "quic")]
                        TransportProtocol::Quic => "quic",
                        #[cfg(feature = "websocket")]
                        TransportProtocol::WebSocket => "websocket",
                        #[cfg(feature = "websocket")]
                        TransportProtocol::Wss => "wss",
                        #[allow(unreachable_patterns)]
                        _ => "tcp",
                    },
                    self.tls_enable,
                    self.tcp_mux,
                    true, // with_crypto
                )
                .await?;
            }
        }

        // Step 4: Read LoginResp
        let resp_msg = if self.v2 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                io_stream.read_v2_frame(),
            )
            .await
            {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    return Err(frp_core::Error::Protocol(
                        format!("Login response read error: {e}").into(),
                    ))
                }
                Err(_) => {
                    return Err(frp_core::Error::Protocol(
                        "Login response timeout (10s)".into(),
                    ))
                }
            }
        } else {
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                io_stream.read_v1_frame(),
            )
            .await
            {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    return Err(frp_core::Error::Protocol(
                        format!("Login response read error: {e}").into(),
                    ))
                }
                Err(_) => {
                    return Err(frp_core::Error::Protocol(
                        "Login response timeout (10s)".into(),
                    ))
                }
            }
        };

        // If AEAD crypto negotiated, wrap stream after LoginResp (matching Go frp flow).
        // Login/LoginResp are exchanged in plaintext; all subsequent messages use AEAD.
        if self.v2 {
            if let Some(ref ctx) = crypto_ctx {
                let token = self.auth_cfg.token.clone();
                // derive_aead_control_keys returns (client_to_server, server_to_client)
                let (write_key, read_key) = frp_core::crypto::derive_aead_control_keys(
                    token.as_bytes(),
                    ctx.algorithm,
                    &ctx.transcript_hash,
                )
                .map_err(|e| frp_core::Error::Protocol(e.into()))?;
                // Client reads from server → server_to_client
                // Client writes to server → client_to_server
                let aead = frp_core::crypto::AeadStream::new(
                    Box::new(io_stream),
                    ctx.algorithm,
                    &read_key,
                    &write_key,
                )
                .map_err(|e| frp_core::Error::Protocol(e.into()))?;
                io_stream = IoStream::Aead(Box::new(aead));
            }
        }
        match resp_msg {
            FrpMessage::LoginResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Auth(
                        format!("Login failed: {}", err).into(),
                    ));
                }
                self.run_id = resp.run_id.clone().unwrap_or_default();
                self.server_auth_scopes = resp.server_additional_auth_scopes.unwrap_or_default();
                info!(run_id = %self.run_id, "Logged in. run_id: {}", self.run_id);
                #[cfg(feature = "quic")]
                {
                    Ok((io_stream, self.run_id.clone(), yamux_session, quic_conn))
                }
                #[cfg(not(feature = "quic"))]
                {
                    Ok((io_stream, self.run_id.clone(), yamux_session))
                }
            }
            _ => Err(frp_core::Error::Protocol(
                "Unexpected response to login".into(),
            )),
        }
    }

    /// Register a proxy with the server.
    pub async fn register_proxy(
        &self,
        p: &ProxyConfig,
        local_addr: &str,
        stream: &mut IoStream,
    ) -> Result<msg::NewProxyResp, frp_core::Error> {
        let np = proxy::create_new_proxy_msg(p, local_addr);
        debug!(json = %serde_json::to_string(&np).unwrap_or_default(), "NewProxy JSON: {}", serde_json::to_string(&np).unwrap_or_default());
        info!(name = %p.name, proxy_type = %p.proxy_type, remote_port = %p.remote_port, local_addr = %local_addr,
            "Registering proxy '{}' type={} remote_port={} local={}",
            p.name, p.proxy_type, p.remote_port, local_addr);
        if self.v2 {
            stream.write_v2_frame(&np).await?;
        } else {
            stream.write_v1_frame(&np).await?;
        }
        info!(name = %p.name, "NewProxy sent for '{}', waiting for response...", p.name);
        let mut iterations = 0u32;
        loop {
            if iterations >= 100 {
                return Err(frp_core::Error::Transport(TransportError::Other(format!(
                    "Proxy '{}' registration failed: too many non-response messages",
                    p.name
                ))));
            }
            iterations += 1;
            let resp_msg = if self.v2 {
                stream.read_v2_frame().await?
            } else {
                stream.read_v1_frame().await?
            };
            match resp_msg {
                FrpMessage::NewProxyResp(resp) => {
                    if let Some(err) = resp.error {
                        return Err(frp_core::Error::Transport(TransportError::Other(format!(
                            "Proxy '{}' registration failed: {err}",
                            p.name
                        ))));
                    }
                    info!(name = %p.name, remote_addr = ?resp.remote_addr, "Proxy '{}' registered on remote port {:?}", p.name, resp.remote_addr);
                    return Ok(resp);
                }
                FrpMessage::ReqWorkConn(_) => {
                    debug!("Skipping ReqWorkConn during proxy registration (pool conns spawned separately)");
                    continue;
                }
                other => {
                    warn!(proxy_name = %p.name, message = ?other, "Unexpected message during NewProxy registration for '{}': {:?}", p.name, other);
                    continue;
                }
            }
        }
    }

    /// Register an XTCP/STCP visitor on the control connection.
    /// Go frps v0.69.1 requires visitor registration before the visitor can
    /// send NatHoleVisitor on the control connection. Without this, the
    /// server responds with "auth failed".
    pub async fn register_visitor(
        &self,
        v: &VisitorConfig,
        stream: &mut IoStream,
    ) -> Result<msg::NewVisitorConnResp, frp_core::Error> {
        let nvc = crate::proxy::create_visitor_conn_msg(
            &v.server_name,
            &v.secret_key,
            v.use_encryption,
            v.use_compression,
        );
        debug!(server_name = %v.server_name, json = %serde_json::to_string(&nvc).unwrap_or_default(), "NewVisitorConn for '{}': {}", v.server_name,
            serde_json::to_string(&nvc).unwrap_or_default());
        info!(visitor_name = %v.name, proxy_name = %v.server_name, "Registering visitor '{}' for proxy '{}'", v.name, v.server_name);
        if self.v2 {
            stream.write_v2_frame(&nvc).await?;
        } else {
            stream.write_v1_frame(&nvc).await?;
        }
        let mut iterations = 0u32;
        loop {
            if iterations >= 100 {
                return Err(frp_core::Error::Transport(TransportError::Other(format!(
                    "Visitor '{}' registration failed: too many non-response messages",
                    v.name
                ))));
            }
            iterations += 1;
            let resp_msg = if self.v2 {
                stream.read_v2_frame().await?
            } else {
                stream.read_v1_frame().await?
            };
            match resp_msg {
                FrpMessage::NewVisitorConnResp(resp) => {
                    if let Some(err) = resp.error {
                        return Err(frp_core::Error::Transport(TransportError::Other(format!(
                            "Visitor '{}' registration failed: {err}",
                            v.name
                        ))));
                    }
                    info!(visitor_name = %v.name, proxy_name = %v.server_name, "Visitor '{}' registered for proxy '{}'", v.name, v.server_name);
                    return Ok(resp);
                }
                FrpMessage::ReqWorkConn(_) => {
                    // Go frps v0.69.1 responds to NewVisitorConn with ReqWorkConn
                    // instead of NewVisitorConnResp. Treat as success.
                    info!(visitor_name = %v.name, "Visitor '{}' registered (Go frps compat: ReqWorkConn after NewVisitorConn)", v.name);
                    return Ok(msg::NewVisitorConnResp {
                        proxy_name: v.server_name.clone(),
                        error: None,
                    });
                }
                other => {
                    warn!(visitor_name = %v.name, message = ?other, "Unexpected message during NewVisitorConn registration for '{}': {:?}", v.name, other);
                    continue;
                }
            }
        }
    }

    /// Send a ping to the server.
    pub async fn send_ping(
        writer: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<(), frp_core::Error> {
        let ping = FrpMessage::Ping(msg::Ping {
            privilege_key: None,
            timestamp: None,
        });
        write_msg_v1(writer, &ping).await
    }
}

/// Resolve the local hostname. Cached via OnceLock — blocking I/O runs in
/// `spawn_blocking` on first call to avoid stalling the tokio worker thread.
static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn resolve_hostname() -> String {
    // Read /etc/hostname
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // Fallback: run hostname command
    if let Ok(o) = std::process::Command::new("hostname").output() {
        if let Ok(s) = String::from_utf8(o.stdout) {
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }
    "unknown".into()
}

async fn hostname() -> String {
    if let Some(h) = HOSTNAME.get() {
        return h.clone();
    }
    let h = tokio::task::spawn_blocking(resolve_hostname)
        .await
        .unwrap_or_else(|_| "unknown".to_string());
    HOSTNAME.get_or_init(|| h).clone()
}
