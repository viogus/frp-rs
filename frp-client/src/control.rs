use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::msg::{self, ClientSpec, FrpMessage};
use frp_core::mux::{self, YamuxSession};
use frp_core::protocol::write_msg_v1;
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{dial_server, DialOptions, IoStream, TransportProtocol};
use frp_core::VERSION;

use crate::util::opt_if_empty;

#[cfg(feature = "quic")]
type LoginRet = (
    IoStream,
    String,
    Option<YamuxSession>,
    Option<QuicConnection>,
    String,
);
#[cfg(not(feature = "quic"))]
type LoginRet = (IoStream, String, Option<YamuxSession>, String);

/// Whether the control connection should wrap its transport stream in yamux
/// when `tcp_mux` is enabled. Go frp v0.70.1 applies yamux over TCP, KCP,
/// WebSocket, and WSS; QUIC remains unmuxed.
fn propose_mux_for_transport(tcp_mux: bool, protocol: &TransportProtocol) -> bool {
    if !tcp_mux {
        return false;
    }
    match protocol {
        TransportProtocol::Tcp => true,
        #[cfg(feature = "kcp")]
        TransportProtocol::Kcp => true,
        #[cfg(feature = "websocket")]
        TransportProtocol::WebSocket => true,
        #[cfg(feature = "websocket")]
        TransportProtocol::Wss => true,
        // Reachable when the relevant transport feature is disabled.
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

/// Wrap an established client transport stream in yamux (matching Go frp
/// v0.70.1, which wraps the connector result for every non-QUIC transport).
pub(crate) async fn wrap_client_mux(
    raw_stream: IoStream,
    keepalive_interval: i64,
) -> Result<(IoStream, Option<YamuxSession>), frp_core::Error> {
    let mux_cfg = mux::TcpMuxConfig {
        keepalive_interval: Duration::from_secs(keepalive_interval.max(1) as u64),
        max_stream_window_size: 6 * 1024 * 1024,
    };
    // Go frp v0.70.1 wraps every non-QUIC transport in yamux; QUIC never
    // gets wrapped (the QUIC connection itself multiplexes streams).
    let transport_name = raw_stream.debug_name();
    if raw_stream.is_yamux_wrappable() {
        let (control_stream, session) = mux::client_mux(raw_stream.into_boxed(), &mux_cfg).await?;
        info!(transport = %transport_name, "Yamux session established over {}", transport_name);
        Ok((IoStream::Yamux(control_stream), Some(session)))
    } else {
        warn!(transport = %transport_name, "Unexpected transport for mux proposal — yamux not applied");
        Ok((raw_stream, None))
    }
}

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
    tls_skip_verify: bool,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
    dns_server: Option<String>,
    tcp_mux: bool,
    disable_custom_tls_first_byte: bool,
    keepalive_secs: u64,
    tcp_mux_keepalive_interval: i64,
    bind_addr: Option<String>,
    v2: bool,
    /// SO_SNDBUF (0 = OS default). frp-rs extension.
    tcp_send_buffer_size: u32,
    /// SO_RCVBUF (0 = OS default). frp-rs extension.
    tcp_recv_buffer_size: u32,
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
    /// QUIC transport parameters (keepalive / idle timeout / max streams).
    /// Go frp compat: [transport.quic].
    #[cfg(feature = "quic")]
    quic_params: frp_core::quic::QuicTransportParams,
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
        tls_skip_verify: bool,
        tls_cert_file: Option<String>,
        tls_key_file: Option<String>,
        dns_server: Option<String>,
        tcp_mux: bool,
        disable_custom_tls_first_byte: bool,
        keepalive_secs: u64,
        tcp_mux_keepalive_interval: i64,
        bind_addr: Option<String>,
        v2: bool,
        tcp_send_buffer_size: u32,
        tcp_recv_buffer_size: u32,
        oidc_client: Option<Arc<OidcClient>>,
        metas: std::collections::HashMap<String, String>,
        proxy_url: String,
        previous_run_id: String,
        client_spec: Option<ClientSpec>,
        dial_server_timeout: i64,
        #[cfg(feature = "quic")] quic_params: frp_core::quic::QuicTransportParams,
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
            tls_skip_verify,
            tls_cert_file,
            tls_key_file,
            dns_server,
            tcp_mux,
            disable_custom_tls_first_byte,
            keepalive_secs,
            tcp_mux_keepalive_interval,
            bind_addr,
            v2,
            tcp_send_buffer_size,
            tcp_recv_buffer_size,
            oidc_client,
            server_auth_scopes: Vec::new(),
            metas,
            proxy_url,
            client_spec,
            dial_server_timeout,
            #[cfg(feature = "quic")]
            quic_params,
        }
    }

    /// Connect to the server and login.
    /// Returns the control stream, run_id, optional yamux session, and optional
    /// QUIC connection (for opening additional streams for work connections).
    pub async fn login(&mut self) -> Result<LoginRet, frp_core::Error> {
        // Go frp servers with tcpMux=true wrap every incoming non-QUIC
        // connection in yamux immediately, so the client MUST wrap BEFORE
        // sending Login. This applies to TCP, TLS, KCP, WebSocket, and WSS
        // (yamux sits on top of the transport stream).
        let propose_mux = propose_mux_for_transport(self.tcp_mux, &self.transport_protocol);

        let opts = DialOptions {
            server_addr: self.server_addr.clone(),
            server_port: self.server_port,
            protocol: self.transport_protocol.clone(),
            tls_enable: self.tls_enable,
            tls_server_name: self.tls_server_name.clone(),
            tls_ca_file: self.tls_ca_file.clone(),
            tls_skip_verify: self.tls_skip_verify,
            tls_cert_file: self.tls_cert_file.clone(),
            tls_key_file: self.tls_key_file.clone(),
            dns_server: self.dns_server.clone(),
            disable_custom_tls_first_byte: self.disable_custom_tls_first_byte,
            keepalive_secs: self.keepalive_secs,
            bind_addr: self.bind_addr.clone(),
            tcp_send_buffer_size: self.tcp_send_buffer_size,
            tcp_recv_buffer_size: self.tcp_recv_buffer_size,
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
                let (stream, qc) = frp_core::quic::dial_quic_with_params(
                    &addr,
                    server_name,
                    ca_file,
                    self.tls_cert_file.as_deref(),
                    self.tls_key_file.as_deref(),
                    self.quic_params.clone(),
                    Some(self.dial_server_timeout as u64),
                )
                .await
                .map_err(|e| frp_core::Error::Transport(format!("QUIC dial: {e}").into()))?;
                (IoStream::Quic(stream), None, Some(qc))
            } else {
                let raw_stream = dial_server(&opts).await?;
                // Wrap in yamux BEFORE V2 handshake (matches Go frp flow).
                // The server wraps its side on accept, so the client must wrap
                // before sending ClientHello.
                if propose_mux {
                    let (io_stream, session) =
                        wrap_client_mux(raw_stream, self.tcp_mux_keepalive_interval).await?;
                    (io_stream, session, None)
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
                let (io_stream, session) =
                    wrap_client_mux(raw_stream, self.tcp_mux_keepalive_interval).await?;
                (io_stream, session)
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

        // Milliseconds precision: the server's duplicate-(run_id, ts) replay
        // detection keys on this value, and frpc reuses its run_id across
        // reconnects — a seconds-precision ts collides when a reconnect
        // happens within the same second (false "replay attack" rejection).
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

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
            login.privilege_key = Some(
                self.auth_cfg
                    .try_generate_login_key(timestamp)
                    .map_err(|e| frp_core::Error::Auth(e.into()))?,
            );
        }

        let login = FrpMessage::Login(Box::new(login));

        // Step 2: Send Login frame immediately after ClientHello (Go frp compat:
        // pipelined before ServerHello).
        //
        // SECURITY: V2 Login (containing privilege_key) is sent as a plaintext
        // V2 frame before AEAD keys are derived from the handshake. Without
        // transport encryption (TLS or QUIC's built-in TLS 1.3), a passive
        // network observer can capture the privilege_key credential.
        // This matches Go frp's protocol design: ClientHello/ServerHello +
        // Login/LoginResp are always plaintext at the V2 frame level; AEAD
        // encryption is established only after login completes.
        // Enable tls_enable or use QUIC transport to protect credentials.
        #[cfg(feature = "quic")]
        let transport_encrypted =
            self.tls_enable || matches!(self.transport_protocol, TransportProtocol::Quic);
        #[cfg(not(feature = "quic"))]
        let transport_encrypted = self.tls_enable;
        if self.v2 && !transport_encrypted {
            warn!(
                "V2 Login credential sent in plaintext: tls_enable=false and \
                 transport={} is not encrypted. Enable tls_enable or use QUIC \
                 to protect the privilege_key from passive network observers.",
                match self.transport_protocol {
                    TransportProtocol::Tcp => "TCP",
                    #[cfg(feature = "kcp")]
                    TransportProtocol::Kcp => "KCP",
                    #[cfg(feature = "websocket")]
                    TransportProtocol::WebSocket => "WebSocket",
                    #[cfg(feature = "websocket")]
                    TransportProtocol::Wss => "WSS",
                    #[allow(unreachable_patterns)]
                    _ => "unknown",
                }
            );
        }
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
                    let udp_codec = crypto_ctx
                        .as_ref()
                        .map(|c| c.udp_packet_codec.clone())
                        .unwrap_or_default();
                    Ok((
                        io_stream,
                        self.run_id.clone(),
                        yamux_session,
                        quic_conn,
                        udp_codec,
                    ))
                }
                #[cfg(not(feature = "quic"))]
                {
                    let udp_codec = crypto_ctx
                        .as_ref()
                        .map(|c| c.udp_packet_codec.clone())
                        .unwrap_or_default();
                    Ok((io_stream, self.run_id.clone(), yamux_session, udp_codec))
                }
            }
            _ => Err(frp_core::Error::Protocol(
                "Unexpected response to login".into(),
            )),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propose_mux_covers_non_tcp_transports_and_skips_quic() {
        assert!(propose_mux_for_transport(true, &TransportProtocol::Tcp));
        #[cfg(feature = "kcp")]
        assert!(propose_mux_for_transport(true, &TransportProtocol::Kcp));
        #[cfg(feature = "websocket")]
        assert!(propose_mux_for_transport(
            true,
            &TransportProtocol::WebSocket
        ));
        #[cfg(feature = "websocket")]
        assert!(propose_mux_for_transport(true, &TransportProtocol::Wss));
        #[cfg(feature = "quic")]
        assert!(!propose_mux_for_transport(true, &TransportProtocol::Quic));

        assert!(!propose_mux_for_transport(false, &TransportProtocol::Tcp));
        #[cfg(feature = "kcp")]
        assert!(!propose_mux_for_transport(false, &TransportProtocol::Kcp));
    }
}
