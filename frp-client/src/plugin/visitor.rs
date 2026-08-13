use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use frp_core::auth::{AuthConfig, AuthMethod};
use frp_core::config::PluginConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::{self, BoxedReadHalf, BoxedWriteHalf, DialOptions, TransportProtocol};
use frp_core::VERSION;

use super::{PluginContext, PluginHandle};

/// Recombine split read/write halves into a duplex stream for
/// `copy_bidirectional_with_sizes`.
struct Duplex<R, W> {
    r: R,
    w: W,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Duplex<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.r).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for Duplex<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.w).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.w).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.w).poll_shutdown(cx)
    }
}

/// Start a visitor plugin that tunnels connections to a remote STCP/XTCP proxy.
///
/// Binds a local TCP listener unless `bind_port == -1` (no-bind mode).
/// Each accepted connection: dials frps, authenticates, sends NewVisitorConn,
/// reads response, bridges bidirectionally.
pub async fn start_visitor_plugin(
    cfg: &PluginConfig,
    ctx: PluginContext,
) -> Result<PluginHandle, frp_core::Error> {
    let server_name = cfg.server_name.clone();
    let secret_key = cfg.secret_key.clone();

    if server_name.is_empty() {
        return Err(frp_core::Error::Config(
            "visitor_plugin: serverName is required".into(),
        ));
    }

    // Determine bind address: bind_addr:bind_port takes priority.
    // Fall back to local_addr for backward compatibility.
    // bind_port == -1 disables the local listener (no-bind mode).
    let no_bind = cfg.bind_port == -1;
    let bind_addr = if no_bind {
        String::new()
    } else if !cfg.bind_addr.is_empty() {
        format!("{}:{}", cfg.bind_addr, cfg.bind_port.max(0))
    } else if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        "127.0.0.1:0".to_string()
    };

    // In no-bind mode, return a handle with no listener task.
    if no_bind {
        debug!("visitor plugin: no-bind mode (bindPort = -1), skipping listener");
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        return Ok(PluginHandle {
            local_addr: "0.0.0.0:0"
                .parse()
                .expect("constant literal socket addr always parses"),
            _task: tokio::spawn(std::future::ready(())),
            shutdown: Some(shutdown_tx),
        });
    }

    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin bind {}: {}", bind_addr, e).into())
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin local_addr: {}", e).into())
    })?;

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let auth_token = ctx.token.clone();
    let server_addr = ctx.server_addr.clone();
    let server_port = ctx.server_port;
    let tls_enable = ctx.tls_enable;
    let tls_server_name = ctx.tls_server_name.clone();
    let tls_ca_file = ctx.tls_ca_file.clone();
    let use_encryption = ctx.use_encryption;
    let use_compression = ctx.use_compression;
    let transport_protocol = ctx.transport_protocol.clone();
    let oidc_client = ctx.oidc_client.clone();
    let ctx_tcp_mux = ctx.tcp_mux;
    let ctx_tcp_mux_keepalive = ctx.tcp_mux_keepalive_interval;
    let ctx_dns = ctx.dns_server.clone();
    let ctx_keepalive = ctx.keepalive_secs;
    let ctx_bind = ctx.connect_bind_addr.clone();
    let ctx_tls_cert = ctx.tls_cert_file.clone();
    let ctx_tls_key = ctx.tls_key_file.clone();
    let ctx_proxy = ctx.proxy_url.clone();
    let ctx_nocustomtls = ctx.disable_custom_tls_first_byte;
    let ctx_dial_timeout = ctx.dial_timeout_secs;

    let task = tokio::spawn(async move {
        debug!(local_addr = %local_addr, "visitor plugin listening on {}", local_addr);
        // Throttle accept-error warnings: under persistent EMFILE the loop
        // fails ~10/s (100ms pause below), which would flood the logs.
        let mut last_accept_warn: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("visitor plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((user_conn, peer)) => {
                            // Disable Nagle for low-latency interactive data
                            // (Go frp parity: user connections use NoDelay(true)).
                            frp_core::transport::set_nodelay(&user_conn);
                            debug!(peer = %peer, "visitor plugin: new connection from {}", peer);
                            let sn = server_name.clone();
                            let sk = secret_key.clone();
                            let at = auth_token.clone();
                            let sa = server_addr.clone();
                            let sp = server_port;
                            let te = tls_enable;
                            let tsn = tls_server_name.clone();
                            let tcf = tls_ca_file.clone();
                            let ue = use_encryption;
                            let uc = use_compression;
                            let tp = transport_protocol.clone();
                            let oidc = oidc_client.clone();

                            let ctx_v2 = ctx.v2;

                            let dns = ctx_dns.clone();
                            let bind = ctx_bind.clone();
                            let tls_cert = ctx_tls_cert.clone();
                            let tls_key = ctx_tls_key.clone();
                            let proxy = ctx_proxy.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_visitor_conn(
                                    user_conn, &sn, &sk, &at, &sa, sp, te, &tsn,
                                    tcf.as_deref(), ue, uc, &tp, oidc,
                                    ctx_tcp_mux, ctx_tcp_mux_keepalive,
                                    &dns, ctx_keepalive, &bind,
                                    &tls_cert, &tls_key, &proxy,
                                    ctx_nocustomtls, ctx_dial_timeout,
                                    ctx_v2,
                                ).await {
                                    debug!(error = %e, "visitor plugin handler: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            // Warn at most once per second while the accept
                            // failure persists (the first failure warns too).
                            if last_accept_warn
                                .map(|t| t.elapsed() >= Duration::from_secs(1))
                                .unwrap_or(true)
                            {
                                warn!(error = %e, "visitor plugin: accept error: {}", e);
                                last_accept_warn = Some(std::time::Instant::now());
                            }
                            // Transient accept errors (EMFILE/ENFILE fd
                            // exhaustion, etc.) must not kill the listener:
                            // Go's Accept loop retries (same pattern as
                            // serve_plugin). Pause briefly to avoid
                            // hot-spinning while the condition persists; only
                            // the shutdown signal breaks the loop.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    });

    Ok(PluginHandle {
        local_addr,
        _task: task,
        shutdown: Some(shutdown_tx),
    })
}

/// Handle one visitor connection: dial frps, login, send NewVisitorConn, bridge.
#[allow(clippy::too_many_arguments)]
async fn handle_visitor_conn(
    user_conn: tokio::net::TcpStream,
    server_name: &str,
    secret_key: &str,
    auth_token: &str,
    server_addr: &str,
    server_port: u16,
    tls_enable: bool,
    tls_server_name: &str,
    tls_ca_file: Option<&str>,
    use_encryption: bool,
    use_compression: bool,
    transport_protocol: &str,
    oidc_client: Option<Arc<frp_core::auth::OidcClient>>,
    // Transport options
    tcp_mux: bool,
    tcp_mux_keepalive_interval: i64,
    dns_server: &Option<String>,
    keepalive_secs: u64,
    bind_addr: &Option<String>,
    tls_cert_file: &Option<String>,
    tls_key_file: &Option<String>,
    proxy_url: &Option<String>,
    disable_custom_tls_first_byte: bool,
    dial_timeout_secs: u64,
    v2: bool,
) -> Result<(), String> {
    // 1. Dial frps server
    let protocol = match transport_protocol {
        #[cfg(feature = "kcp")]
        "kcp" => TransportProtocol::Kcp,
        #[cfg(feature = "quic")]
        "quic" => TransportProtocol::Quic,
        #[cfg(feature = "websocket")]
        "websocket" | "wss" => TransportProtocol::WebSocket,
        _ => TransportProtocol::Tcp,
    };
    let opts = DialOptions {
        server_addr: server_addr.to_string(),
        server_port,
        protocol,
        tls_enable,
        tls_server_name: tls_server_name.to_string(),
        tls_ca_file: tls_ca_file.map(|s| s.to_string()),
        tls_cert_file: tls_cert_file.clone(),
        tls_key_file: tls_key_file.clone(),
        dns_server: dns_server.clone(),
        disable_custom_tls_first_byte,
        keepalive_secs,
        bind_addr: bind_addr.clone(),
        proxy_url: proxy_url.clone(),
        dial_timeout_secs,
        v2,
    };
    let raw_stream = transport::dial_server(&opts)
        .await
        .map_err(|e| format!("dial server: {e}"))?;
    // Wrap in yamux when tcp_mux is enabled (Go frp compat).
    let mut _yamux_sess: Option<YamuxSession> = None;
    let mut server_stream = if tcp_mux {
        match crate::control::wrap_client_mux(raw_stream, tcp_mux_keepalive_interval).await {
            Ok((io, session)) => {
                _yamux_sess = session;
                io
            }
            Err(e) => return Err(format!("yamux wrap: {e}")),
        }
    } else {
        raw_stream
    };

    // Bound the handshake response waits (mirrors
    // read_start_work_conn_with_timeout in work_conn.rs): a server that
    // accepts the dial but never answers must not pin this connection's
    // task (and its user connection) forever.
    let resp_timeout = Duration::from_secs(dial_timeout_secs.max(1));

    // 2. Login
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let auth_cfg = AuthConfig {
        method: AuthMethod::Token,
        token: auth_token.to_string(),
        token_source: None,
        oidc_issuer: String::new(),
        oidc_audience: String::new(),
        oidc_skip_expiry: false,
        oidc_skip_issuer: false,
        oidc_skip_nbf: false,
        oidc_skip_audience: false,
        oidc_additional_audience: Vec::new(),
        oidc_tls_trusted_ca_file: String::new(),
        additional_data: None,
        oidc_proxy_url: String::new(),
        additional_auth_scopes: Vec::new(),
        authentication_timeout: 0,
        token_auth_timeout: true,
        use_encryption: false,
    };
    let mut login = msg::Login {
        version: Some(VERSION.into()),
        hostname: None,
        os: None,
        arch: None,
        user: None,
        run_id: None,
        client_id: None,
        pool_count: Some(1),
        timestamp: Some(timestamp),
        privilege_key: None,
        metas: None,
        client_spec: None,
        multiplexer: None,
    };
    if let Some(ref oidc) = oidc_client {
        oidc.set_login(&mut login)
            .await
            .map_err(|e| format!("OIDC: {e}"))?;
    } else {
        login.privilege_key = auth_cfg.generate_login_key(timestamp);
    }
    write_msg_v1(&mut server_stream, &FrpMessage::Login(Box::new(login)))
        .await
        .map_err(|e| format!("write login: {e}"))?;

    match tokio::time::timeout(resp_timeout, read_msg_v1(&mut server_stream))
        .await
        .map_err(|_| format!("read login resp: timeout after {}s", resp_timeout.as_secs()))?
        .map_err(|e| format!("read login resp: {e}"))?
    {
        FrpMessage::LoginResp(resp) => {
            if let Some(err) = resp.error {
                return Err(format!("login rejected: {err}"));
            }
        }
        other => return Err(format!("unexpected login response: {:?}", other)),
    }

    // 3. Send NewVisitorConn
    // Note: plugin visitors have no user/run_id context; pass None.
    let nvc = crate::proxy::create_visitor_conn_msg(
        server_name,
        secret_key,
        use_encryption,
        use_compression,
        None,
        None,
        None,
    );
    write_msg_v1(&mut server_stream, &nvc)
        .await
        .map_err(|e| format!("write NewVisitorConn: {e}"))?;

    // 4. Read NewVisitorConnResp
    match tokio::time::timeout(resp_timeout, read_msg_v1(&mut server_stream))
        .await
        .map_err(|_| {
            format!(
                "read NewVisitorConnResp: timeout after {}s",
                resp_timeout.as_secs()
            )
        })?
        .map_err(|e| format!("read NewVisitorConnResp: {e}"))?
    {
        FrpMessage::NewVisitorConnResp(resp) => {
            if let Some(err) = resp.error {
                return Err(format!("visitor conn rejected: {err}"));
            }
        }
        other => return Err(format!("unexpected visitor response: {:?}", other)),
    }

    // 5. Bridge user_conn ↔ server_stream
    let (u_r, u_w) = tokio::io::split(user_conn);
    let (s_r, s_w) = match frp_core::transport::split_work_conn_halves(server_stream) {
        Ok(pair) => pair,
        Err(e) => {
            return Err(format!(
                "visitor plugin: could not split server stream: {e}"
            ))
        }
    };

    // Visitor-segment encryption/compression, symmetric with the server's
    // `split_user_side` (Go three-segment model stage 1): the server wraps
    // its user-side half in CipherReader/CipherWriter (`derive_key(sk)`) and
    // SnappyStream when the visitor declared use_encryption/use_compression,
    // so the plugin bridge must apply the same wrappers (snappy inner, CFB
    // outer) or the server would decrypt/decompress a plaintext stream.
    let use_enc = use_encryption && !secret_key.is_empty();
    let enc_key = use_enc.then(|| frp_core::encryption::derive_key(secret_key));
    let s_r: BoxedReadHalf = if use_compression {
        let inner: BoxedReadHalf = if let Some(key) = enc_key {
            Box::new(frp_core::cipher_stream::CipherReader::new(s_r, key))
        } else {
            s_r
        };
        Box::new(frp_core::snappy_stream::SnappyStreamReader::new(inner))
    } else if let Some(key) = enc_key {
        Box::new(frp_core::cipher_stream::CipherReader::new(s_r, key))
    } else {
        s_r
    };
    let s_w: BoxedWriteHalf = if use_compression {
        let inner: BoxedWriteHalf = if let Some(key) = enc_key {
            Box::new(frp_core::cipher_stream::CipherWriter::new(s_w, key))
        } else {
            s_w
        };
        Box::new(frp_core::snappy_stream::SnappyStreamWriter::new(inner))
    } else if let Some(key) = enc_key {
        Box::new(frp_core::cipher_stream::CipherWriter::new(s_w, key))
    } else {
        s_w
    };

    let mut user_side = Duplex { r: u_r, w: u_w };
    let mut server_side = Duplex { r: s_r, w: s_w };
    match tokio::io::copy_bidirectional_with_sizes(
        &mut user_side,
        &mut server_side,
        *frp_core::buffer_pool::BUFFER_SIZE,
        *frp_core::buffer_pool::BUFFER_SIZE,
    )
    .await
    {
        Ok((n1, n2)) => {
            debug!(n1 = ?n1, n2 = ?n2, "visitor plugin: bridge done ({:?}B→server, {:?}B→user)", n1, n2)
        }
        Err(e) => debug!(error = %e, "visitor plugin: bridge closed: {}", e),
    }

    Ok(())
}
