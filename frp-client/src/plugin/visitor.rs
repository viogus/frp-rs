use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

use frp_core::auth::AuthConfig;
use frp_core::config::PluginConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::{self, DialOptions, TransportProtocol};
use frp_core::VERSION;

use super::{PluginHandle, PluginContext};

/// Start a visitor plugin that tunnels connections to a remote STCP/XTCP proxy.
///
/// Binds a local TCP listener. Each accepted connection: dials frps, authenticates,
/// sends NewVisitorConn, reads response, bridges bidirectionally.
pub async fn start_visitor_plugin(
    cfg: &PluginConfig,
    ctx: PluginContext,
) -> Result<PluginHandle, frp_core::Error> {
    let bind_addr = if !cfg.local_addr.is_empty() {
        cfg.local_addr.clone()
    } else {
        "127.0.0.1:0".to_string()
    };

    let server_name = cfg.server_name.clone();
    let secret_key = cfg.secret_key.clone();

    if server_name.is_empty() {
        return Err(frp_core::Error::Config(
            "visitor_plugin: serverName is required".into()
        ));
    }

    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin bind {}: {}", bind_addr, e))
    })?;
    let local_addr = listener.local_addr().map_err(|e| {
        frp_core::Error::Transport(format!("visitor plugin local_addr: {}", e))
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

    let task = tokio::spawn(async move {
        debug!("visitor plugin listening on {}", local_addr);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    debug!("visitor plugin shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((user_conn, peer)) => {
                            debug!("visitor plugin: new connection from {}", peer);
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

                            tokio::spawn(async move {
                                if let Err(e) = handle_visitor_conn(
                                    user_conn, &sn, &sk, &at, &sa, sp, te, &tsn,
                                    tcf.as_deref(), ue, uc, &tp, oidc,
                                ).await {
                                    debug!("visitor plugin handler: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            warn!("visitor plugin: accept error: {}", e);
                            break;
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
) -> Result<(), String> {
    // 1. Dial frps server
    let protocol = match transport_protocol {
        "kcp" => TransportProtocol::Kcp,
        "quic" => TransportProtocol::Quic,
        "websocket" => TransportProtocol::WebSocket,
        _ => TransportProtocol::Tcp,
    };
    let opts = DialOptions {
        server_addr: server_addr.to_string(),
        server_port,
        protocol,
        tls_enable,
        tls_server_name: tls_server_name.to_string(),
        tls_ca_file: tls_ca_file.map(|s| s.to_string()),
        ..Default::default()
    };
    let mut server_stream = transport::dial_server(&opts).await
        .map_err(|e| format!("dial server: {e}"))?;

    // 2. Login
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let auth_cfg = AuthConfig {
        token: auth_token.to_string(),
        ..Default::default()
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
        oidc.set_login(&mut login).await.map_err(|e| format!("OIDC: {e}"))?;
    } else {
        login.privilege_key = auth_cfg.generate_login_key(timestamp);
    }
    write_msg_v1(&mut server_stream, &FrpMessage::Login(login)).await
        .map_err(|e| format!("write login: {e}"))?;

    match read_msg_v1(&mut server_stream).await.map_err(|e| format!("read login resp: {e}"))? {
        FrpMessage::LoginResp(resp) => {
            if let Some(err) = resp.error {
                return Err(format!("login rejected: {err}"));
            }
        }
        other => return Err(format!("unexpected login response: {:?}", other)),
    }

    // 3. Send NewVisitorConn
    let nvc = crate::proxy::create_visitor_conn_msg(
        server_name, secret_key, use_encryption, use_compression,
    );
    write_msg_v1(&mut server_stream, &nvc).await
        .map_err(|e| format!("write NewVisitorConn: {e}"))?;

    // 4. Read NewVisitorConnResp
    match read_msg_v1(&mut server_stream).await.map_err(|e| format!("read NewVisitorConnResp: {e}"))? {
        FrpMessage::NewVisitorConnResp(resp) => {
            if let Some(err) = resp.error {
                return Err(format!("visitor conn rejected: {err}"));
            }
        }
        other => return Err(format!("unexpected visitor response: {:?}", other)),
    }

    // 5. Bridge user_conn ↔ server_stream
    let (mut u_r, mut u_w) = tokio::io::split(user_conn);
    let (mut s_r, mut s_w) = server_stream.into_split();

    let a = tokio::spawn(async move {
        let n = tokio::io::copy(&mut u_r, &mut s_w).await;
        let _ = s_w.shutdown().await;
        n
    });
    let b = tokio::spawn(async move {
        let n = tokio::io::copy(&mut s_r, &mut u_w).await;
        let _ = u_w.shutdown().await;
        n
    });

    match tokio::join!(a, b) {
        (Ok(n1), Ok(n2)) => debug!("visitor plugin: bridge done ({:?}B→server, {:?}B→user)", n1, n2),
        (Err(e), _) | (_, Err(e)) => debug!("visitor plugin: bridge closed: {}", e),
    }

    Ok(())
}
