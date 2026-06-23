use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn, error, debug};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use crate::proxy::{ProxyInfo, allocate_port};
use crate::service::{AppState, InternalMsg, ControlTx};

/// A pending request from a proxy listener waiting for a work connection.
struct PendingRequest {
    proxy_name: String,
    user_conn: TcpStream,
}

/// Handle a control connection from a frpc client.
/// The login message has already been consumed from the stream.
/// `peer` is passed separately because generic stream types don't have peer_addr().
pub async fn handle_control<S>(
    stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("New control connection from {:?}", peer);

    // --- Authenticate ---
    if let Err(e) = state.auth_cfg.validate_login(
        login.privilege_key.as_deref(),
        login.timestamp,
    ) {
        warn!("Authentication failed for {:?}: {}", peer, e);
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: None,
            server_udp_port: None,
            error: Some(e),
        });
        let (_, mut writer) = tokio::io::split(stream);
        let _ = write_msg_v1(&mut writer, &resp).await;
        return;
    }

    let run_id = login.run_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!("Client {:?} logged in with run_id: {}", peer, run_id);

    // --- Set up internal channel ---
    let (internal_tx, mut internal_rx) = mpsc::unbounded_channel::<InternalMsg>();

    // Register control channel so work-conn and proxy listeners can reach us
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        map.insert(run_id.clone(), ControlTx { tx: internal_tx.clone() });
    }

    // --- Split stream for reading/writing ---
    let (mut reader, mut writer) = tokio::io::split(stream);

    // --- Send login response ---
    let resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(run_id.clone()),
        server_udp_port: None,
        error: None,
    });
    if let Err(e) = write_msg_v1(&mut writer, &resp).await {
        warn!("Failed to send login response to {:?}: {}", peer, e);
        unregister_control(&state, &run_id).await;
        return;
    }

    // --- Per-client state ---
    let mut work_pool: VecDeque<IoStream> = VecDeque::new();
    let mut pending_requests: VecDeque<PendingRequest> = VecDeque::new();

    // --- Main select loop ---
    loop {
        tokio::select! {
            biased;

            // Prefer internal messages to reduce latency for proxy connections
            internal = internal_rx.recv() => {
                match internal {
                    Some(InternalMsg::NewWorkConn(stream)) => {
                        debug!("Got work conn for run_id {}", run_id);
                        if let Some(req) = pending_requests.pop_front() {
                            assign_work_to_proxy(stream, req).await;
                        } else {
                            work_pool.push_back(stream);
                            debug!("Work conn pooled for {} (pool size: {})", run_id, work_pool.len());
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn }) => {
                        debug!("User conn for proxy {} on run_id {}", proxy_name, run_id);
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn }).await;
                        } else {
                            debug!("No pooled work conn, sending ReqWorkConn for {}", proxy_name);
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn });
                        }
                    }
                    None => {
                        info!("Control channel closed for {:?}", peer);
                        break;
                    }
                }
            }

            msg = read_msg_v1(&mut reader) => {
                match msg {
                    Ok(FrpMessage::NewProxy(np)) => {
                        handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx).await;
                    }
                    Ok(FrpMessage::CloseProxy(cp)) => {
                        state.proxy_manager.remove(&cp.proxy_name).await;
                        info!("Proxy closed: {}", cp.proxy_name);
                    }
                    Ok(FrpMessage::Ping(_)) => {
                        let pong = FrpMessage::Pong(msg::Pong {});
                        if let Err(e) = write_msg_v1(&mut writer, &pong).await {
                            warn!("Failed to send pong: {}", e);
                            break;
                        }
                        debug!("Ping from {:?}", peer);
                    }
                    Ok(_) => {
                        debug!("Unhandled message from {:?}", peer);
                    }
                    Err(e) => {
                        info!("Control connection {:?} closed: {}", peer, e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    unregister_control(&state, &run_id).await;
    state.proxy_manager.remove_client(&run_id).await;
    info!("Control connection {} removed", run_id);
}

/// Assign a work connection to a pending proxy request.
async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
) {
    let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        dst_addr: None,
        dst_port: None,
        error: None,
    });

    let write_result = match &mut work_conn {
        IoStream::Tcp(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Tls(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::WebSocket(_) => {
            warn!("WebSocket work conn not supported for bridging");
            return;
        }
    };

    if let Err(e) = write_result {
        warn!("Failed to send StartWorkConn: {}", e);
        return;
    }

    info!("Bridging user conn to work conn for proxy '{}'", req.proxy_name);

    tokio::spawn(async move {
        match work_conn {
            IoStream::Tcp(mut work) => {
                let mut user = req.user_conn;
                if let Err(e) = tokio::io::copy_bidirectional(&mut user, &mut work).await {
                    debug!("Proxy '{}' bridge closed: {}", req.proxy_name, e);
                }
            }
            IoStream::Tls(mut work) => {
                let mut user = req.user_conn;
                if let Err(e) = tokio::io::copy_bidirectional(&mut user, &mut work).await {
                    debug!("Proxy '{}' bridge (TLS) closed: {}", req.proxy_name, e);
                }
            }
            IoStream::WebSocket(_) => {
                warn!("WebSocket bridging not implemented");
            }
        }
        info!("Proxy '{}' bridge completed", req.proxy_name);
    });
}

/// Register a new proxy and start listening on its assigned port.
async fn handle_new_proxy(
    np: msg::NewProxy,
    run_id: &str,
    state: &Arc<AppState>,
    writer: &mut (impl AsyncWriteExt + Unpin),
    internal_tx: &mpsc::UnboundedSender<InternalMsg>,
) {
    let remote_port = np.remote_port.unwrap_or(0) as u16;

    let allocated_port = {
        let mut ports = state.used_ports.write().await;
        allocate_port(&mut ports, remote_port, 100, 10000)
    };

    match allocated_port {
        Some(port) => {
            let info = ProxyInfo {
                name: np.proxy_name.clone(),
                proxy_type: np.proxy_type.clone(),
                run_id: run_id.to_string(),
                remote_port: Some(port),
                sk: np.sk.clone(),
                group: np.group.clone(),
                group_key: np.group_key.clone(),
                local_addr: np.local_str.clone(),
            };

            if let Err(e) = state.proxy_manager.register(run_id.to_string(), info.clone()).await {
                let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                    proxy_name: np.proxy_name.clone(),
                    remote_port: None,
                    error: Some(e),
                });
                let _ = write_msg_v1(writer, &resp).await;
                return;
            }

            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();

            tokio::spawn(async move {
                listen_and_proxy(port, pn, itx).await;
            });

            info!("Proxy '{}' registered on port {} (run_id: {})", np.proxy_name, port, run_id);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_port: Some(port as i32),
                error: None,
            });
            let _ = write_msg_v1(writer, &resp).await;
        }
        None => {
            warn!("No available port for proxy '{}'", np.proxy_name);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_port: None,
                error: Some("no available port".into()),
            });
            let _ = write_msg_v1(writer, &resp).await;
        }
    }
}

/// Listen on a proxy port and forward incoming connections to the control handler.
async fn listen_and_proxy(
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!("Proxy listener started on {} for '{}'", addr, proxy_name);
            l
        }
        Err(e) => {
            error!("Failed to bind proxy port {}: {}", port, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((user_conn, _addr)) => {
                if internal_tx.send(InternalMsg::ProxyUserConn {
                    proxy_name: proxy_name.clone(),
                    user_conn,
                }).is_err() {
                    warn!("Control handler gone, stopping proxy listener for '{}'", proxy_name);
                    break;
                }
            }
            Err(e) => {
                error!("Accept error on proxy port {}: {}", port, e);
                break;
            }
        }
    }
}

async fn unregister_control(state: &Arc<AppState>, run_id: &str) {
    let mut map = state.run_id_to_ctl_tx.write().await;
    map.remove(run_id);
}
