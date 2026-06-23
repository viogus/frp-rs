use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tracing::{info, warn, debug};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;

use crate::proxy::{ProxyInfo, allocate_port};
use crate::service::{AppState, InternalMsg, ControlTx};

/// A pending request from a proxy listener waiting for a work connection.
struct PendingRequest {
    proxy_name: String,
    user_conn: TcpStream,
    pre_read: Vec<u8>,
    use_encryption: bool,
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
                    Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
                        debug!("STCP visitor conn for proxy {} on run_id {}", proxy_name, run_id);
                        let tcp = match visitor_conn {
                            IoStream::Tcp(s) => s,
                            _ => { warn!("STCP visitor requires TCP stream"); return; }
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn: tcp, pre_read: Vec::new(), use_encryption: false }).await;
                        } else {
                            debug!("No pooled work conn for STCP, sending ReqWorkConn");
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn: tcp, pre_read: Vec::new(), use_encryption: false });
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
                        // Extract TcpStream from IoStream for PendingRequest
                        let tcp = match user_conn {
                            IoStream::Tcp(s) => s,
                            _ => {
                                warn!("Unsupported user connection type for proxy {}", proxy_name);
                                return;
                            }
                        };
                        debug!("User conn for proxy {} on run_id {}", proxy_name, run_id);
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn: tcp, pre_read, use_encryption: false }).await;
                        } else {
                            debug!("No pooled work conn, sending ReqWorkConn for {}", proxy_name);
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            let enc = state.proxy_manager.get(&proxy_name).await
                                .map(|p| p.use_encryption).unwrap_or(false);
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn: tcp, pre_read, use_encryption: enc });
                        }
                    }
                    Some(InternalMsg::UdpData { proxy_name: _pn, content, remote_addr }) => {
                        debug!("UDP data for proxy '{}' from {}", _pn, remote_addr);
                        let udp_packet = FrpMessage::UDPPacket(msg::UDPPacket {
                            content,
                            local_addr: String::new(),
                            remote_addr,
                        });
                        if let Err(e) = write_msg_v1(&mut writer, &udp_packet).await {
                            warn!("Failed to send UDPPacket: {}", e);
                            break;
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
                    Ok(FrpMessage::NewVisitorConn(nvc)) => {
                        debug!("NewVisitorConn for proxy '{}'", nvc.proxy_name);
                        let sk = nvc.sk.as_deref().unwrap_or("");
                        let proxy_name = state.sk_index.read().await.get(sk).cloned();
                        let resp = match proxy_name {
                            Some(pn) => FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                                proxy_name: pn,
                                error: None,
                            }),
                            None => FrpMessage::NewVisitorConnResp(msg::NewVisitorConnResp {
                                proxy_name: nvc.proxy_name.clone(),
                                error: Some("no matching STCP proxy found for sk".into()),
                            }),
                        };
                        let _ = write_msg_v1(&mut writer, &resp).await;
                    }
                    Ok(FrpMessage::UDPPacket(up)) => {
                        debug!("UDPPacket from client: {} bytes to {}", up.content.len(), up.remote_addr);
                        // Forward the UDP data to the original sender via a temporary socket
                        tokio::spawn(async move {
                            if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                                let _ = socket.send_to(&up.content, &up.remote_addr).await;
                            }
                        });
                    }
                    Ok(FrpMessage::NewProxy(np)) => {
                        handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx).await;
                    }
                    Ok(FrpMessage::CloseProxy(cp)) => {
                        if let Some(info) = state.proxy_manager.get(&cp.proxy_name).await {
                            if let Some(port) = info.remote_port {
                                state.used_ports.write().await.remove(&port);
                            }
                        }
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
        IoStream::Kcp(_) => { warn!("Kcp streaming not yet supported"); return; }
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

    let pre_read = req.pre_read;
    let enc_key = req.use_encryption;

    tokio::spawn(async move {
        // Write VHost pre-read bytes to work connection first
        if !pre_read.is_empty() {
            match &mut work_conn {
                IoStream::Tcp(ref mut s) => {
                    let _ = s.write_all(&pre_read).await;
                }
                IoStream::Tls(ref mut s) => {
                    let _ = s.write_all(&pre_read).await;
                }
                _ => {}
            }
        }

        if enc_key {
            // Derive encryption key (would use state.auth_cfg.token in production)
            let key = frp_core::encryption::derive_key("frp-rs");
            match work_conn {
                IoStream::Tcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key).await;
                }
                IoStream::Kcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key).await;
                }
                IoStream::Tls(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key).await;
                }
                IoStream::Kcp(_) => { warn!("Kcp streaming not yet supported"); return; }
            IoStream::WebSocket(_) => {
                    warn!("Encrypted WebSocket bridging not implemented");
                }
            }
        } else {
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
                IoStream::Kcp(_) => { warn!("Kcp streaming not yet supported"); return; }
            IoStream::WebSocket(_) => {
                    warn!("WebSocket bridging not implemented");
                }
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
            use_encryption: np.use_encryption.unwrap_or(false),
            use_compression: np.use_compression.unwrap_or(false),
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

            // Register STCP proxies in sk_index
            if np.proxy_type == "stcp" {
                if let Some(ref sk) = np.sk {
                    if !sk.is_empty() {
                        state.sk_index.write().await.insert(sk.clone(), np.proxy_name.clone());
                        info!("STCP proxy '{}' registered with sk", np.proxy_name);
                    }
                }
            }

            // Register HTTP proxies with VhostManager
            if np.proxy_type == "http" {
                if let Some(ref domains) = np.custom_domains {
                    if !domains.is_empty() {
                        state.vhost_manager.register(
                            &np.proxy_name,
                            domains,
                            run_id,
                        ).await;
                        info!("VHost routes registered for '{}': {:?}", np.proxy_name, domains);
                    }
                }
            }

            // For UDP proxies, start a UDP listener
            if np.proxy_type == "udp" {
                let pn = np.proxy_name.clone();
                let itx = internal_tx.clone();
                let bind_addr = state.proxy_bind_addr.clone();
                tokio::spawn(async move {
                    run_udp_listener(bind_addr, port, pn, itx).await;
                });
                info!("UDP proxy '{}' listening on port {}", np.proxy_name, port);
            }

            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();
            let bind_addr = state.proxy_bind_addr.clone();

            tokio::spawn(async move {
                listen_and_proxy(bind_addr, port, pn, itx).await;
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
    bind_addr: String,
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!("Proxy listener started on {} for '{}'", addr, proxy_name);
            l
        }
        Err(e) => {
            tracing::error!("Failed to bind proxy port {}: {}", port, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((user_conn, _addr)) => {
                if internal_tx.send(InternalMsg::ProxyUserConn {
                    proxy_name: proxy_name.clone(),
                    user_conn: IoStream::Tcp(user_conn),
                    pre_read: vec![],
                }).is_err() {
                    warn!("Control handler gone, stopping proxy listener for '{}'", proxy_name);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("Accept error on proxy port {}: {}", port, e);
                break;
            }
        }
    }
}


/// Run a UDP listener for a UDP proxy.
/// Forwards received packets to the control handler via InternalMsg.
async fn run_udp_listener(
    bind_addr: String,
    port: u16,
    proxy_name: String,
    internal_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    let addr = format!("{}:{}", bind_addr, port);
    let socket = match UdpSocket::bind(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to bind UDP port {}: {}", port, e);
            return;
        }
    };
    info!("UDP listener started on {} for '{}'", addr, proxy_name);

    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let data = buf[..n].to_vec();
                if internal_tx.send(InternalMsg::UdpData {
                    proxy_name: proxy_name.clone(),
                    content: data,
                    remote_addr: src.to_string(),
                }).is_err() {
                    warn!("Control handler gone, stopping UDP listener for '{}'", proxy_name);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("UDP recv error on {}: {}", addr, e);
                break;
            }
        }
    }
}

async fn unregister_control(state: &Arc<AppState>, run_id: &str) {
    let mut map = state.run_id_to_ctl_tx.write().await;
    map.remove(run_id);
    // Release allocated ports for this client
    let used = &state.used_ports;
    let pm = &state.proxy_manager;
    let proxies = pm.list_client(run_id).await;
    let mut ports = used.write().await;
    for p in &proxies {
        if let Some(port) = p.remote_port {
            ports.remove(&port);
        }
    }
}
