use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_core::format_socket_addr;

use crate::proxy::{ProxyInfo, allocate_port};
use crate::service::{AppState, InternalMsg, ControlTx};

/// Max age of a pending request before it is dropped (Go frp: 10s default).
const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Max time without receiving a ping before the server closes the connection (Go frp: 90s).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Max work connections to pool beyond what the client requested (Go frp: poolCount + 10).
const WORK_POOL_EXTRA: usize = 10;

/// A pending request from a proxy listener waiting for a work connection.
struct PendingRequest {
    proxy_name: String,
    user_conn: IoStream,
    pre_read: Vec<u8>,
    use_encryption: bool,
    use_compression: bool,
    created_at: Instant,
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

    // Register control channel. If a previous handler exists for this run_id,
    // send Shutdown to it so it stops listening (Go frp v0.69.1 compat).
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        if let Some(old_ctl) = map.get(&run_id) {
            warn!("Duplicate run_id {}: shutting down old control handler", run_id);
            let _ = old_ctl.tx.send(InternalMsg::Shutdown);
        }
        map.insert(run_id.clone(), ControlTx { tx: internal_tx.clone() });
    }

    // --- Split stream for reading/writing ---
    let (mut reader, mut writer) = tokio::io::split(stream);

    // --- Send login response ---
    let resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(run_id.clone()),
        error: None,
    });
    if let Err(e) = write_msg_v1(&mut writer, &resp).await {
        warn!("Failed to send login response to {:?}: {}", peer, e);
        unregister_control(&state, &run_id).await;
        return;
    }

    // --- Per-client state ---
    let pool_cap = login.pool_count.unwrap_or(1).max(0) as usize + WORK_POOL_EXTRA;
    let mut work_pool: VecDeque<IoStream> = VecDeque::new();
    let mut pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let mut listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> = std::collections::HashMap::new();
    let mut last_ping = Instant::now();

    // --- Main select loop ---
    loop {
        // Expire stale pending requests
        while let Some(req) = pending_requests.front() {
            if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                let expired = pending_requests.pop_front().unwrap();
                warn!("Pending request for proxy '{}' timed out after {:?}", expired.proxy_name, PENDING_REQUEST_TIMEOUT);
            } else {
                break;
            }
        }

        // Heartbeat check: if no ping in HEARTBEAT_TIMEOUT, disconnect
        if last_ping.elapsed() > HEARTBEAT_TIMEOUT {
            warn!("Heartbeat timeout for {:?} (no ping in {:?}), disconnecting", peer, HEARTBEAT_TIMEOUT);
            break;
        }

        tokio::select! {
            biased;

            // Prefer internal messages to reduce latency for proxy connections
            internal = internal_rx.recv() => {
                match internal {
                    Some(InternalMsg::NewWorkConn(stream)) => {
                        debug!("Got work conn for run_id {}", run_id);
                        // Drain expired requests first
                        while let Some(req) = pending_requests.front() {
                            if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                                pending_requests.pop_front();
                            } else {
                                break;
                            }
                        }
                        if let Some(req) = pending_requests.pop_front() {
                            assign_work_to_proxy(stream, req, state.encryption_key).await;
                        } else if work_pool.len() < pool_cap {
                            work_pool.push_back(stream);
                            debug!("Work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                        } else {
                            debug!("Work pool full for {} ({}/{}), dropping work conn", run_id, work_pool.len(), pool_cap);
                        }
                    }
                    Some(InternalMsg::VisitorConn { proxy_name, visitor_conn }) => {
                        debug!("STCP visitor conn for proxy {} on run_id {}", proxy_name, run_id);
                        let (enc, comp) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            (e, c)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now() }, state.encryption_key).await;
                        } else {
                            debug!("No pooled work conn for STCP, sending ReqWorkConn");
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn: visitor_conn, pre_read: Vec::new(), use_encryption: enc, use_compression: comp, created_at: Instant::now() });
                        }
                    }
                    Some(InternalMsg::ProxyUserConn { proxy_name, user_conn, pre_read }) => {
                        debug!("User conn for proxy {} on run_id {}", proxy_name, run_id);
                        let (enc, comp) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            (e, c)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now() }, state.encryption_key).await;
                        } else {
                            debug!("No pooled work conn, sending ReqWorkConn for {}", proxy_name);
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now() });
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
                    Some(InternalMsg::Shutdown) => {
                        warn!("Shutdown received for run_id {} (replaced by new control connection)", run_id);
                        break;
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
                        let sk = nvc.sign_key.as_deref().unwrap_or("");
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
                        handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut listener_handles).await;
                    }
                    Ok(FrpMessage::CloseProxy(cp)) => {
                        if let Some(info) = state.proxy_manager.get(&cp.proxy_name).await {
                            if let Some(port) = info.remote_port {
                                state.used_ports.write().await.remove(&port);
                            }
                            // Clean up STCP sk_index
                            if let Some(ref sk) = info.sk {
                                if !sk.is_empty() {
                                    state.sk_index.write().await.remove(sk);
                                }
                            }
                            // Clean up VHost routes
                            state.vhost_manager.unregister(&cp.proxy_name).await;
                        }
                        // Stop the listener task
                        if let Some(handle) = listener_handles.remove(&cp.proxy_name) {
                            handle.abort();
                        }
                        state.proxy_manager.remove(&cp.proxy_name).await;
                        info!("Proxy closed: {}", cp.proxy_name);
                    }
                    Ok(FrpMessage::Ping(_)) => {
                        last_ping = Instant::now();
                        let pong = FrpMessage::Pong(msg::Pong { error: None });
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
    for (_, handle) in listener_handles.drain() {
        handle.abort();
    }
    unregister_control(&state, &run_id).await;
    state.proxy_manager.remove_client(&run_id).await;
    info!("Control connection {} removed", run_id);
}

/// Assign a work connection to a pending proxy request.
async fn assign_work_to_proxy(
    mut work_conn: IoStream,
    req: PendingRequest,
    encryption_key: [u8; 16],
) {
    let swc = FrpMessage::StartWorkConn(msg::StartWorkConn {
        proxy_name: req.proxy_name.clone(),
        src_addr: None,
        src_port: None,
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
    let comp_key = req.use_compression;

    tokio::spawn(async move {
        // Write VHost pre-read bytes to work connection first.
        // For encrypted bridges, send through encryption framing as the first frame.
        if !pre_read.is_empty() {
            if enc_key {
                match frp_core::encryption::encrypt(&pre_read, &encryption_key) {
                    Ok(encrypted) => {
                        let len = u32::try_from(encrypted.len()).unwrap_or(u32::MAX).to_be_bytes();
                        let write_result = match &mut work_conn {
                            IoStream::Tcp(ref mut s) => {
                                if s.write_all(&len).await.is_err() { Err(std::io::Error::other("write failed")) }
                                else { s.write_all(&encrypted).await }
                            }
                            IoStream::Tls(ref mut s) => {
                                if s.write_all(&len).await.is_err() { Err(std::io::Error::other("write failed")) }
                                else { s.write_all(&encrypted).await }
                            }
                            _ => Ok(()),
                        };
                        if let Err(e) = write_result {
                            warn!("Failed to write encrypted VHost pre-read: {}", e);
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to encrypt VHost pre-read: {}", e);
                        return;
                    }
                }
            } else {
                let write_result = match &mut work_conn {
                    IoStream::Tcp(ref mut s) => s.write_all(&pre_read).await,
                    IoStream::Tls(ref mut s) => s.write_all(&pre_read).await,
                    _ => Ok(()),
                };
                if let Err(e) = write_result {
                    warn!("Failed to write VHost pre-read bytes: {}", e);
                    return;
                }
            }
        }

        if enc_key {
            let key = encryption_key;
            match work_conn {
                IoStream::Tcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key).await;
                }
                IoStream::Kcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key).await;
                }
                IoStream::Tls(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key).await;
                }
            IoStream::WebSocket(_) => {
                    warn!("Encrypted WebSocket bridging not implemented");
                }
            }
        } else {
            // Plain bridge: split both sides and copy bidirectionally
            let (mut u_r, mut u_w) = req.user_conn.into_split();
            let (mut w_r, mut w_w) = work_conn.into_split();
            let to_work = tokio::io::copy(&mut u_r, &mut w_w);
            let to_user = tokio::io::copy(&mut w_r, &mut u_w);
            let result = tokio::join!(to_work, to_user);
            if let Err(e) = result.0 {
                debug!("Proxy '{}' user→work closed: {}", req.proxy_name, e);
            }
            if let Err(e) = result.1 {
                debug!("Proxy '{}' work→user closed: {}", req.proxy_name, e);
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
    listener_handles: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
) {
    let raw_port = np.remote_port.unwrap_or(0);
    if raw_port < 0 || raw_port > u16::MAX as i32 {
        let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: np.proxy_name.clone(),
            remote_addr: None,
            error: Some(format!("remote_port {} out of valid range (0-65535)", raw_port)),
        });
        let _ = write_msg_v1(writer, &resp).await;
        return;
    }
    let remote_port = raw_port as u16;

    let allocated_port = {
        let mut ports = state.used_ports.write().await;
        let base = state.allow_port_start;
        let count = state.allow_port_end.saturating_sub(base).max(100);
        allocate_port(&mut ports, remote_port, count, base)
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
                    remote_addr: None,
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
                let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

                // Subdomain routing: {subdomain}.{sub_domain_host}
                if let Some(ref subdomain) = np.subdomain {
                    if !subdomain.is_empty() {
                        let sub_host = &state.sub_domain_host;
                        if !sub_host.is_empty() {
                            let full_domain = format!("{}.{}", subdomain, sub_host);
                            info!("Subdomain route: {} → {}", full_domain, np.proxy_name);
                            if !domains.contains(&full_domain) {
                                domains.push(full_domain);
                            }
                        }
                    }
                }

                if !domains.is_empty() {
                    state.vhost_manager.register(
                        &np.proxy_name,
                        &domains,
                        run_id,
                    ).await;
                    info!("VHost routes registered for '{}': {:?}", np.proxy_name, domains);
                }
            }

            // Start the appropriate listener for this proxy type.
            // STCP/XTCP use NAT hole punching — no listener port needed.
            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();
            let bind_addr = state.proxy_bind_addr.clone();

            let is_nat_hole = np.proxy_type == "stcp" || np.proxy_type == "xtcp";

            if np.proxy_type == "udp" {
                let handle = tokio::spawn(async move {
                    run_udp_listener(bind_addr, port, pn, itx).await;
                });
                listener_handles.insert(np.proxy_name.clone(), handle);
                info!("UDP proxy '{}' listening on port {}", np.proxy_name, port);
            } else if is_nat_hole {
                info!("{} proxy '{}' registered (no listener, NAT hole punch)", np.proxy_type, np.proxy_name);
            } else {
                let handle = tokio::spawn(async move {
                    listen_and_proxy(bind_addr, port, pn, itx).await;
                });
                listener_handles.insert(np.proxy_name.clone(), handle);
            }

            info!("Proxy '{}' registered on port {} (run_id: {})", np.proxy_name, port, run_id);
            let remote_addr_str = format!(":{}", port);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_addr: Some(remote_addr_str),
                error: None,
            });
            let _ = write_msg_v1(writer, &resp).await;
        }
        None => {
            warn!("No available port for proxy '{}'", np.proxy_name);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_addr: None,
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
    let addr = format_socket_addr(&bind_addr, port);
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
    let addr = format_socket_addr(&bind_addr, port);
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
    // Scope the run_id_to_ctl_tx lock to just the remove call
    {
        let mut map = state.run_id_to_ctl_tx.write().await;
        map.remove(run_id);
    }
    // Release allocated ports and clean up sk/vhost entries for this client
    let proxies = state.proxy_manager.list_client(run_id).await;
    let mut ports = state.used_ports.write().await;
    for p in &proxies {
        if let Some(port) = p.remote_port {
            ports.remove(&port);
        }
        // Clean up STCP sk_index
        if let Some(ref sk) = p.sk {
            if !sk.is_empty() {
                state.sk_index.write().await.remove(sk);
            }
        }
    }
    drop(ports);
    // VHost unregister outside port lock to avoid holding it across awaits
    for p in &proxies {
        state.vhost_manager.unregister(&p.name).await;
    }
}
