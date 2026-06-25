use std::sync::Arc;
use std::net::SocketAddr;
use std::collections::VecDeque;
use tokio::sync::mpsc;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use tracing::{info, warn, debug};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use frp_core::encryption;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::IncomingStreams;
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::transport::IoStream;
use frp_core::format_socket_addr;

use crate::proxy::{ProxyInfo, allocate_port_multi};
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
    mut stream: S,
    login: msg::Login,
    state: Arc<AppState>,
    peer: Option<SocketAddr>,
    mut incoming: Option<IncomingStreams>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("New control connection from {:?}", peer);

    // --- Authenticate ---
    let oidc_subject: Option<String> = if let Some(ref verifier) = state.oidc_verifier {
        let token = login.privilege_key.as_deref().unwrap_or("");
        match verifier.verify_login(token).await {
            Ok(oidc_token) => {
                info!("OIDC login verified: subject={}", oidc_token.subject);
                Some(oidc_token.subject)
            }
            Err(e) => {
                warn!("OIDC auth failed for {:?}: {}", peer, e);
                let (_, mut writer) = tokio::io::split(stream);
                let resp = FrpMessage::LoginResp(msg::LoginResp {
                    version: Some(frp_core::VERSION.into()),
                    run_id: None,
                    error: Some(format!("OIDC authentication failed: {e}")),
                });
                let _ = write_msg_v1(&mut writer, &resp).await;
                return;
            }
        }
    } else {
        if let Err(e) = state.auth_cfg.validate_login(
            login.privilege_key.as_deref(),
            login.timestamp,
        ) {
            warn!("Authentication failed for {:?}: {}", peer, e);
            let (_, mut writer) = tokio::io::split(stream);
            let resp = FrpMessage::LoginResp(msg::LoginResp {
                version: Some(frp_core::VERSION.into()),
                run_id: None,
                error: Some(e),
            });
            let _ = write_msg_v1(&mut writer, &resp).await;
            return;
        }
        None
    };

    let run_id = login.run_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!("Client {:?} logged in with run_id: {}", peer, run_id);

    // Store OIDC subject for ping/NWC verification
    if let Some(ref sub) = oidc_subject {
        state.oidc_subjects.write().await.insert(run_id.clone(), sub.clone());
    }

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

    // --- Send login response (plain, before encryption) ---
    {
        let resp = FrpMessage::LoginResp(msg::LoginResp {
            version: Some(frp_core::VERSION.into()),
            run_id: Some(run_id.clone()),
            error: None,
        });
        if let Err(e) = write_msg_v1(&mut stream, &resp).await {
            warn!("Failed to send login response to {:?}: {}", peer, e);
            unregister_control(&state, &run_id).await;
            return;
        }
    }

    // --- Wrap in AES-128-CFB encryption (matches client after login) ---
    let enc_key = encryption::derive_key(&state.auth_cfg.token);
    let cipher = frp_core::cipher_stream::CipherStream::new(Box::new(stream), enc_key);

    // --- Split encrypted stream for reading/writing ---
    let (mut reader, mut writer) = tokio::io::split(cipher);

    // --- Per-client state ---
    let pool_cap = login.pool_count.unwrap_or(1).max(0) as usize + WORK_POOL_EXTRA;
    let mut work_pool: VecDeque<IoStream> = VecDeque::new();
    let mut pending_requests: VecDeque<PendingRequest> = VecDeque::new();
    let mut listener_handles: std::collections::HashMap<String, tokio::task::JoinHandle<()>> = std::collections::HashMap::new();
    let mut udp_sockets: std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>> = std::collections::HashMap::new();
    // Reverse mapping: local_addr → proxy_name for routing UDPPacket responses
    let mut udp_local_to_proxy: std::collections::HashMap<String, String> = std::collections::HashMap::new();
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
                        // Group load balancing: if proxy belongs to a group,
                        // select a backend (possibly on a different run_id).
                        let (target_proxy, target_run_id) = {
                            let p = state.proxy_manager.get(&proxy_name).await;
                            let group = p.as_ref().and_then(|p| p.group.clone()).filter(|g| !g.is_empty());
                            let group_key = p.as_ref().and_then(|p| p.group_key.clone()).unwrap_or_default();
                            if let Some(ref group_name) = group {
                                if let Some(backend) = state.proxy_manager.select_group_backend(group_name, &group_key).await {
                                    let backend_run_id = state.proxy_manager.get_run_id(&backend).await.unwrap_or_default();
                                    info!("Group LB: {} -> backend {} (run_id {})", proxy_name, backend, backend_run_id);
                                    (backend, backend_run_id)
                                } else {
                                    (proxy_name.clone(), run_id.clone())
                                }
                            } else {
                                (proxy_name.clone(), run_id.clone())
                            }
                        };
                        // If backend is on a different run_id, forward to that handler
                        if target_run_id != run_id {
                            let ctl_tx = {
                                let map = state.run_id_to_ctl_tx.read().await;
                                map.get(&target_run_id).cloned()
                            };
                            if let Some(ctl) = ctl_tx {
                                let _ = ctl.tx.send(InternalMsg::ProxyUserConn {
                                    proxy_name: target_proxy,
                                    user_conn,
                                    pre_read,
                                });
                                continue;
                            }
                            warn!("Group backend run_id {} not found for proxy {}", target_run_id, target_proxy);
                            continue;
                        }
                        let (enc, comp) = {
                            let p = state.proxy_manager.get(&target_proxy).await;
                            let e = p.as_ref().map(|p| p.use_encryption).unwrap_or(false);
                            let c = p.as_ref().map(|p| p.use_compression).unwrap_or(false);
                            (e, c)
                        };
                        if let Some(work_conn) = work_pool.pop_front() {
                            assign_work_to_proxy(work_conn, PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now() }, state.encryption_key).await;
                        } else {
                            debug!("No pooled work conn, sending ReqWorkConn for {}", target_proxy);
                            if let Err(e) = write_msg_v1(&mut writer, &FrpMessage::ReqWorkConn(msg::ReqWorkConn {})).await {
                                warn!("Failed to send ReqWorkConn: {}", e);
                                break;
                            }
                            pending_requests.push_back(PendingRequest { proxy_name: target_proxy, user_conn, pre_read, use_encryption: enc, use_compression: comp, created_at: Instant::now() });
                        }
                    }
                    Some(InternalMsg::UdpData { proxy_name: ref _pn, content, remote_addr }) => {
                        debug!("UDP data for proxy '{}' from {}", _pn, remote_addr);
                        // Include proxy's local_str so the client can route to the correct local UDP socket
                        let local_str = udp_local_to_proxy.iter()
                            .find(|(_, pn)| *pn == _pn)
                            .map(|(ls, _)| ls.clone())
                            .unwrap_or_default();
                        // Encrypt/compress if the proxy requires it (Go frp v0.69.1 compat)
                        let mut payload = content;
                        if let Some(proxy_info) = state.proxy_manager.get(_pn).await {
                            if proxy_info.use_compression {
                                if let Ok(compressed) = encryption::compress(&payload) {
                                    payload = compressed;
                                }
                            }
                            if proxy_info.use_encryption {
                                if let Ok(encrypted) = encryption::encrypt(&payload, &state.encryption_key) {
                                    payload = encrypted;
                                }
                            }
                        }
                        let udp_packet = FrpMessage::UDPPacket(msg::UDPPacket {
                            content: payload,
                            local_addr: local_str,
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

            // Accept yamux streams (TcpMux work connections).
            // Go frp compat: client sends NewWorkConn on each yamux stream.
            // Read it to validate, then pool or assign.
            incoming_msg = async {
                match &mut incoming {
                    Some(inc) => inc.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(stream) = incoming_msg {
                    let mut io = IoStream::Yamux(stream);
                    match read_msg_v1(&mut io).await {
                        Ok(FrpMessage::NewWorkConn(nwc)) => {
                            let stream_run_id = nwc.run_id.as_deref().unwrap_or("");
                            if stream_run_id != run_id {
                                debug!("Yamux work conn run_id mismatch: expected {run_id}, got {stream_run_id}");
                                continue;
                            }
                        }
                        Ok(other) => {
                            debug!("Unexpected yamux stream message for {run_id}: {:?}", other.v1_type_byte());
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to read from yamux stream for {run_id}: {e}");
                            continue;
                        }
                    }
                    debug!("Yamux work conn for run_id {}", run_id);
                    while let Some(req) = pending_requests.front() {
                        if req.created_at.elapsed() > PENDING_REQUEST_TIMEOUT {
                            pending_requests.pop_front();
                        } else {
                            break;
                        }
                    }
                    if let Some(req) = pending_requests.pop_front() {
                        assign_work_to_proxy(io, req, state.encryption_key).await;
                    } else if work_pool.len() < pool_cap {
                        work_pool.push_back(io);
                        debug!("Yamux work conn pooled for {} (pool size: {}/{})", run_id, work_pool.len(), pool_cap);
                    } else {
                        debug!("Work pool full for {} ({}/{}), dropping yamux work conn", run_id, work_pool.len(), pool_cap);
                    }
                }
            }

            msg = read_msg_v1(&mut reader) => {
                match msg {
                    Ok(FrpMessage::UDPPacket(up)) => {
                        debug!("UDPPacket from client: {} bytes to {}", up.content.len(), up.remote_addr);
                        // Forward via the proxy's UDP socket (bidirectional NAT, Go frp compat).
                        // Lookup: local_addr → proxy_name → socket, fallback to first socket.
                        let proxy_name = udp_local_to_proxy.get(&up.local_addr);
                        // Decrypt/decompress if the proxy requires it
                        let mut payload = up.content.clone();
                        if let Some(pn) = proxy_name {
                            if let Some(proxy_info) = state.proxy_manager.get(pn).await {
                                if proxy_info.use_encryption {
                                    if let Ok(decrypted) = encryption::decrypt(&payload, &state.encryption_key) {
                                        payload = decrypted;
                                    }
                                }
                                if proxy_info.use_compression {
                                    if let Ok(decompressed) = encryption::decompress(&payload) {
                                        payload = decompressed;
                                    }
                                }
                            }
                        }
                        let sock_opt = proxy_name
                            .and_then(|pn| udp_sockets.get(pn))
                            .or_else(|| udp_sockets.iter().next().map(|(_, s)| s));
                        if let Some(sock) = sock_opt {
                            let sock = sock.clone();
                            let content = payload;
                            let remote_addr = up.remote_addr.clone();
                            tokio::spawn(async move {
                                let _ = sock.send_to(&content, &remote_addr).await;
                            });
                        } else {
                            warn!("No UDP socket for proxy, dropping {} bytes", up.content.len());
                        }
                    }
                    Ok(FrpMessage::NewProxy(np)) => {
                        handle_new_proxy(np, &run_id, &state, &mut writer, &internal_tx, &mut listener_handles, &mut udp_sockets, &mut udp_local_to_proxy).await;
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
                        // Send CloseProxyResp back to client (Go frp compat)
                        let cpr = FrpMessage::CloseProxyResp(msg::CloseProxyResp {
                            proxy_name: cp.proxy_name.clone(),
                        });
                        let _ = write_msg_v1(&mut writer, &cpr).await;
                    }
                    Ok(FrpMessage::Ping(ref ping_msg)) => {
                        // Validate ping auth (Go frp v0.69.1 compat)
                        // OIDC path: verify JWT + subject binding
                        let ping_auth_result = if let Some(ref verifier) = state.oidc_verifier {
                            let expected_sub = state.oidc_subjects.read().await
                                .get(&run_id).cloned().unwrap_or_default();
                            verifier.verify_ping(
                                ping_msg.privilege_key.as_deref().unwrap_or(""),
                                &expected_sub,
                            ).await
                        } else {
                            state.auth_cfg.validate_login(
                                ping_msg.privilege_key.as_deref(),
                                ping_msg.timestamp,
                            ).map(|_| ())
                        };
                        if let Err(e) = ping_auth_result {
                            warn!("Ping auth failed from {:?}: {}", peer, e);
                            let pong = FrpMessage::Pong(msg::Pong { error: Some(e) });
                            let _ = write_msg_v1(&mut writer, &pong).await;
                            break;
                        }
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
        IoStream::WebSocket(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Yamux(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Kcp(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Quic(ref mut s) => write_msg_v1(s, &swc).await,
        IoStream::Cipher(_) => unreachable!("Cipher stream not used on server"),
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
                            IoStream::WebSocket(ref mut s) => {
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
                    IoStream::WebSocket(ref mut s) => s.write_all(&pre_read).await,
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
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::Tls(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::Kcp(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::WebSocket(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::Quic(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = work.into_split();
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::Yamux(work) => {
                    let (u_r, u_w) = req.user_conn.into_split();
                    let (w_r, w_w) = tokio::io::split(work);
                    frp_core::bridge::bridge_encrypted(u_r, u_w, w_r, w_w, &key, comp_key, None, None).await;
                }
                IoStream::Cipher(_) => unreachable!("Cipher stream not used on server"),
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
    udp_sockets: &mut std::collections::HashMap<String, std::sync::Arc<tokio::net::UdpSocket>>,
    udp_local_to_proxy: &mut std::collections::HashMap<String, String>,
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
        allocate_port_multi(&mut ports, remote_port, &state.allow_ports)
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
                state.used_ports.write().await.remove(&port);
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

                let locations: Vec<String> = np.locations.clone().unwrap_or_default();

                if !domains.is_empty() || !locations.is_empty() {
                    let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
                    let http_user = np.http_user.as_deref().unwrap_or("");
                    let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                    state.vhost_manager.register(
                        &np.proxy_name,
                        &domains,
                        &locations,
                        run_id,
                        hhr,
                        http_user,
                        http_pwd,
                    ).await;
                    info!("VHost routes registered for '{}': domains={:?}, locations={:?}, rewrite={:?}",
                        np.proxy_name, domains, locations, hhr);
                }
            }

            // Start the appropriate listener for this proxy type.
            // STCP/XTCP use NAT hole punching — no listener port needed.
            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();
            let bind_addr = state.proxy_bind_addr.clone();

            let is_nat_hole = np.proxy_type == "stcp" || np.proxy_type == "xtcp";

            if np.proxy_type == "udp" {
                let addr = format_socket_addr(&bind_addr, port);
                let socket = match UdpSocket::bind(&addr).await {
                    Ok(s) => std::sync::Arc::new(s),
                    Err(e) => {
                        tracing::error!("Failed to bind UDP port {}: {}", port, e);
                        state.used_ports.write().await.remove(&port);
                        state.proxy_manager.remove(&np.proxy_name).await;
                        let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                            proxy_name: np.proxy_name.clone(),
                            remote_addr: None,
                            error: Some(format!("UDP bind failed: {e}")),
                        });
                        let _ = write_msg_v1(writer, &resp).await;
                        return;
                    }
                };
                let sock = socket.clone();
                udp_sockets.insert(np.proxy_name.clone(), socket);
                // Build reverse lookup: local_addr → proxy_name for routing UDPPacket responses
                if let Some(ref local_str) = np.local_str {
                    if !local_str.is_empty() {
                        udp_local_to_proxy.insert(local_str.clone(), np.proxy_name.clone());
                    }
                }
                let handle = tokio::spawn(async move {
                    run_udp_listener(sock, pn, itx).await;
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
/// Uses a shared Arc<UdpSocket> so the control handler can send responses
/// through the same socket (bidirectional NAT, Go frp v0.69.1 compat).
async fn run_udp_listener(
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    proxy_name: String,
    internal_tx: mpsc::UnboundedSender<InternalMsg>,
) {
    info!("UDP listener started for '{}'", proxy_name);

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
                tracing::error!("UDP recv error for '{}': {}", proxy_name, e);
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
