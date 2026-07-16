use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::encryption;
use frp_core::metrics::ProxyMetricsRegistry;
use frp_core::msg::{self, FrpMessage};
use frp_core::mux::YamuxSession;
use frp_core::protocol::{read_msg_v1, read_msg_v2, write_msg_v1, write_msg_v2};
#[cfg(feature = "quic")]
use frp_core::quic::QuicConnection;
use frp_core::transport::{dial_server, DialOptions, IoStream};

use crate::proxy;
use crate::proxy_runtime::ProxyRuntimeInfo;
use crate::util::opt_if_empty;

#[cfg(feature = "vnet")]
type VnetTunMap = Arc<Mutex<HashMap<String, Option<Box<dyn frp_vnet::tun::TunDevice>>>>>;

/// Conditional type for the QUIC connection parameter.
/// When the `quic` feature is disabled, the parameter is `()` (ZST, no-op).
#[cfg(feature = "quic")]
type QuicConnOpt = Option<Arc<QuicConnection>>;
#[cfg(not(feature = "quic"))]
type QuicConnOpt = ();

/// Notification from a work connection that an XTCP NatHoleSid was received.
/// Sent to the control message loop so it can do STUN and send NatHoleClient.
#[derive(Debug)]
pub(crate) struct XtcpNotification {
    pub sid: String,
    pub proxy_name: String,
}

/// Check if an auth scope is enabled, considering both client and server config.
pub(crate) fn scope_requires_auth(
    client_scopes: &[String],
    server_scopes: &[String],
    scope: &str,
) -> bool {
    client_scopes.iter().any(|s| s == scope) || server_scopes.iter().any(|s| s == scope)
}

/// Configuration for spawning a work connection.
pub(crate) struct WorkConnConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: frp_core::transport::TransportProtocol,
    pub run_id: String,
    pub proxy_info_map: Arc<RwLock<HashMap<String, ProxyRuntimeInfo>>>,
    pub enc_key: [u8; 16],
    pub pool_id: i32,
    pub auth_token: String,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub tls_ca_file: Option<String>,
    pub yamux: Option<Arc<YamuxSession>>,
    pub quic_conn: QuicConnOpt,
    pub v2: bool,
    pub oidc_client: Option<Arc<OidcClient>>,
    pub udp_sockets: Arc<Mutex<HashMap<String, Arc<UdpSocket>>>>,
    pub udp_enc_cfg: Arc<Mutex<HashMap<String, (bool, bool)>>>,
    pub proxy_metrics: Arc<ProxyMetricsRegistry>,
    pub client_auth_scopes: Vec<String>,
    pub server_auth_scopes: Vec<String>,
    pub disable_custom_tls_first_byte: bool,
    pub keepalive_secs: u64,
    pub bind_addr: Option<String>,
    pub proxy_url: String,
    pub xtcp_tx: mpsc::Sender<XtcpNotification>,
    pub session_alive: Arc<AtomicBool>,
    #[cfg(feature = "vnet")]
    pub vnet_tuns: VnetTunMap,
    #[cfg(feature = "vnet")]
    pub vnet_routes: Arc<RwLock<frp_vnet::router::RouteTable>>,
}

/// Spawn a single work connection task.
///
/// The task:
/// 1. Under TcpMux: opens a yamux stream on the shared session
///    Without TcpMux: dials the server via TCP/TLS/WS
/// 2. Without TcpMux: sends NewWorkConn (with run_id + auth)
/// 3. Reads StartWorkConn from the server
/// 4. Connects to the local service
/// 5. Bridges data bidirectionally
///
/// `pool_id` is for logging only (< 0 means on-demand).
pub(crate) fn spawn_work_conn(cfg: WorkConnConfig) {
    tokio::spawn(async move {
        let WorkConnConfig {
            server_addr,
            server_port,
            protocol,
            run_id,
            proxy_info_map,
            enc_key,
            pool_id,
            auth_token,
            tls_enable,
            tls_server_name,
            tls_ca_file,
            yamux,
            quic_conn,
            v2,
            oidc_client,
            udp_sockets,
            udp_enc_cfg,
            proxy_metrics,
            client_auth_scopes: client_scopes,
            server_auth_scopes: server_scopes,
            disable_custom_tls_first_byte,
            keepalive_secs,
            bind_addr,
            proxy_url,
            xtcp_tx,
            session_alive,
            #[cfg(feature = "vnet")]
            vnet_tuns,
            #[cfg(feature = "vnet")]
            vnet_routes,
        } = cfg;

        // Clones for replenishment (before any field is consumed)
        let repl_udp_sockets = udp_sockets.clone();
        let repl_udp_enc_cfg = udp_enc_cfg.clone();
        let repl_proxy_metrics = proxy_metrics.clone();
        let repl_proxy_url = proxy_url.clone();
        let repl_xtcp_tx = xtcp_tx.clone();
        let repl_session_alive = session_alive.clone();
        #[cfg(feature = "vnet")]
        let repl_vnet_tuns = vnet_tuns.clone();
        #[cfg(feature = "vnet")]
        let repl_vnet_routes = vnet_routes.clone();

        let label = if pool_id >= 0 {
            format!("pool-{}", pool_id)
        } else {
            "on-demand".to_string()
        };

        // Acquire the underlying transport stream.
        // Priority: QUIC multi-stream > TcpMux yamux > direct dial.
        // Go frp compat: QUIC work connections open new streams on the
        // existing QUIC connection (multi-stream-per-connection).
        #[cfg(feature = "quic")]
        let mut work = if let Some(ref quic) = quic_conn {
            match quic.open_bi().await {
                Ok(stream) => {
                    debug!(label = %label, "Work conn {} opened QUIC stream", label);
                    IoStream::Quic(stream)
                }
                Err(e) => {
                    warn!(label = %label, error = %e, "Work conn {}: QUIC open_bi failed: {}", label, e);
                    return;
                }
            }
        } else if let Some(ref yamux) = yamux {
            match yamux.open_stream().await {
                Some(stream) => {
                    debug!(label = %label, "Work conn {} opened yamux stream", label);
                    IoStream::Yamux(stream)
                }
                None => {
                    warn!(label = %label, "Work conn {}: yamux open stream failed, session closed?", label);
                    return;
                }
            }
        } else {
            debug!(label = %label, "Work conn {} dialing server", label);
            let opts = DialOptions {
                server_addr: server_addr.clone(),
                server_port,
                protocol: protocol.clone(),
                tls_enable,
                tls_server_name: tls_server_name.clone(),
                tls_ca_file: tls_ca_file.clone(),
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr: bind_addr.clone(),
                proxy_url: opt_if_empty!(proxy_url),
                ..Default::default()
            };
            match dial_server(&opts).await {
                Ok(io) => io,
                Err(e) => {
                    debug!(label = %label, error = %e, "Work conn {} dial failed: {}", label, e);
                    return;
                }
            }
        };

        #[cfg(not(feature = "quic"))]
        let mut work = if let Some(ref yamux) = yamux {
            match yamux.open_stream().await {
                Some(stream) => {
                    debug!(label = %label, "Work conn {} opened yamux stream", label);
                    IoStream::Yamux(stream)
                }
                None => {
                    warn!(label = %label, "Work conn {}: yamux open stream failed, session closed?", label);
                    return;
                }
            }
        } else {
            debug!(label = %label, "Work conn {} dialing server", label);
            let opts = DialOptions {
                server_addr: server_addr.clone(),
                server_port,
                protocol: protocol.clone(),
                tls_enable,
                tls_server_name: tls_server_name.clone(),
                tls_ca_file: tls_ca_file.clone(),
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr: bind_addr.clone(),
                proxy_url: opt_if_empty!(proxy_url),
                ..Default::default()
            };
            match dial_server(&opts).await {
                Ok(io) => io,
                Err(e) => {
                    debug!(label = %label, error = %e, "Work conn {} dial failed: {}", label, e);
                    return;
                }
            }
        };

        // Send NewWorkConn — required for both yamux and raw transports.
        // Go frps needs the run_id and auth to associate the stream.
        {
            let nwc_token = auth_token.clone();
            let mut nwc_msg = msg::NewWorkConn {
                run_id: Some(run_id.clone()),
                timestamp: None,
                privilege_key: None,
            };
            let requires_auth = scope_requires_auth(&client_scopes, &server_scopes, "NewWorkConns");
            if requires_auth {
                if let Some(ref oidc) = oidc_client {
                    if let Err(e) = oidc.set_new_work_conn(&mut nwc_msg).await {
                        warn!(label = %label, error = %e, "Work conn {} OIDC NewWorkConn auth failed: {}", label, e);
                        return;
                    }
                } else {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let auth_cfg = AuthConfig::with_token(nwc_token);
                    nwc_msg.privilege_key = auth_cfg.generate_login_key(timestamp);
                    nwc_msg.timestamp = Some(timestamp);
                }
            }
            // Write V2 magic before NewWorkConn on work connection streams.
            // Both Go frp and Rust frp write V2 magic on yamux work conn
            // streams, matching Go frp's messageConnector.Connect() which
            // calls WriteMagicIfV2 before returning the stream.
            if v2 {
                if let Err(e) = frp_core::protocol::write_v2_magic(&mut work).await {
                    warn!(label = %label, error = %e, "Work conn {} failed to write V2 magic: {}", label, e);
                    return;
                }
            }
            let nwc = FrpMessage::NewWorkConn(nwc_msg);
            let write_result = if v2 {
                work.write_v2_frame(&nwc).await
            } else {
                work.write_v1_frame(&nwc).await
            };
            if let Err(e) = write_result {
                warn!(label = %label, error = %e, "Work conn {} failed to send NewWorkConn: {}", label, e);
                return;
            }
            debug!(label = %label, "Work conn {} sent NewWorkConn, waiting for StartWorkConn", label);
        }

        // Read StartWorkConn
        let swc_result = if v2 {
            work.read_v2_frame().await
        } else {
            work.read_v1_frame().await
        };
        match swc_result {
            Ok(FrpMessage::StartWorkConn(swc)) => {
                let proxy_name = &swc.proxy_name;
                debug!(label = %label, proxy_name = %proxy_name, "Work conn {} assigned to proxy '{}'", label, proxy_name);

                // Look up the proxy runtime info
                let info = {
                    let map = proxy_info_map.read().await;
                    map.get(proxy_name).cloned()
                };
                let info = match info {
                    Some(info) => info,
                    None => {
                        warn!(label = %label, proxy_name = %proxy_name, "Work conn {}: unknown proxy '{}'", label, proxy_name);
                        return;
                    }
                };

                if info.proxy_type == "xtcp" {
                    // XTCP proxy: after StartWorkConn, the next data on the work
                    // connection is either a NatHoleSid frame (XTCP notification)
                    // or raw bridge data (STCP fallback).
                    //
                    // Rust frps embeds nat_hole_sid in StartWorkConn JSON (new).
                    // Go frps sends a separate NatHoleSid V1 frame after (old).
                    // Check the embedded field first, then fall back to byte-peek.
                    if let Some(sid) = swc.nat_hole_sid.clone() {
                        if sid.is_empty() {
                            // STCP fallback marker from Rust frps.
                            // nat_hole_sid: Some("") (empty string) signals
                            // that this work conn is for STCP bridging, not
                            // XTCP notification. No dummy frame follows —
                            // the StartWorkConn payload is immediately
                            // followed by bridge data.
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: STCP fallback for '{}'", label, proxy_name);
                            // Fall through to bridging
                        } else {
                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid in StartWorkConn for '{}'", label, proxy_name);
                            let _ = xtcp_tx.try_send(XtcpNotification {
                                sid,
                                proxy_name: proxy_name.clone(),
                            });
                            return; // XTCP notification: work conn consumed
                        }
                    }

                    // No embedded sid. Could be Go frps XTCP notification
                    // (separate NatHoleSid V1 frame with type byte 0x35 follows)
                    // or STCP fallback (bridge data follows).
                    // Byte-peek: read 1 byte, check if it's NatHoleSid type.
                    if !v2 {
                        use tokio::io::AsyncReadExt;
                        let mut peek = [0u8; 1];
                        match work.read_exact(&mut peek).await {
                            Ok(_) if peek[0] == msg::TYPE_NAT_HOLE_SID => {
                                // Likely Go frps NatHoleSid V1 frame.
                                // Read remaining 8 header bytes + payload.
                                let mut header = [0u8; 8];
                                let mut consumed = vec![msg::TYPE_NAT_HOLE_SID];
                                match work.read_exact(&mut header).await {
                                    Ok(_) => {
                                        consumed.extend_from_slice(&header);
                                        let length = i64::from_be_bytes(header);
                                        if (0..=frp_core::protocol::V1_MAX_MSG_LENGTH)
                                            .contains(&length)
                                        {
                                            let mut payload = vec![0u8; length as usize];
                                            if work.read_exact(&mut payload).await.is_ok() {
                                                consumed.extend_from_slice(&payload);
                                                match serde_json::from_slice::<msg::NatHoleSid>(
                                                    &payload,
                                                ) {
                                                    Ok(sid_msg) => {
                                                        if let Some(sid) = sid_msg.sid {
                                                            debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (Go frps) for '{}'", label, proxy_name);
                                                            let _ = xtcp_tx.try_send(
                                                                XtcpNotification {
                                                                    sid,
                                                                    proxy_name: proxy_name.clone(),
                                                                },
                                                            );
                                                            return;
                                                        }
                                                        // sid=None: STCP fallback (Go frps — unlikely)
                                                        debug!(label = %label, "XTCP work conn {}: NatHoleSid without sid (Go frps STCP fallback)", label);
                                                        // Fall through to bridging — no pre-read needed (NatHoleSid consumed).
                                                    }
                                                    _ => {
                                                        // Parsed as non-NatHoleSid — bridge data with a
                                                        // very unlikely 0x35 collision. Wrap consumed bytes.
                                                        work = IoStream::BufferedRead(
                                                            consumed,
                                                            0,
                                                            Box::new(work),
                                                        );
                                                    }
                                                }
                                            } else {
                                                // Payload read failed — wrap consumed header bytes.
                                                work = IoStream::BufferedRead(
                                                    consumed,
                                                    0,
                                                    Box::new(work),
                                                );
                                            }
                                        } else {
                                            // Invalid V1 length — wrap consumed header bytes.
                                            work =
                                                IoStream::BufferedRead(consumed, 0, Box::new(work));
                                        }
                                    }
                                    Err(_) => {
                                        // Header read failed after 0x35 — wrap 1 byte.
                                        work = IoStream::BufferedRead(consumed, 0, Box::new(work));
                                    }
                                }
                            }
                            Ok(_) => {
                                // Not 0x35 — STCP fallback. Wrap the peeked byte
                                // as pre-read bridge data.
                                work = IoStream::BufferedRead(vec![peek[0]], 0, Box::new(work));
                            }
                            Err(_) => {
                                // EOF after StartWorkConn — bridge will get 0 bytes.
                            }
                        }
                    }
                    // V2: read one frame and check for NatHoleSid.
                    // Rust frps sends a V2 NatHoleSid frame after StartWorkConn
                    // for XTCP notification (separate frame for Go frp compat).
                    // Go frp v0.69.1 doesn't support V2 XTCP, so this is
                    // Rust↔Rust only.
                    if v2 {
                        use frp_core::protocol::{read_v2_frame_raw, V2_FRAME_TYPE_MESSAGE};
                        let mut peek_buf = Vec::new();
                        match read_v2_frame_raw(&mut work).await {
                            Ok((V2_FRAME_TYPE_MESSAGE, flags, payload)) => {
                                peek_buf.extend_from_slice(&V2_FRAME_TYPE_MESSAGE.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                if payload.len() >= 2 {
                                    let type_id = u16::from_be_bytes([payload[0], payload[1]]);
                                    if type_id == msg::V2_TYPE_NAT_HOLE_SID {
                                        if let Ok(sid_msg) =
                                            serde_json::from_slice::<msg::NatHoleSid>(&payload[2..])
                                        {
                                            if let Some(sid) = sid_msg.sid {
                                                if !sid.is_empty() {
                                                    debug!(label = %label, proxy_name = %proxy_name, "XTCP work conn {}: NatHoleSid (V2) for '{}'", label, proxy_name);
                                                    let _ = xtcp_tx.try_send(XtcpNotification {
                                                        sid,
                                                        proxy_name: proxy_name.clone(),
                                                    });
                                                    return;
                                                }
                                            }
                                            // sid=None or empty: STCP fallback — replay frame
                                        }
                                    }
                                }
                                // Not a NatHoleSid with non-empty sid — replay for STCP bridging
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Ok((frame_type, flags, payload)) => {
                                // Non-Message frame type — replay for STCP bridging
                                peek_buf.extend_from_slice(&frame_type.to_be_bytes());
                                peek_buf.extend_from_slice(&flags.to_be_bytes());
                                peek_buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                                peek_buf.extend_from_slice(&payload);
                                work = IoStream::BufferedRead(peek_buf, 0, Box::new(work));
                            }
                            Err(_) => {
                                // Not a V2 frame — raw bridge data for STCP fallback.
                                // read_v2_frame_raw already consumed some bytes; the
                                // stream is in an indeterminate state. Fall through to
                                // bridging — the bridge will get an error or partial data.
                            }
                        }
                    }

                    // Fall through to normal bridging for STCP fallback
                }

                #[cfg(feature = "vnet")]
                if info.proxy_type == "vnet" {
                    // VnetController is spawned in the service layer after TUN
                    // creation. The work connection for vnet proxies carries
                    // StartWorkConn for connection lifecycle signaling;
                    // VnetPackets flow on the control connection.
                    info!(label = %label, proxy_name = %proxy_name, "vnet work conn established (controller in service layer)");
                    return;
                }

                if info.proxy_type == "udp" {
                    // UDP proxy: bridge work conn ↔ local UDP socket
                    let sock = {
                        let map = udp_sockets.lock().await;
                        map.get(proxy_name).cloned()
                    };
                    let sock = match sock {
                        Some(s) => s,
                        None => {
                            warn!(label = %label, proxy_name = %proxy_name, "Work conn {}: no UDP socket for proxy '{}'", label, proxy_name);
                            return;
                        }
                    };
                    let enc_cfg = {
                        let cfg = udp_enc_cfg.lock().await;
                        cfg.get(proxy_name).copied().unwrap_or((false, false))
                    };
                    let (use_enc, use_comp) = enc_cfg;

                    info!(label = %label, proxy_name = %proxy_name, use_enc = %use_enc, use_comp = %use_comp,
                        "Work conn {} bridging UDP for '{}' (enc={}, comp={})",
                        label, proxy_name, use_enc, use_comp);

                    let (mut w_r, mut w_w) = work.into_split();

                    // Shared last_remote_addr: the server tells us the remote user's address
                    // in each UDPPacket. We must echo it back so the server can route
                    // the response to the correct remote user (not the local echo service).
                    let last_remote: Arc<Mutex<Option<msg::UdpAddr>>> = Arc::new(Mutex::new(None));

                    // Reader: work conn → local UDP socket
                    // Decrypt/decompress before forwarding to local service
                    let sock_r = sock.clone();
                    let pn_r = proxy_name.clone();
                    let enc_key_r = enc_key;
                    let last_remote_r = last_remote.clone();
                    tokio::spawn(async move {
                        debug!(proxy_name = %pn_r, "UDP reader '{}' started", pn_r);
                        loop {
                            let result = if v2 {
                                read_msg_v2(&mut w_r).await
                            } else {
                                read_msg_v1(&mut w_r).await
                            };
                            match result {
                                Ok(FrpMessage::UDPPacket(up)) => {
                                    // Save the original remote address for the response
                                    if let Some(ref ra) = up.remote_addr {
                                        *last_remote_r.lock().await = Some(ra.clone());
                                    }
                                    let n = up.content.len();
                                    let mut payload = up.content;
                                    if use_enc {
                                        if let Ok(d) = encryption::decrypt(&payload, &enc_key_r) {
                                            payload = d;
                                        }
                                    }
                                    if use_comp {
                                        if let Ok(d) = encryption::decompress(&payload) {
                                            payload = d;
                                        }
                                    }
                                    debug!(proxy_name = %pn_r, byte_count = n, "UDP reader '{}': forwarding {} bytes to local", pn_r, n);
                                    if let Err(e) = sock_r.send(&payload).await {
                                        debug!(proxy_name = %pn_r, error = %e, "UDP '{}' send to local failed: {}", pn_r, e);
                                        break;
                                    }
                                }
                                Ok(FrpMessage::Ping(_)) | Ok(FrpMessage::Pong(_)) => continue,
                                Ok(other) => {
                                    debug!(proxy_name = %pn_r, v1_type = ?other.v1_type_byte(), "UDP work conn '{}': unexpected msg 0x{:02x}", pn_r, other.v1_type_byte());
                                }
                                Err(e) => {
                                    debug!(proxy_name = %pn_r, error = %e, "UDP work conn '{}' read closed: {}", pn_r, e);
                                    break;
                                }
                            }
                        }
                    });

                    // Writer: local UDP socket → work conn
                    // Encrypt/compress before sending to server
                    let pn_w = proxy_name.clone();
                    let local_addr_str = info.local_addr.clone();
                    let last_remote_w = last_remote.clone();
                    tokio::spawn(async move {
                        debug!(proxy_name = %pn_w, "UDP writer '{}' started", pn_w);
                        let mut buf = vec![0u8; 65535];
                        let mut payload = Vec::with_capacity(65535);
                        loop {
                            match sock.recv_from(&mut buf).await {
                                Ok((n, src)) => {
                                    debug!(proxy_name = %pn_w, byte_count = n, src_addr = %src, "UDP writer '{}': recv'd {} bytes from local {}", pn_w, n, src);
                                    payload.clear();
                                    payload.extend_from_slice(&buf[..n]);
                                    if use_comp {
                                        if let Ok(c) = encryption::compress(&payload) {
                                            payload = c;
                                        }
                                    }
                                    if use_enc {
                                        if let Ok(e) = encryption::encrypt(&payload, &enc_key) {
                                            payload = e;
                                        }
                                    }
                                    // Use saved remote_addr from server (the true remote user)
                                    let remote = last_remote_w.lock().await.clone();
                                    // Take ownership of payload, leaving an empty Vec
                                    // (capacity preserved) for the next iteration.
                                    let taken = std::mem::take(&mut payload);
                                    let pkt = FrpMessage::UDPPacket(msg::UDPPacket {
                                        content: taken,
                                        local_addr: msg::UdpAddr::from_string(&local_addr_str),
                                        remote_addr: remote,
                                    });
                                    let write_result = if v2 {
                                        write_msg_v2(&mut w_w, &pkt).await
                                    } else {
                                        write_msg_v1(&mut w_w, &pkt).await
                                    };
                                    if let Err(e) = write_result {
                                        debug!(proxy_name = %pn_w, error = %e, "UDP '{}' send to work conn failed: {}", pn_w, e);
                                        break;
                                    }
                                    debug!(proxy_name = %pn_w, byte_count = n, "UDP writer '{}': sent {} bytes to work conn", pn_w, n);
                                }
                                Err(e) => {
                                    debug!(proxy_name = %pn_w, error = %e, "UDP '{}' recv from local failed: {}", pn_w, e);
                                    break;
                                }
                            }
                        }
                    });
                } else {
                    // TCP/HTTP/STCP: connect to local TCP service and bridge
                    match proxy::connect_local(&info.local_addr).await {
                        Ok(mut local) => {
                            // Write PROXY protocol header if configured
                            if !info.proxy_protocol_version.is_empty() {
                                if let Some(ref src) = swc.src_addr {
                                    if info.proxy_protocol_version == "v1" {
                                        let header =
                                            frp_core::proxy_protocol::build_proxy_protocol_v1(
                                                src,
                                                swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                                swc.src_port.unwrap_or(0) as u16,
                                                swc.dst_port.unwrap_or(0) as u16,
                                            );
                                        if let Err(e) = local.write_all(header.as_bytes()).await {
                                            warn!(error = %e, "Failed to write PROXY v1 header: {}", e);
                                        }
                                    } else if info.proxy_protocol_version == "v2" {
                                        match frp_core::proxy_protocol::build_proxy_protocol_v2(
                                            src,
                                            swc.dst_addr.as_deref().unwrap_or("0.0.0.0"),
                                            swc.src_port.unwrap_or(0) as u16,
                                            swc.dst_port.unwrap_or(0) as u16,
                                        ) {
                                            Ok(header) => {
                                                if let Err(e) = local.write_all(&header).await {
                                                    warn!(error = %e, "Failed to write PROXY v2 header: {}", e);
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to build PROXY v2 header: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            // Respect StartWorkConn's use_encryption/use_compression
                            // if explicitly set (Some), otherwise fall back to
                            // proxy info. This allows the server to disable
                            // encryption for XTCP STCP fallback work connections
                            // to avoid the dual-CipherWriter deadlock.
                            let use_enc = swc.use_encryption.unwrap_or(info.use_encryption);
                            let use_comp = swc.use_compression.unwrap_or(info.use_compression);
                            let enc = if use_enc { Some(&enc_key) } else { None };
                            proxy::bridge_streams(
                                local,
                                work,
                                proxy_name,
                                use_enc,
                                use_comp,
                                enc,
                                info.bandwidth_limit,
                                &info.bandwidth_limit_mode,
                                proxy_metrics,
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(label = %label, local_addr = %info.local_addr, error = %e, "Work conn {}: failed to connect to local {}: {}", label, info.local_addr, e);
                        }
                    }
                }
            }
            Ok(other) => {
                warn!(label = %label, v1_type = ?other.v1_type_byte(), "Work conn {}: unexpected message: {:?}", label, other.v1_type_byte());
            }
            Err(e) => {
                debug!(label = %label, error = %e, "Work conn {}: read error: {}", label, e);
            }
        }

        debug!(label = %label, "Work conn {} completed", label);

        // Replenish pool: spawn replacement to maintain pool_count
        // (Go frp v0.69.1 compat — idle work conns refilled after use)
        if pool_id >= 0 && repl_session_alive.load(Ordering::Acquire) {
            spawn_work_conn(WorkConnConfig {
                server_addr: server_addr.clone(),
                server_port,
                protocol: protocol.clone(),
                run_id: run_id.clone(),
                proxy_info_map: proxy_info_map.clone(),
                enc_key,
                pool_id,
                auth_token,
                tls_enable,
                tls_server_name,
                tls_ca_file,
                yamux,
                quic_conn,
                v2,
                oidc_client,
                udp_sockets: repl_udp_sockets,
                udp_enc_cfg: repl_udp_enc_cfg,
                proxy_metrics: repl_proxy_metrics,
                client_auth_scopes: client_scopes,
                server_auth_scopes: server_scopes,
                disable_custom_tls_first_byte,
                keepalive_secs,
                bind_addr,
                proxy_url: repl_proxy_url,
                xtcp_tx: repl_xtcp_tx,
                session_alive: repl_session_alive,
                #[cfg(feature = "vnet")]
                vnet_tuns: repl_vnet_tuns,
                #[cfg(feature = "vnet")]
                vnet_routes: repl_vnet_routes,
            });
        }
    });
}
