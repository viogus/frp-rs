use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg_v1;
use frp_core::transport::IoStream;
use frp_core::format_socket_addr;

use crate::proxy::{ProxyInfo, allocate_port_multi};
use crate::service::{AppState, InternalMsg};

/// Register a new proxy and start listening on its assigned port.
pub(crate) async fn handle_new_proxy(
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

    // Server plugin: new_proxy hook (before port allocation).
    // Control-enabled plugins can reject the proxy registration.
    let np_content = serde_json::json!({
        "proxy_name": np.proxy_name,
        "proxy_type": np.proxy_type,
        "remote_port": remote_port,
        "custom_domains": np.custom_domains,
        "run_id": run_id,
    });
    if let Err(reason) = state.plugin_manager.notify("new_proxy", np_content).await {
        let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
            proxy_name: np.proxy_name.clone(),
            remote_addr: None,
            error: Some(reason),
        });
        let _ = write_msg_v1(writer, &resp).await;
        return;
    }

    let is_sudp = np.proxy_type == "sudp";
    // When sudp_port is configured, force all SUDP proxies to use that port
    let remote_port = if is_sudp && state.sudp_port > 0 {
        if remote_port > 0 && remote_port != state.sudp_port {
            info!("SUDP proxy '{}': overriding remote_port {} → {} (sudp_port config)",
                np.proxy_name, remote_port, state.sudp_port);
        }
        state.sudp_port
    } else {
        remote_port
    };
    let allocated_port = if is_sudp && remote_port > 0 {
        // SUDP proxies can share ports. If the requested port is already
        // in use, reuse it without adding to used_ports.
        let ports = state.used_ports.read().await;
        if ports.contains(&remote_port) {
            Some(remote_port)
        } else {
            drop(ports);
            let mut ports = state.used_ports.write().await;
            allocate_port_multi(&mut ports, remote_port, &state.reloadable.read().unwrap().allow_ports)
        }
    } else {
        let mut ports = state.used_ports.write().await;
        allocate_port_multi(&mut ports, remote_port, &state.reloadable.read().unwrap().allow_ports)
    };

    match allocated_port {
        Some(port) => {
            let virtual_net = np.virtual_net.clone()
                .filter(|v| !v.is_empty());
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
                virtual_net: virtual_net.clone(),
                allow_users: np.allow_users.clone().unwrap_or_default(),
                proxy_protocol_version: np.proxy_protocol_version.clone().unwrap_or_default(),
                response_headers: np.response_headers.clone().unwrap_or_default(),
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

            // Register STCP/XTCP proxies in sk_index (scoped by virtual_net)
            if np.proxy_type == "stcp" || np.proxy_type == "xtcp" {
                if let Some(ref sk) = np.sk {
                    if !sk.is_empty() {
                        let vn = np.virtual_net.as_deref().unwrap_or("");
                        let sk_key = if vn.is_empty() {
                            sk.clone()
                        } else {
                            format!("{}:{}", vn, sk)
                        };
                        state.sk_index.write().await.insert(sk_key, np.proxy_name.clone());
                        info!("STCP/XTCP proxy '{}' registered with sk{}",
                            np.proxy_name,
                            if vn.is_empty() { String::new() } else { format!(" (virtual_net: {vn})") });
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

                // Always register HTTP proxies with VHost manager.
                // If both domains and locations are empty, register with empty
                // strings as catch-all routes (matches any host/path).
                let mut domains = domains;
                let mut locations = locations;
                if domains.is_empty() && locations.is_empty() {
                    domains.push(String::new());   // catch-all domain
                    locations.push(String::new()); // catch-all path
                }
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

            // Register HTTPS proxies with VhostManager for SNI routing.
            // Routes by domain only (no path/location) — SNI hostname
            // from the TLS ClientHello determines the route.
            if np.proxy_type == "https" {
                let mut domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();

                // Subdomain routing
                if let Some(ref subdomain) = np.subdomain {
                    if !subdomain.is_empty() {
                        let sub_host = &state.sub_domain_host;
                        if !sub_host.is_empty() {
                            let full_domain = format!("{}.{}", subdomain, sub_host);
                            if !domains.contains(&full_domain) {
                                domains.push(full_domain);
                            }
                        }
                    }
                }

                if domains.is_empty() {
                    warn!("HTTPS proxy '{}' has no custom_domains — SNI routing won't work", np.proxy_name);
                }

                let hhr = np.host_header_rewrite.as_deref().unwrap_or("");
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                state.vhost_manager.register(
                    &np.proxy_name,
                    &domains,
                    &[],  // no locations for HTTPS SNI routing
                    run_id,
                    hhr,
                    http_user,
                    http_pwd,
                ).await;
                info!(
                    "VHost SNI routes registered for HTTPS proxy '{}': domains={:?}",
                    np.proxy_name, domains
                );
            }

            // Register TCPMux proxies with TcpMuxManager (domain-based CONNECT routing).
            // Follows the same pattern as VHost HTTP registration.
            if np.proxy_type == "tcpmux" {
                let domains: Vec<String> = np.custom_domains.clone().unwrap_or_default();
                if domains.is_empty() {
                    // TCPMux requires at least one domain for routing
                    let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                        proxy_name: np.proxy_name.clone(),
                        remote_addr: None,
                        error: Some("tcpmux proxy requires custom_domains".into()),
                    });
                    let _ = write_msg_v1(writer, &resp).await;
                    state.proxy_manager.remove(&np.proxy_name).await;
                    return;
                }
                let http_user = np.http_user.as_deref().unwrap_or("");
                let http_pwd = np.http_pwd.as_deref().unwrap_or("");
                state.tcpmux_manager.register(
                    &np.proxy_name,
                    &domains,
                    run_id,
                    http_user,
                    http_pwd,
                ).await;
                info!(
                    "TCPMux routes registered for '{}': domains={:?}",
                    np.proxy_name, domains
                );
            }

            // Start the appropriate listener for this proxy type.
            // STCP/XTCP/TCPMux use NAT hole punching or shared ports — no listener port needed.
            let pn = np.proxy_name.clone();
            let itx = internal_tx.clone();
            let bind_addr = state.proxy_bind_addr.clone();

            let is_nat_hole = np.proxy_type == "stcp"
                || np.proxy_type == "xtcp"
                || np.proxy_type == "tcpmux";

            // Collect oneshot senders for UDP work-conn tasks so we can signal
            // them after NewProxyResp has been written (avoiding the race where
            // client receives ReqWorkConn before proxy registration completes).
            let mut udp_resp_signals: Vec<oneshot::Sender<()>> = Vec::new();

            if np.proxy_type == "udp" || np.proxy_type == "sudp" {
                let is_sudp = np.proxy_type == "sudp";
                let addr = format_socket_addr(&bind_addr, port);
                let bind_result = UdpSocket::bind(&addr).await;
                // For SUDP with an already-bound shared port, bind may fail with
                // EADDRINUSE — that's expected, reuse existing socket for this port.
                let socket = match bind_result {
                    Ok(s) => std::sync::Arc::new(s),
                    Err(e) if is_sudp => {
                        // Try to find an existing socket on this port
                        let found = udp_sockets.iter().find_map(|(_, sock)| {
                            sock.local_addr().ok().filter(|a| a.port() == port).map(|_| sock.clone())
                        });
                        match found {
                            Some(sock) => {
                                info!("SUDP proxy '{}' sharing port {} (reusing existing socket)", np.proxy_name, port);
                                sock
                            }
                            None => {
                                tracing::error!("SUDP port {} bind failed (no existing socket to share): {}", port, e);
                                state.proxy_manager.remove(&np.proxy_name).await;
                                let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                                    proxy_name: np.proxy_name.clone(),
                                    remote_addr: None,
                                    error: Some(format!("SUDP bind failed: {e}")),
                                });
                                let _ = write_msg_v1(writer, &resp).await;
                                return;
                            }
                        }
                    }
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
                udp_sockets.insert(np.proxy_name.clone(), socket);
                // Build reverse lookup: local_addr → proxy_name for routing UDPPacket responses
                if let Some(ref local_str) = np.local_str {
                    if !local_str.is_empty() {
                        udp_local_to_proxy.insert(local_str.clone(), np.proxy_name.clone());
                    }
                }
                // For SUDP sharing existing socket, don't spawn duplicate listener
                let should_spawn = !is_sudp || !udp_sockets.iter().any(|(n, _)| n != &np.proxy_name && {
                    udp_sockets.get(n).and_then(|s| s.local_addr().ok()).is_some_and(|a| a.port() == port)
                });
                if should_spawn {
                    // Go frp v0.69.1 compat: UDP data flows over work connections,
                    // not the control connection. Request a work conn from the client.
                    // Use oneshot channel to ensure NewProxyResp is written BEFORE
                    // ReqWorkConn, avoiding race where client receives ReqWorkConn
                    // before proxy registration completes.
                    let pn_clone = np.proxy_name.clone();
                    let itx_clone = itx.clone();
                    let (tx, rx) = oneshot::channel();
                    udp_resp_signals.push(tx);
                    tokio::spawn(async move {
                        let _ = rx.await; // Wait until NewProxyResp is written
                        let _ = itx_clone.send(InternalMsg::UdpNeedsWorkConn { proxy_name: pn_clone });
                    });
                }
                info!("{} proxy '{}' listening on port {}", if is_sudp { "SUDP" } else { "UDP" }, np.proxy_name, port);
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

            // Signal UDP work-conn tasks that NewProxyResp has been written.
            // This ensures ReqWorkConn is never sent to the client before the
            // proxy registration response, preventing a race in the Go frp
            // v0.69.1 compatibility path.
            for tx in udp_resp_signals.drain(..) {
                let _ = tx.send(());
            }
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
pub(crate) async fn listen_and_proxy(
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



pub(crate) async fn unregister_control(state: &Arc<AppState>, run_id: &str) {
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
        // Clean up STCP sk_index (with virtual_net scoping)
        if let Some(ref sk) = p.sk {
            if !sk.is_empty() {
                let sk_key = if let Some(ref vn) = p.virtual_net {
                    format!("{}:{}", vn, sk)
                } else {
                    sk.clone()
                };
                state.sk_index.write().await.remove(&sk_key);
            }
        }
    }
    drop(ports);
    // VHost unregister outside port lock to avoid holding it across awaits
    for p in &proxies {
        state.vhost_manager.unregister(&p.name).await;
        state.tcpmux_manager.unregister(&p.name).await;
        state.proxy_metrics.remove(&p.name).await;
    }
}
