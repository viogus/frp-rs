use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc};
use tokio::net::TcpStream;
use tokio::net::TcpListener;
use tracing::{info, warn, error, debug};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::auth::AuthConfig;
use frp_core::transport::IoStream;

use crate::proxy::{ProxyManager, ProxyInfo, ProxyEntry, allocate_port};

/// Handle a single control connection from a frpc client.
pub async fn handle_control(
    stream: TcpStream,
    proxy_manager: Arc<ProxyManager>,
    auth_cfg: Arc<AuthConfig>,
    proxy_table: Arc<RwLock<HashMap<String, ProxyEntry>>>,
    used_ports: Arc<RwLock<std::collections::HashSet<u16>>>,
) {
    let peer = stream.peer_addr().ok();
    info!("New control connection from {:?}", peer);

    let (mut reader, mut writer) = stream.into_split();

    // --- Login ---
    let login_msg = match read_msg_v1(&mut reader).await {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to read login from {:?}: {}", peer, e);
            return;
        }
    };

    let login = match &login_msg {
        FrpMessage::Login(l) => l.clone(),
        _ => {
            warn!("Expected login message from {:?}", peer);
            return;
        }
    };

    // Authenticate
    if let Err(e) = auth_cfg.validate_login(
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
        let _ = write_msg_v1(&mut writer, &resp).await;
        return;
    }

    let run_id = login.run_id.clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    info!("Client {:?} logged in with run_id: {}", peer, run_id);

    // Send login response
    let resp = FrpMessage::LoginResp(msg::LoginResp {
        version: Some(frp_core::VERSION.into()),
        run_id: Some(run_id.clone()),
        server_udp_port: None,
        error: None,
    });
    if let Err(e) = write_msg_v1(&mut writer, &resp).await {
        warn!("Failed to send login response to {:?}: {}", peer, e);
        return;
    }

    // --- Message loop ---
    loop {
        let msg = match read_msg_v1(&mut reader).await {
            Ok(m) => m,
            Err(e) => {
                info!("Control connection {:?} closed: {}", peer, e);
                break;
            }
        };

        match msg {
            FrpMessage::NewProxy(np) => {
                handle_new_proxy(
                    np, &run_id, &proxy_manager,
                    &proxy_table, &used_ports, &mut writer,
                ).await;
            }
            FrpMessage::CloseProxy(cp) => {
                proxy_manager.remove(&cp.proxy_name).await;
                proxy_table.write().await.remove(&cp.proxy_name);
                info!("Proxy closed: {}", cp.proxy_name);
            }
            FrpMessage::Ping(_) => {
                let pong = FrpMessage::Pong(msg::Pong {});
                if let Err(e) = write_msg_v1(&mut writer, &pong).await {
                    warn!("Failed to send pong: {}", e);
                    break;
                }
                debug!("Ping from {:?}", peer);
            }
            _ => {
                debug!("Unhandled message from {:?}", peer);
            }
        }
    }

    proxy_manager.remove_client(&run_id).await;
    info!("Control connection {:?} removed", peer);
}

async fn handle_new_proxy(
    np: msg::NewProxy,
    run_id: &str,
    proxy_manager: &ProxyManager,
    proxy_table: &Arc<RwLock<HashMap<String, ProxyEntry>>>,
    used_ports: &Arc<RwLock<std::collections::HashSet<u16>>>,
    writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
) {
    let remote_port = np.remote_port.unwrap_or(0) as u16;

    let allocated_port = {
        let mut ports = used_ports.write().await;
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

            if let Err(e) = proxy_manager.register(run_id.to_string(), info).await {
                let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                    proxy_name: np.proxy_name.clone(),
                    remote_port: None,
                    error: Some(e),
                });
                let _ = write_msg_v1(writer, &resp).await;
                return;
            }

            let (_tx, rx) = mpsc::unbounded_channel::<IoStream>();
            let entry = ProxyEntry {
                info: ProxyInfo {
                    name: np.proxy_name.clone(),
                    proxy_type: np.proxy_type.clone(),
                    run_id: run_id.to_string(),
                    remote_port: Some(port),
                    sk: np.sk.clone(),
                    group: np.group.clone(),
                    group_key: np.group_key.clone(),
                    local_addr: np.local_str.clone(),
                },
                work_conn_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            };

            proxy_table.write().await.insert(np.proxy_name.clone(), entry);

            info!("Proxy registered: {} on port {}", np.proxy_name, port);
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_port: Some(port as i32),
                error: None,
            });
            let _ = write_msg_v1(writer, &resp).await;
        }
        None => {
            let resp = FrpMessage::NewProxyResp(msg::NewProxyResp {
                proxy_name: np.proxy_name.clone(),
                remote_port: None,
                error: Some("no available port".into()),
            });
            let _ = write_msg_v1(writer, &resp).await;
        }
    }
}

/// Listen on the proxy port and bridge incoming connections to work connections.
pub async fn listen_and_proxy(
    port: u16,
    proxy_name: String,
    proxy_table: Arc<RwLock<HashMap<String, ProxyEntry>>>,
    bind_addr: &str,
) {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!("Proxy listener started on {}", addr);
            l
        }
        Err(e) => {
            error!("Failed to bind proxy port {}: {}", port, e);
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((user_conn, _)) => {
                let pn = proxy_name.clone();
                let pt = proxy_table.clone();
                tokio::spawn(async move {
                    crate::proxy::proxy_pair(user_conn, pn, pt).await;
                });
            }
            Err(e) => {
                error!("Accept error on proxy port {}: {}", port, e);
                break;
            }
        }
    }
}
