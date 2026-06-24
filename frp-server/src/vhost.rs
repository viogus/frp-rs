use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, debug};

use crate::service::{AppState, InternalMsg};

/// A route mapping: domain -> proxy entry.
#[derive(Debug, Clone)]
pub struct VhostRoute {
    pub proxy_name: String,
    pub run_id: String,
}

/// Manages HTTP VHost routing table (domain -> proxy).
pub struct VhostManager {
    routes: RwLock<HashMap<String, VhostRoute>>,
    by_proxy: RwLock<HashMap<String, Vec<String>>>,
}

impl VhostManager {
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            by_proxy: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register(&self, proxy_name: &str, domains: &[String], run_id: &str) {
        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;
        let mut domains_for_proxy = Vec::new();
        for domain in domains {
            routes.insert(domain.clone(), VhostRoute {
                proxy_name: proxy_name.to_string(),
                run_id: run_id.to_string(),
            });
            domains_for_proxy.push(domain.clone());
        }
        by_proxy.insert(proxy_name.to_string(), domains_for_proxy);
    }

    pub async fn unregister(&self, proxy_name: &str) {
        let mut routes = self.routes.write().await;
        let mut by_proxy = self.by_proxy.write().await;
        if let Some(domains) = by_proxy.remove(proxy_name) {
            for domain in &domains {
                routes.remove(domain);
            }
        }
    }

    pub async fn lookup(&self, domain: &str) -> Option<VhostRoute> {
        self.routes.read().await.get(domain).cloned()
    }
}

/// Run an HTTP VHost listener on the given address.
/// Accepts connections, reads the Host header, and routes via InternalMsg.
pub async fn run_vhost_http_listener(
    addr: String,
    state: Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTP VHost listener started on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            // Read the first 4096 bytes to extract Host header (with 10s timeout)
            let mut buf = [0u8; 4096];
            let mut stream = stream;
            let n = match tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };

            let pre_read = buf[..n].to_vec();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let host = match extract_host_header(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
            };

            debug!("HTTP VHost request for '{}' from {}", host, peer);

            if let Some(route) = state.vhost_manager.lookup(&host).await {
                let internal_tx = {
                    let map = state.run_id_to_ctl_tx.read().await;
                    map.get(&route.run_id).cloned()
                };

                if let Some(ctl_tx) = internal_tx {
                    let _ = ctl_tx.tx.send(InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tcp(stream),
                        pre_read,
                    }).ok();
                } else {
                    warn!("VHost route for '{}' found but control handler gone", host);
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                }
            } else {
                warn!("No VHost route for '{}' from {}", host, peer);
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            }
        });
    }
}

/// Extract the Host header from an HTTP request string.

/// Run an HTTPS VHost listener on the given address.
/// Performs TLS handshake, then extracts Host header and routes via InternalMsg.
pub async fn run_vhost_https_listener(
    addr: String,
    tls_cert_file: String,
    tls_key_file: String,
    state: std::sync::Arc<crate::service::AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    use frp_core::transport::build_tls_acceptor;
    use tokio::net::TcpListener;
    use tokio::io::AsyncReadExt;
    use tracing::{info, warn, debug};

    let acceptor = build_tls_acceptor(&tls_cert_file, &tls_key_file)?;
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS VHost listener started on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer, e);
                    return;
                }
            };

            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(std::time::Duration::from_secs(10), tls_stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };

            let pre_read = buf[..n].to_vec();
            let request_text = String::from_utf8_lossy(&buf[..n]);
            let host = match extract_host_header(&request_text) {
                Some(h) => h.to_string(),
                None => {
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut tls_stream, b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                }
            };

            debug!("HTTPS VHost request for '{}' from {}", host, peer);

            if let Some(route) = state.vhost_manager.lookup(&host).await {
                let internal_tx = {
                    let map = state.run_id_to_ctl_tx.read().await;
                    map.get(&route.run_id).cloned()
                };
                if let Some(ctl_tx) = internal_tx {
                    let _ = ctl_tx.tx.send(crate::service::InternalMsg::ProxyUserConn {
                        proxy_name: route.proxy_name.clone(),
                        user_conn: frp_core::transport::IoStream::Tls(
                            tokio_rustls::TlsStream::Server(tls_stream)
                        ),
                        pre_read,
                    }).ok();
                }
            } else {
                warn!("No VHost route for '{}' from {}", host, peer);
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tls_stream, b"HTTP/1.1 404 Not Found\r\n\r\n").await;
            }
        });
    }
}

fn extract_host_header(request: &str) -> Option<&str> {
    for line in request.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            let value = line[5..].trim();
            return Some(value.split(':').next().unwrap_or(value));
        }
    }
    None
}
