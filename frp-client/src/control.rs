use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use frp_core::config::ProxyConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg_v1;
use frp_core::auth::{AuthConfig, OidcClient};
use frp_core::mux::{self, YamuxSession};
use frp_core::transport::{IoStream, TransportProtocol, DialOptions, dial_server};
use frp_core::VERSION;

use crate::proxy;

/// Control connection state for the client.
pub struct ControlConnection {
    server_addr: String,
    server_port: u16,
    auth_cfg: Arc<AuthConfig>,
    transport_protocol: TransportProtocol,
    pool_count: i32,
    user: String,
    client_id: String,
    run_id: String,
    tls_enable: bool,
    tls_server_name: String,
    tls_ca_file: Option<String>,
    tls_cert_file: Option<String>,
    tls_key_file: Option<String>,
    dns_server: Option<String>,
    tcp_mux: bool,
    oidc_client: Option<Arc<OidcClient>>,
}

impl ControlConnection {
    pub fn new(
        server_addr: String,
        server_port: u16,
        auth_cfg: Arc<AuthConfig>,
        transport_protocol: TransportProtocol,
        pool_count: i32,
        user: String,
        client_id: String,
        tls_enable: bool,
        tls_server_name: String,
        tls_ca_file: Option<String>,
        tls_cert_file: Option<String>,
        tls_key_file: Option<String>,
        dns_server: Option<String>,
        tcp_mux: bool,
        oidc_client: Option<Arc<OidcClient>>,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            auth_cfg,
            transport_protocol,
            pool_count,
            user,
            client_id,
            run_id: String::new(),
            tls_enable,
            tls_server_name,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            dns_server,
            tcp_mux,
            oidc_client,
        }
    }

    /// Connect to the server and login.
    /// Returns the control stream, run_id, and optional yamux session.
    pub async fn login(&mut self) -> Result<(IoStream, String, Option<YamuxSession>), frp_core::Error> {
        // Yamux only applies when transport is plain TCP and TLS is off.
        // With TLS/WS/KCP/QUIC, yamux multiplexing is not used —
        // those protocols have their own layering.
        let propose_mux = self.tcp_mux
            && matches!(self.transport_protocol, TransportProtocol::Tcp)
            && !self.tls_enable;

        let opts = DialOptions {
            server_addr: self.server_addr.clone(),
            server_port: self.server_port,
            protocol: self.transport_protocol.clone(),
            tls_enable: self.tls_enable,
            tls_server_name: self.tls_server_name.clone(),
            tls_ca_file: self.tls_ca_file.clone(),
            tls_cert_file: self.tls_cert_file.clone(),
            tls_key_file: self.tls_key_file.clone(),
            dns_server: self.dns_server.clone(),
            ..Default::default()
        };

        let mut raw_stream = dial_server(&opts).await?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut login = msg::Login {
            version: Some(VERSION.into()),
            hostname: Some(hostname().await.unwrap_or_default()),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            user: if self.user.is_empty() { None } else { Some(self.user.clone()) },
            run_id: None,
            client_id: if self.client_id.is_empty() { None } else { Some(self.client_id.clone()) },
            pool_count: Some(self.pool_count),
            timestamp: Some(timestamp),
            privilege_key: None,
            metas: None,
            client_spec: None,
            multiplexer: if propose_mux { Some("yamux".into()) } else { None },
        };

        // Set auth: OIDC path or token path
        if let Some(ref oidc) = self.oidc_client {
            oidc.set_login(&mut login).await
                .map_err(|e| frp_core::Error::Auth(format!("OIDC login: {e}")))?;
        } else {
            login.privilege_key = self.auth_cfg.generate_login_key(timestamp);
        }

        let login = FrpMessage::Login(login);

        // Send Login on raw stream (plaintext, before yamux/encryption).
        // Go frp v0.69.1: Login/LoginResp happen in plaintext; encryption and
        // yamux are set up only after the login handshake.
        raw_stream.write_v1_frame(&login).await?;
        info!("Login sent, waiting for response...");

        let resp_msg = raw_stream.read_v1_frame().await?;
        match resp_msg {
            FrpMessage::LoginResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Auth(format!("Login failed: {}", err)));
                }
                self.run_id = resp.run_id.clone().unwrap_or_default();
                info!("Logged in. run_id: {}", self.run_id);
            }
            _ => return Err(frp_core::Error::Protocol("Unexpected response to login".into())),
        }

        // After login: wrap in AES-128-CFB encryption (Go frp v0.69.1 always
        // encrypts the control connection for V1).
        let enc_key = frp_core::encryption::derive_key(&self.auth_cfg.token);
        let encrypted = raw_stream.into_encrypted(enc_key);

        // Create yamux on the encrypted stream (if proposing mux).
        // Go frp v0.69.1: yamux runs on top of encryption, not raw transport.
        let (io_stream, yamux_session) = if propose_mux {
            match encrypted {
                IoStream::Cipher(cipher_box) => {
                    let mux_cfg = mux::TcpMuxConfig::default();
                    let (control_stream, session) = mux::client_mux(cipher_box, &mux_cfg).await?;
                    info!("Yamux session established over encrypted stream");
                    (IoStream::Yamux(control_stream), Some(session))
                }
                other => {
                    warn!("Expected encrypted stream for mux, got {:?}", other);
                    (other, None)
                }
            }
        } else {
            (encrypted, None)
        };

        Ok((io_stream, self.run_id.clone(), yamux_session))
    }

    /// Register a proxy with the server.
    pub async fn register_proxy(
        &self,
        p: &ProxyConfig,
        local_addr: &str,
        stream: &mut IoStream,
    ) -> Result<msg::NewProxyResp, frp_core::Error> {
        let np = proxy::create_new_proxy_msg(p, local_addr);
        info!("Registering proxy '{}' type={} remote_port={} local={}",
            p.name, p.proxy_type, p.remote_port, local_addr);
        stream.write_v1_frame(&np).await?;
        info!("NewProxy sent for '{}', waiting for response...", p.name);
        loop {
            let resp_msg = stream.read_v1_frame().await?;
            match resp_msg {
                FrpMessage::NewProxyResp(resp) => {
                    if let Some(err) = resp.error {
                        return Err(frp_core::Error::Other(format!(
                            "Proxy '{}' registration failed: {err}", p.name
                        )));
                    }
                    info!("Proxy '{}' registered on remote port {:?}", p.name, resp.remote_addr);
                    return Ok(resp);
                }
                FrpMessage::ReqWorkConn(_) => {
                    debug!("Skipping ReqWorkConn during proxy registration (pool conns spawned separately)");
                    continue;
                }
                other => {
                    warn!("Unexpected message during NewProxy registration for '{}': {:?}", p.name, other);
                    continue;
                }
            }
        }
    }

    /// Send a ping to the server.
    pub async fn send_ping(writer: &mut (impl AsyncWriteExt + Unpin)) -> Result<(), frp_core::Error> {
        let ping = FrpMessage::Ping(msg::Ping {
            privilege_key: None,
            timestamp: None,
        });
        write_msg_v1(writer, &ping).await
    }
}


/// Resolve the local hostname. All blocking I/O delegated to spawn_blocking.
async fn hostname() -> Option<String> {
    // Read /etc/hostname on a blocking thread
    let etc_result = tokio::task::spawn_blocking(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
    .await
    .unwrap_or(None);

    if let Some(s) = etc_result {
        return Some(s);
    }

    // Fallback: run hostname command on a blocking thread
    let result = tokio::task::spawn_blocking(|| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    })
    .await
    .unwrap_or(None);

    if let Some(s) = result {
        if !s.is_empty() {
            return Some(s);
        }
    }
    Some("unknown".into())
}
