use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::info;

use frp_core::config::ProxyConfig;
use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::write_msg_v1;
use frp_core::auth::AuthConfig;
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
    tcp_mux: bool,
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
        tcp_mux: bool,
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
            tcp_mux,
        }
    }

    /// Connect to the server and login.
    /// Returns the control stream, run_id, and optional yamux session.
    pub async fn login(&mut self) -> Result<(IoStream, String, Option<YamuxSession>), frp_core::Error> {
        // Yamux only applies when transport is plain TCP and TLS is off.
        // With TLS/WS/KCP/QUIC, yamux multiplexing is not used —
        // those protocols have their own layering.
        // Go frp servers with tcpMux=true wrap every incoming TCP connection
        // in yamux immediately, so the client MUST wrap BEFORE sending Login.
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
            ..Default::default()
        };

        let raw_stream = dial_server(&opts).await?;

        // Wrap in yamux BEFORE any protocol communication if proposing mux.
        // The Go frp server wraps its side on accept, so the client must
        // wrap before sending its first frame.
        let (mut io_stream, yamux_session) = if propose_mux {
            match raw_stream {
                IoStream::Tcp(tcp_stream) => {
                    let mux_cfg = mux::TcpMuxConfig::default();
                    let (control_stream, session) = mux::client_mux(tcp_stream, &mux_cfg).await?;
                    info!("Yamux session established");
                    (IoStream::Yamux(control_stream), Some(session))
                }
                _ => unreachable!("propose_mux only true for plain TCP"),
            }
        } else {
            (raw_stream, None)
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let privilege_key = self.auth_cfg.generate_login_key(timestamp);

        let login = FrpMessage::Login(msg::Login {
            version: Some(VERSION.into()),
            hostname: Some(hostname().await.unwrap_or_default()),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            user: if self.user.is_empty() { None } else { Some(self.user.clone()) },
            run_id: None,
            client_id: if self.client_id.is_empty() { None } else { Some(self.client_id.clone()) },
            pool_count: Some(self.pool_count),
            timestamp: Some(timestamp),
            privilege_key,
            metas: None,
            client_spec: None,
            multiplexer: if propose_mux { Some("yamux".into()) } else { None },
        });

        io_stream.write_v1_frame(&login).await?;

        let resp_msg = io_stream.read_v1_frame().await?;
        match resp_msg {
            FrpMessage::LoginResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Auth(format!("Login failed: {}", err)));
                }
                self.run_id = resp.run_id.clone().unwrap_or_default();
                info!("Logged in. run_id: {}", self.run_id);
                Ok((io_stream, self.run_id.clone(), yamux_session))
            }
            _ => Err(frp_core::Error::Protocol("Unexpected response to login".into())),
        }
    }

    /// Register a proxy with the server.
    pub async fn register_proxy(
        &self,
        p: &ProxyConfig,
        local_addr: &str,
        stream: &mut IoStream,
    ) -> Result<msg::NewProxyResp, frp_core::Error> {
        let np = proxy::create_new_proxy_msg(p, local_addr);
        stream.write_v1_frame(&np).await?;
        let resp_msg = stream.read_v1_frame().await?;
        match resp_msg {
            FrpMessage::NewProxyResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Other(format!(
                        "Proxy '{}' registration failed: {err}", p.name
                    )));
                }
                info!("Proxy '{}' registered on remote port {:?}", p.name, resp.remote_addr);
                Ok(resp)
            }
            _ => Err(frp_core::Error::Protocol("Unexpected response to NewProxy".into())),
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
