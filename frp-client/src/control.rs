use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use frp_core::msg::{self, FrpMessage};
use frp_core::protocol::{read_msg_v1, write_msg_v1};
use frp_core::auth::AuthConfig;
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
    run_id: String,
}

impl ControlConnection {
    pub fn new(
        server_addr: String,
        server_port: u16,
        auth_cfg: Arc<AuthConfig>,
        transport_protocol: TransportProtocol,
        pool_count: i32,
        user: String,
    ) -> Self {
        Self {
            server_addr,
            server_port,
            auth_cfg,
            transport_protocol,
            pool_count,
            user,
            run_id: String::new(),
        }
    }

    /// Connect to the server and login.
    pub async fn login(&mut self) -> Result<(TcpStream, String), frp_core::Error> {
        let opts = DialOptions {
            server_addr: self.server_addr.clone(),
            server_port: self.server_port,
            protocol: self.transport_protocol.clone(),
            ..Default::default()
        };

        let io_stream = dial_server(&opts).await?;

        let (mut reader, mut writer) = match io_stream {
            IoStream::Tcp(s) => s.into_split(),
            IoStream::WebSocket(ref _ws) => {
                return Err(frp_core::Error::Transport(
                    "WebSocket control connection not yet fully supported".into()
                ));
            }
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let privilege_key = self.auth_cfg.generate_login_key(timestamp);

        let login = FrpMessage::Login(msg::Login {
            version: Some(VERSION.into()),
            hostname: Some(hostname().unwrap_or_default()),
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            user: if self.user.is_empty() { None } else { Some(self.user.clone()) },
            run_id: None,
            pool_count: Some(self.pool_count),
            timestamp: Some(timestamp),
            privilege_key,
            metadatas: None,
        });

        write_msg_v1(&mut writer, &login).await?;

        let resp_msg = read_msg_v1(&mut reader).await?;
        match resp_msg {
            FrpMessage::LoginResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Auth(format!("Login failed: {}", err)));
                }
                self.run_id = resp.run_id.clone().unwrap_or_default();
                info!("Logged in to frps (run_id: {})", self.run_id);
                let stream = reader.unsplit(writer);
                Ok((stream, self.run_id.clone()))
            }
            _ => Err(frp_core::Error::Protocol("Unexpected response to login".into())),
        }
    }

    /// Register a proxy with the server.
    pub async fn register_proxy(
        &self,
        name: &str,
        proxy_type: &str,
        local_addr: &str,
        remote_port: u16,
        use_encryption: bool,
        use_compression: bool,
        sk: &str,
        stream: &mut TcpStream,
    ) -> Result<msg::NewProxyResp, frp_core::Error> {
        let (mut reader, mut writer) = stream.into_split();

        let np = proxy::create_new_proxy_msg(name, proxy_type, local_addr, remote_port, use_encryption, use_compression, sk);
        write_msg_v1(&mut writer, &np).await?;

        let resp_msg = read_msg_v1(&mut reader).await?;
        match resp_msg {
            FrpMessage::NewProxyResp(resp) => {
                if let Some(err) = resp.error {
                    return Err(frp_core::Error::Other(format!(
                        "Proxy '{name}' registration failed: {err}"
                    )));
                }
                info!("Proxy '{name}' registered on remote port {:?}", resp.remote_port);
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

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string()))
        })
        .or_else(|| Some("unknown".into()))
}
