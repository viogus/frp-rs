use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The WebSocket path used by frp (matching the Go version).
pub const FRP_WEBSOCKET_PATH: &str = "/~!frp";

/// Transport protocol variant.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    WebSocket,
    Wss,
    Quic,
}

impl TransportProtocol {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "websocket" | "ws" => TransportProtocol::WebSocket,
            "wss" => TransportProtocol::Wss,
            "quic" => TransportProtocol::Quic,
            _ => TransportProtocol::Tcp,
        }
    }
}

/// Unified stream type for TCP and WebSocket.
pub enum IoStream {
    Tcp(TcpStream),
    WebSocket(WebSocketStream<MaybeTlsStream<TcpStream>>),
}

/// Options for dialing the server.
#[derive(Debug, Clone)]
pub struct DialOptions {
    pub server_addr: String,
    pub server_port: u16,
    pub protocol: TransportProtocol,
    pub tls_enable: bool,
    pub tls_server_name: String,
    pub dial_timeout_secs: u64,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0".into(),
            server_port: 7000,
            protocol: TransportProtocol::Tcp,
            tls_enable: false,
            tls_server_name: String::new(),
            dial_timeout_secs: 10,
        }
    }
}

/// Connect to the server with the given options.
pub async fn dial_server(opts: &DialOptions) -> Result<IoStream, crate::Error> {
    use tokio::time::{timeout, Duration};

    let addr = format!("{}:{}", opts.server_addr, opts.server_port);
    let stream = timeout(
        Duration::from_secs(opts.dial_timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| crate::Error::Transport(format!("dial timeout to {addr}")))?
    .map_err(|e| crate::Error::Transport(format!("dial to {addr}: {e}")))?;

    match opts.protocol {
        TransportProtocol::Tcp => Ok(IoStream::Tcp(stream)),
        TransportProtocol::WebSocket | TransportProtocol::Wss => {
            let is_wss = opts.protocol == TransportProtocol::Wss;
            let host = if !opts.tls_server_name.is_empty() {
                opts.tls_server_name.clone()
            } else {
                opts.server_addr.clone()
            };
            let url = format!(
                "{}://{}{}",
                if is_wss { "wss" } else { "ws" },
                host,
                FRP_WEBSOCKET_PATH
            );
            let (ws_stream, _) = tokio_tungstenite::connect_async(url)
                .await
                .map_err(|e| crate::Error::Transport(format!("WebSocket connect: {e}")))?;
            Ok(IoStream::WebSocket(ws_stream))
        }
        TransportProtocol::Quic => {
            Err(crate::Error::Transport("QUIC not yet implemented".into()))
        }
    }
}

/// Accept a WebSocket upgrade on the server side.
pub async fn accept_websocket(stream: TcpStream) -> Result<IoStream, crate::Error> {
    let tls_stream = MaybeTlsStream::Plain(stream);
    let ws_stream = tokio_tungstenite::accept_async(tls_stream)
        .await
        .map_err(|e| crate::Error::Transport(format!("WebSocket accept: {e}")))?;
    Ok(IoStream::WebSocket(ws_stream))
}

/// TLS configuration.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enable: bool,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub ca_file: Option<String>,
}
