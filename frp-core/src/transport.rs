use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};


use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

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

/// Create a TLS acceptor from PEM-encoded cert and key files.
pub fn build_tls_acceptor(
    cert_file: &str,
    key_file: &str,
) -> Result<TlsAcceptor, crate::Error> {
    use std::fs::File;
    use std::io::BufReader;

    let cert_file = File::open(cert_file)
        .map_err(|e| crate::Error::Other(format!("open cert file: {e}")))?;
    let mut reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::Error::Other(format!("read certs: {e}")))?;

    let key_file = File::open(key_file)
        .map_err(|e| crate::Error::Other(format!("open key file: {e}")))?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| crate::Error::Other(format!("read private key: {e}")))?
        .ok_or_else(|| crate::Error::Other("no private key found".into()))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| crate::Error::Other(format!("build TLS config: {e}")))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Create a TLS connector for client-side TLS.
/// If ca_file is provided, use it as a custom root CA; otherwise use webpki roots.
pub fn build_tls_connector(
    ca_file: Option<&str>,
) -> Result<TlsConnector, crate::Error> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = ca_file {
        let file = std::fs::File::open(ca_path)
            .map_err(|e| crate::Error::Other(format!("open CA file: {e}")))?;
        let mut reader = std::io::BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| crate::Error::Other(format!("read CA certs: {e}")))?;
        root_store.add_parsable_certificates(certs);
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tls_connector_with_default_roots() {
        let result = build_tls_connector(None);
        assert!(result.is_ok(), "TLS connector with default roots should build");
    }

    #[test]
    fn test_build_tls_acceptor_missing_cert() {
        let result = build_tls_acceptor(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
        );
        assert!(result.is_err(), "TLS acceptor with missing files should fail");
    }
}
