//! KCP listener — bind UDP socket, accept incoming KCP connections, dial outbound.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::KcpConfig;
use super::session::KcpSession;
use super::socket::{KcpSocket, KcpSocketHandle};
use super::stream::KcpStream;

pub struct KcpListener {
    local_addr: SocketAddr,
    handle: KcpSocketHandle,
    accept_rx: mpsc::UnboundedReceiver<KcpStream>,
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (kcp_socket, handle, accept_rx) = KcpSocket::new(socket, config);

        tokio::spawn(async move { kcp_socket.run().await });

        Ok(Self {
            local_addr,
            handle,
            accept_rx,
        })
    }

    /// Accept the next incoming KCP connection.
    /// Returns KcpStream with peer_addr already set (matching old API).
    pub async fn accept(&mut self) -> io::Result<KcpStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "KCP listener closed"))
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Create an outbound KCP connection (dial).
pub async fn dial_kcp(addr: &str, config: KcpConfig) -> io::Result<KcpStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let conv: u32 = rand::random();

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);

    let (kcp_socket, handle, _accept_rx) = KcpSocket::new(socket, config.clone());
    let (read_tx, read_rx) = mpsc::unbounded_channel();
    let session = KcpSession::new(conv, remote, config.clone(), read_tx);

    // Spawn driver BEFORE registering the session so the driver is already
    // running (or at least scheduled) when the registration message arrives.
    // This prevents a race where a fast write() can arrive before the driver
    // has processed the session registration.
    tokio::spawn(async move { kcp_socket.run().await });
    // Yield to let the driver task begin executing.
    tokio::task::yield_now().await;

    handle
        .register_tx
        .send((conv, remote, session))
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "driver closed"))?;

    // Yield again to give the driver a chance to process the registration
    // before the caller sends data.
    tokio::task::yield_now().await;

    Ok(KcpStream::new(conv, remote, handle.write_tx, read_rx))
}
