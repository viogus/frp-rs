//! KCP listener — bind UDP socket, accept incoming KCP connections, dial outbound.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::KcpConfig;

/// UDP socket receive buffer size (4 MiB), matching Go frp's `SetReadBuffer(4194304)`.
/// Without explicit sizing, the OS default (~212KB on Linux) can cause packet
/// drops under bursty KCP traffic.
const KCP_UDP_RCVBUF: usize = 4_194_304;
/// UDP socket send buffer size (4 MiB), matching Go frp's `SetWriteBuffer(4194304)`.
const KCP_UDP_SNDBUF: usize = 4_194_304;
use super::session::KcpSession;
use super::socket::{KcpSocket, KcpSocketHandle};
use super::stream::KcpStream;

pub struct KcpListener {
    local_addr: SocketAddr,
    /// Held to keep write/register channels alive for spawned driver.
    _handle: KcpSocketHandle,
    accept_rx: mpsc::Receiver<KcpStream>,
    /// Back-channel: notify the socket driver when a session has been
    /// accepted, so it stops being subject to the unaccepted timeout.
    accept_notify_tx: mpsc::Sender<(u32, SocketAddr)>,
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        // Set socket buffer sizes (4 MiB each) matching Go frp's
        // listener.SetReadBuffer(4194304) / listener.SetWriteBuffer(4194304).
        // Without explicit sizing, OS defaults (~212KB on Linux) can cause
        // packet drops under bursty KCP traffic.
        if let Err(e) = socket2::SockRef::from(&socket).set_recv_buffer_size(KCP_UDP_RCVBUF) {
            tracing::debug!(error = %e, "KCP: failed to set SO_RCVBUF to {} (continuing with OS default)", KCP_UDP_RCVBUF);
        }
        if let Err(e) = socket2::SockRef::from(&socket).set_send_buffer_size(KCP_UDP_SNDBUF) {
            tracing::debug!(error = %e, "KCP: failed to set SO_SNDBUF to {} (continuing with OS default)", KCP_UDP_SNDBUF);
        }
        let socket = Arc::new(socket);

        let (kcp_socket, handle, accept_rx) = KcpSocket::new(socket, config);

        tokio::spawn(async move { kcp_socket.run().await });

        let accept_notify_tx = handle.accept_notify_tx.clone();
        Ok(Self {
            local_addr,
            _handle: handle,
            accept_rx,
            accept_notify_tx,
        })
    }

    /// Accept the next incoming KCP connection.
    /// Returns KcpStream with peer_addr already set (matching old API).
    pub async fn accept(&mut self) -> io::Result<KcpStream> {
        let stream = self
            .accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("KCP listener closed"))?;
        // Notify the socket driver that this session has been accepted.
        // If channel is full or closed, ignore — session ages out of
        // timeout set naturally after 30s.
        let _ = self
            .accept_notify_tx
            .try_send((stream.conv(), stream.peer_addr));
        Ok(stream)
    }

    /// Local address of the underlying UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// Create an outbound KCP connection (dial).
pub async fn dial_kcp(addr: &str, config: KcpConfig) -> io::Result<KcpStream> {
    let remote: SocketAddr = addr.parse().map_err(io::Error::other)?;
    let conv: u32 = loop {
        let c = rand::random();
        if c != 0 {
            break c;
        } // conv=0 is FEC parity sentinel
    };

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let socket = Arc::new(socket);

    let (kcp_socket, handle, _accept_rx) = KcpSocket::new(socket, config.clone());
    let (read_tx, read_rx) = mpsc::channel(256);
    let session = KcpSession::new(conv, remote, config.clone(), read_tx);
    let alive_handle = session.alive_handle();

    // Register session BEFORE spawning driver so the driver can route
    // incoming FEC packets to the correct session from the start.
    // Otherwise a race: driver spawns → recvs packet → resolve_key gives
    // wrong conv → creates duplicate session before register_tx processed.
    handle
        .register_tx
        .try_send((conv, remote, session))
        .map_err(|e| io::Error::other(format!("KCP register failed: {e}")))?;

    tokio::spawn(async move { kcp_socket.run().await });

    Ok(KcpStream::new(
        conv,
        remote,
        handle.write_tx,
        read_rx,
        handle.write_backlog.clone(),
        handle.write_notify.clone(),
        alive_handle,
    ))
}
