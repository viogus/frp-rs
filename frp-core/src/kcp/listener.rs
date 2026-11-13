//! KCP listener — bind UDP socket, accept incoming KCP connections, dial outbound.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use super::config::KcpConfig;
use super::driver_thread::DriverThread;

/// UDP socket receive buffer size (1 MiB). ~5x the OS default (~212KB on Linux),
/// enough to absorb KCP bursts without 200-client memory blowout.
const KCP_UDP_RCVBUF: usize = 1_048_576;
/// UDP socket send buffer size (1 MiB), matching RCVBUF.
const KCP_UDP_SNDBUF: usize = 1_048_576;
use super::session::KcpSession;
use super::socket::{KcpSocket, KcpSocketHandle};
use super::stream::KcpStream;

/// Where the dial path's socket driver runs.
enum DriverSource {
    /// Spawned as a task on the caller's runtime (the default).
    Task(Box<KcpSocket>),
    /// Hosted on its own thread; the sender releases it once the session is
    /// registered.
    Thread(
        tokio::sync::oneshot::Sender<()>,
        std::thread::JoinHandle<()>,
    ),
}

pub struct KcpListener {
    local_addr: SocketAddr,
    /// Held to keep write/register channels alive for spawned driver.
    _handle: KcpSocketHandle,
    /// The UDP socket event-loop task. Aborted on drop so closing the
    /// listener also stops the driver explicitly (audit round 5, LOW 2.3).
    _driver: Option<tokio::task::JoinHandle<()>>,
    /// Set when the driver runs on its own thread (see `driver_thread`).
    _driver_thread: Option<DriverThread>,
    accept_rx: mpsc::Receiver<KcpStream>,
    /// Back-channel: notify the socket driver when a session has been
    /// accepted, so it stops being subject to the unaccepted timeout.
    accept_notify_tx: mpsc::Sender<(u32, SocketAddr)>,
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        if let Some(driver) = self._driver.take() {
            driver.abort();
        }
        // `DriverThread`'s own drop signals and joins the thread.
    }
}

impl KcpListener {
    /// Bind a KCP listener on the given address.
    pub async fn bind(addr: &str, config: KcpConfig) -> io::Result<Self> {
        if super::driver_thread::driver_thread_wanted() {
            let bound = super::driver_thread::bind_driver(addr, config)?;
            let accept_notify_tx = bound.handle.accept_notify_tx.clone();
            return Ok(Self {
                local_addr: bound.local_addr,
                _handle: bound.handle,
                _driver: None,
                _driver_thread: Some(bound.guard),
                accept_rx: bound.accept_rx,
                accept_notify_tx,
            });
        }
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        // Set socket buffer sizes (1 MiB each). ~5x OS default (~212KB on Linux)
        // — enough for KCP bursts without 200-client kernel-memory blowout.
        if let Err(e) = socket2::SockRef::from(&socket).set_recv_buffer_size(KCP_UDP_RCVBUF) {
            tracing::debug!(error = %e, "KCP: failed to set SO_RCVBUF to {} (continuing with OS default)", KCP_UDP_RCVBUF);
        }
        if let Err(e) = socket2::SockRef::from(&socket).set_send_buffer_size(KCP_UDP_SNDBUF) {
            tracing::debug!(error = %e, "KCP: failed to set SO_SNDBUF to {} (continuing with OS default)", KCP_UDP_SNDBUF);
        }
        let socket = Arc::new(socket);

        let (kcp_socket, handle, accept_rx) = KcpSocket::new(socket, config);

        let driver = tokio::spawn(async move { kcp_socket.run().await });

        let accept_notify_tx = handle.accept_notify_tx.clone();
        Ok(Self {
            local_addr,
            _handle: handle,
            _driver: Some(driver),
            _driver_thread: None,
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
    let (stream, driver) = dial_kcp_with_driver(addr, config).await?;
    // Detach the driver: it self-exits once the stream is dropped (see
    // KcpSocket::run). The JoinHandle is deliberately dropped — aborting
    // it here would kill the connection before its first probe is sent
    // (audit round 5 tried this and it broke dial→accept).
    drop(driver);
    Ok(stream)
}

/// Like [`dial_kcp`], but returns the socket driver's `JoinHandle` so the
/// caller can observe driver self-exit (after the last stream is dropped
/// the driver terminates itself — see `KcpSocket::run`). Production uses
/// [`dial_kcp`], which detaches the handle; tests use this to prove the
/// driver does not leak.
pub async fn dial_kcp_with_driver(
    addr: &str,
    config: KcpConfig,
) -> io::Result<(KcpStream, tokio::task::JoinHandle<()>)> {
    // Go parity: kcp-go's `Dial(raddr string)` resolves its argument with
    // `net.ResolveUDPAddr`, so a hostname is a valid dial target here too —
    // rejecting it with a bare parse error was an frp-rs-only restriction that
    // surfaced as `KCP dial: invalid socket address syntax` one layer up.
    //
    // The address is chosen the way `ResolveUDPAddr` chooses it — not as the
    // resolver's first entry: `addrList.forResolve` (`net/ipsock.go:79-107`)
    // prefers IPv4 unless the dialled string is a bracketed IPv6 literal, and
    // falls back to the first entry when the name has no IPv4 address. That
    // differs from the resolver's own order on this platform (`localhost`
    // resolves `[::1]` first), so `.next()` picked the address Go does not
    // return. No fallback is possible at this layer either way: a datagram to a
    // dead or unreachable address is dropped silently (see the socket-family
    // note below), so a failure appears later as a retransmission timeout
    // rather than as an error here.
    let remote: SocketAddr = match addr.parse() {
        Ok(remote) => remote,
        Err(_) => {
            let peers = crate::transport::resolve::resolve_peers(addr)
                .await
                .map_err(|e| io::Error::other(format!("resolve '{addr}': {e}")))?;
            crate::transport::resolve::pick_for_resolve(&peers, addr.contains('['))
        }
    };
    let conv: u32 = loop {
        let c = rand::random();
        if c != 0 {
            break c;
        } // conv=0 is FEC parity sentinel
    };

    // Bind the wildcard socket of the *remote's* family. `0.0.0.0:0` used to be
    // unconditional, which made an IPv6 remote undialable — reached by an IPv6
    // literal and by any host name whose first resolved address is IPv6
    // (`localhost` on macOS). This socket is never `connect`ed: packets leave
    // through `UdpSocket::try_send_to`, called from `KcpSocket::send_udp_packet`
    // and `KcpSocket::drain_pending_udp` (`frp-core/src/kcp/socket.rs`), and a
    // cross-family `sendto` is silently dropped (macOS even reports success for
    // the send; elsewhere the send errors and is only `tracing::debug!`-logged),
    // so the caller sees no error at all and the session dies later as a
    // retransmission timeout. Go matches the family too: kcp-go dials with
    // `net.DialUDP("udp", nil, raddr)`, whose nil local address is resolved to
    // the family of `raddr`.
    let bind_addr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    // Clamp the MTU ONCE so the socket AND the session agree: KcpSocket::new
    // clamps its internal copy, but KcpSession::new reads config.mtu directly
    // (kcp.set_mtu), so passing the raw config would let the dial session
    // emit `mtu + KCP_WIRE_OVERHEAD`-byte FEC wire packets that the receiver's
    // fixed 1500-byte driver recv buffer would truncate.
    let config = config.clamped();

    // A multi-worker runtime hosts the driver on its own thread, with the
    // socket bound *inside* it so its registration belongs to that runtime.
    let (driver_source, handle) = if super::driver_thread::driver_thread_wanted() {
        let (handle, go, thread) = super::driver_thread::dial_driver(bind_addr, config.clone())?;
        (DriverSource::Thread(go, thread), handle)
    } else {
        let socket = UdpSocket::bind(bind_addr).await?;

        // Set socket buffer sizes (1 MiB each), matching the listener — an
        // outbound dial otherwise keeps the OS defaults (~212KB on Linux),
        // which can drop KCP bursts under load.
        if let Err(e) = socket2::SockRef::from(&socket).set_recv_buffer_size(KCP_UDP_RCVBUF) {
            tracing::debug!(error = %e, "KCP: dial failed to set SO_RCVBUF to {} (continuing with OS default)", KCP_UDP_RCVBUF);
        }
        if let Err(e) = socket2::SockRef::from(&socket).set_send_buffer_size(KCP_UDP_SNDBUF) {
            tracing::debug!(error = %e, "KCP: dial failed to set SO_SNDBUF to {} (continuing with OS default)", KCP_UDP_SNDBUF);
        }
        let socket = Arc::new(socket);
        let (kcp_socket, handle, _accept_rx) = KcpSocket::new(socket, config.clone());
        (DriverSource::Task(Box::new(kcp_socket)), handle)
    };
    let (read_tx, read_rx) = mpsc::channel(256);
    let session = KcpSession::with_chunk_pool(
        conv,
        remote,
        config.clone(),
        read_tx,
        handle.chunk_pool.clone(),
    );
    let alive_handle = session.alive_handle();
    // Share the session's send-queue backlog counter with the stream so
    // poll_write can gate on a stalled peer (window 0) instead of letting
    // snd_queue grow without bound.
    let (snd_backlog, snd_notify) = session.snd_backlog_handle();

    // Register session BEFORE spawning driver so the driver can route
    // incoming FEC packets to the correct session from the start.
    // Otherwise a race: driver spawns → recvs packet → resolve_key gives
    // wrong conv → creates duplicate session before register_tx processed.
    handle
        .register_tx
        .try_send((conv, remote, session))
        .map_err(|e| io::Error::other(format!("KCP register failed: {e}")))?;

    // Spawn the socket driver. The JoinHandle is returned to the caller but
    // NOT used to abort: dial returns before the KCP handshake completes,
    // so aborting the driver on stream drop would kill the connection
    // before its first probe is sent (audit round 5 tried this and it broke
    // dial→accept). Instead the driver self-exits once the last stream is
    // dropped (KcpSocket::run exit check, keyed on the alive_streams
    // counter + register channel closure) — closing the UDP socket and
    // freeing the task instead of leaking one per dial for the process
    // lifetime (HIGH leak under reconnect churn).
    let driver = match driver_source {
        DriverSource::Task(kcp_socket) => tokio::spawn(async move { kcp_socket.run().await }),
        DriverSource::Thread(go, thread) => {
            // Release the driver thread now that the session is registered.
            // The thread ends on its own when the driver exits; the join
            // handle is dropped rather than awaited (awaiting it would block
            // this runtime on a UDP socket's lifetime).
            let _ = go.send(());
            drop(thread);
            tokio::spawn(async {})
        }
    };

    Ok((
        KcpStream::new(
            conv,
            remote,
            handle.write_tx,
            read_rx,
            handle.write_backlog.clone(),
            handle.write_notify.clone(),
            handle.chunk_pool.clone(),
            snd_backlog,
            snd_notify,
            alive_handle,
            handle.alive_streams,
        ),
        driver,
    ))
}
