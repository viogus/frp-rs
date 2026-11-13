//! Hosting a KCP socket driver on its own single-threaded runtime.
//!
//! The driver task is the only task that touches the UDP socket, and on a
//! shared multi-worker runtime it is migrated between worker threads like any
//! other task. Measured on a 4-vCPU host (one session, 1024 MiB, `abbench`):
//! at four workers the process moved 20 % fewer bytes than at one worker while
//! burning ~60 % more CPU, and the penalty was a step at the second worker
//! (`2/1` was as slow as `4/4`) — the driver's working set (session table,
//! send queues, KCP window) is re-warmed on every migration. Parking the
//! driver on a private current-thread runtime keeps it on one OS thread for
//! its whole life, so the rest of the process can use as many workers as the
//! relay side wants:
//!
//! | workerThreads (srv/cli) | shared pool | own driver thread |
//! |-------------------------|-------------|-------------------|
//! | 4 / 1                   | 94.2 MiB/s  | 119.4 MiB/s       |
//! | 4 / 4                   | 76.8 MiB/s  | 111.9 MiB/s       |
//! | 1 / 1                   | 116.3 MiB/s | not used (1 worker) |
//!
//! The socket must be *bound inside* that runtime: a `tokio::net::UdpSocket`
//! registers with the reactor that was current when it was created, and a
//! driver polling a socket that belongs to another reactor only pays an extra
//! cross-reactor wakeup per burst (measured 30 % slower, not faster).

use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::runtime::Builder;
use tokio::sync::{mpsc, oneshot};

use super::config::KcpConfig;
use super::socket::{KcpSocket, KcpSocketHandle};
use super::stream::KcpStream;

/// UDP socket receive buffer size (1 MiB), matching the listener.
const KCP_UDP_RCVBUF: usize = 1_048_576;
/// UDP socket send buffer size (1 MiB), matching the listener.
const KCP_UDP_SNDBUF: usize = 1_048_576;

/// Whether this socket's driver should get its own thread.
///
/// Enabled whenever the ambient runtime has more than one worker, because that
/// is where the shared pool loses (see the module docs). A single-worker
/// runtime is left alone: the driver already owns the only thread there, and a
/// second thread was measured 2 % slower. `FRP_KCP_DRIVER_RUNTIME=1|0`
/// overrides the decision (for bisecting a KCP throughput regression).
pub(crate) fn driver_thread_wanted() -> bool {
    match std::env::var("FRP_KCP_DRIVER_RUNTIME").as_deref() {
        Ok("1") | Ok("true") => return true,
        Ok("0") | Ok("false") => return false,
        _ => {}
    }
    tokio::runtime::Handle::try_current()
        .map(|handle| handle.metrics().num_workers() > 1)
        .unwrap_or(false)
}

/// Owns the OS thread a driver runtime runs on; dropping it stops the runtime
/// (which drops the driver task, closing the socket).
pub(crate) struct DriverThread {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for DriverThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What a listener needs back from its driver thread.
pub(crate) struct BoundDriver {
    pub(crate) local_addr: std::net::SocketAddr,
    pub(crate) handle: KcpSocketHandle,
    pub(crate) accept_rx: mpsc::Receiver<KcpStream>,
    pub(crate) guard: DriverThread,
}

fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    Builder::new_current_thread().enable_all().build()
}

fn tune(socket: &UdpSocket) {
    if let Err(e) = socket2::SockRef::from(socket).set_recv_buffer_size(KCP_UDP_RCVBUF) {
        tracing::debug!(error = %e, "KCP: failed to set SO_RCVBUF to {} (continuing with OS default)", KCP_UDP_RCVBUF);
    }
    if let Err(e) = socket2::SockRef::from(socket).set_send_buffer_size(KCP_UDP_SNDBUF) {
        tracing::debug!(error = %e, "KCP: failed to set SO_SNDBUF to {} (continuing with OS default)", KCP_UDP_SNDBUF);
    }
}

/// Bind `addr` on a private runtime and host its driver there.
pub(crate) fn bind_driver(addr: &str, config: KcpConfig) -> std::io::Result<BoundDriver> {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<
        std::io::Result<(
            std::net::SocketAddr,
            KcpSocketHandle,
            mpsc::Receiver<KcpStream>,
        )>,
    >(1);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let bind_addr = addr.to_string();
    let thread = std::thread::Builder::new()
        .name("frp-kcp-driver".to_string())
        .spawn(move || {
            let rt = match build_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            rt.block_on(async move {
                let socket = match UdpSocket::bind(&bind_addr).await {
                    Ok(socket) => socket,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let local_addr = match socket.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                tune(&socket);
                let (kcp_socket, handle, accept_rx) = KcpSocket::new(Arc::new(socket), config);
                if ready_tx.send(Ok((local_addr, handle, accept_rx))).is_err() {
                    return;
                }
                tokio::select! {
                    _ = kcp_socket.run() => {}
                    _ = stop_rx => {}
                }
            });
        })?;
    let (local_addr, handle, accept_rx) = match ready_rx.recv() {
        Ok(Ok(parts)) => parts,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::other(
                "KCP driver thread exited before binding",
            ))
        }
    };
    Ok(BoundDriver {
        local_addr,
        handle,
        accept_rx,
        guard: DriverThread {
            stop: Some(stop_tx),
            thread: Some(thread),
        },
    })
}

/// Bind a dial socket on a private runtime, hand its handle back to the
/// caller (which registers the session first), then run the driver there for
/// as long as it lives. The returned sender must be used to release the
/// driver — dropping it unblocks the thread too.
pub(crate) fn dial_driver(
    bind_addr: &str,
    config: KcpConfig,
) -> std::io::Result<(
    KcpSocketHandle,
    oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
)> {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<std::io::Result<KcpSocketHandle>>(1);
    let (go_tx, go_rx) = oneshot::channel::<()>();
    let bind_addr = bind_addr.to_string();
    let thread = std::thread::Builder::new()
        .name("frp-kcp-driver".to_string())
        .spawn(move || {
            let rt = match build_runtime() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            rt.block_on(async move {
                let socket = match UdpSocket::bind(&bind_addr).await {
                    Ok(socket) => socket,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                tune(&socket);
                let (kcp_socket, handle, _accept_rx) = KcpSocket::new(Arc::new(socket), config);
                if ready_tx.send(Ok(handle)).is_err() {
                    return;
                }
                // The caller registers its session on `handle` before the
                // driver processes a datagram (the same ordering the in-runtime
                // spawn uses, see `dial`).
                let _ = go_rx.await;
                kcp_socket.run().await;
            });
        })?;
    let handle = match ready_rx.recv() {
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::other(
                "KCP driver thread exited before binding",
            ))
        }
    };
    Ok((handle, go_tx, thread))
}
