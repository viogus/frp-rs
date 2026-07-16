/// STATUS: Stub implementation. Windows TUN device support is planned for a
/// future release. All operations return errors — callers should handle
/// gracefully.
///
/// Windows Wintun TUN device (stub — requires wintun.dll from WireGuard project).
///
/// Full implementation in a follow-up PR. Wintun provides a kernel-level
/// WireGuard TUN adapter for Windows with a C API. The integration requires
/// either bundling wintun.dll or detecting a system-installed copy.
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tun::TunDevice;
pub struct WindowsTun {
    name: String,
    mtu: u16,
}

impl WindowsTun {
    pub async fn open(_requested_name: &str) -> anyhow::Result<Box<dyn TunDevice>> {
        anyhow::bail!(
            "Windows TUN (Wintun) not yet implemented. \
             Requires wintun.dll from https://www.wintun.net/. \
             Use Linux or macOS for vnet TUN support."
        )
    }
}

impl TunDevice for WindowsTun {
    fn configure(&self, _addr: Ipv4Addr, _netmask: Ipv4Addr, _mtu: u16) -> anyhow::Result<()> {
        anyhow::bail!("Windows TUN not implemented")
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl AsyncRead for WindowsTun {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows TUN not implemented",
        )))
    }
}

impl AsyncWrite for WindowsTun {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows TUN not implemented",
        )))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
