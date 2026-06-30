use std::net::Ipv4Addr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Cross-platform TUN device — reads/writes raw IP packets (L3, no Ethernet header).
pub trait TunDevice: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    /// Bring the interface up with the given IPv4 address, netmask, and MTU.
    fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> anyhow::Result<()>;
    /// Return the OS interface name (e.g. "tun0", "utun3").
    fn name(&self) -> &str;
    /// Return the current MTU.
    fn mtu(&self) -> u16;
}

/// Open a TUN device with the given name (empty = OS picks).
/// Returns a boxed TunDevice.
pub async fn open_tun(name: &str) -> anyhow::Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "linux")]
    {
        crate::tun_linux::LinuxTun::open(name).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        anyhow::bail!("TUN devices not yet implemented on this platform")
    }
}
