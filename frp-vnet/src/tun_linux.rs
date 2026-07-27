use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

use super::tun::TunDevice;

/// Linux TUN device using /dev/net/tun.
pub struct LinuxTun {
    async_fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: AtomicU16,
}

// SAFETY: Rust auto-derives Send — all fields are Send (AsyncFd<OwnedFd> is
// Send+Sync on Unix; AtomicU16 is Sync). This static assertion catches any
// future non-Send field addition at compile time.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<LinuxTun>();
};

impl LinuxTun {
    pub async fn open(requested_name: &str) -> anyhow::Result<Box<dyn TunDevice>> {
        use std::ffi::CStr;

        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let raw_fd = dev.as_raw_fd();
        // SAFETY: zeroed ifreq is valid — all-zeroes is a well-defined
        // representation for this C struct (kernel fills name on success).
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

        let name_bytes = if requested_name.is_empty() {
            b"tun%d\0".to_vec()
        } else {
            let mut bytes = requested_name.as_bytes().to_vec();
            bytes.push(0);
            bytes
        };
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
        for (dst, src) in ifr.ifr_name[..copy_len]
            .iter_mut()
            .zip(&name_bytes[..copy_len])
        {
            *dst = *src as libc::c_char;
        }

        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        // SAFETY: raw_fd is a valid /dev/net/tun fd; ifr is a valid ifreq
        // with IFF_TUN|IFF_NO_PI flags; TUNSETIFF is the correct ioctl.
        let ret = unsafe { libc::ioctl(raw_fd, libc::TUNSETIFF, &ifr) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "TUNSETIFF failed: {}",
                io::Error::last_os_error()
            ));
        }

        // SAFETY: after successful TUNSETIFF, ifr.ifr_name is NUL-terminated
        // by the kernel with the assigned interface name.
        let name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr()) }
            .to_string_lossy()
            .into_owned();

        // Set non-blocking.
        // SAFETY: raw_fd is a valid /dev/net/tun file descriptor; F_GETFL
        // is a standard fcntl operation with no memory side effects.
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(anyhow::anyhow!(
                "fcntl F_GETFL failed: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: raw_fd is valid; F_SETFL with O_NONBLOCK is a standard
        // operation; the flags value came from a successful F_GETFL above.
        let ret = unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(anyhow::anyhow!(
                "fcntl F_SETFL O_NONBLOCK failed: {}",
                io::Error::last_os_error()
            ));
        }

        let raw_fd = dev.into_raw_fd();
        // SAFETY: raw_fd was obtained from dev.into_raw_fd() — we own this
        // fd and it refers to a valid open /dev/net/tun descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let async_fd = AsyncFd::new(fd)?;
        tracing::info!(name = %name, "Linux TUN device opened");

        Ok(Box::new(LinuxTun {
            async_fd,
            name,
            mtu: AtomicU16::new(1500),
        }))
    }
}

impl TunDevice for LinuxTun {
    fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> anyhow::Result<()> {
        // SAFETY: socket(AF_INET, SOCK_DGRAM, 0) is a standard POSIX call;
        // the only valid fds returned are >= 0.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(anyhow::anyhow!(
                "socket failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Helper to set sockaddr via ioctl.
        // SAFETY: this function is unsafe because the caller must ensure
        // sock is a valid fd and ifr has been zero-initialized with the
        // correct interface name copied in.
        unsafe fn set_sockaddr(
            ifr: &mut libc::ifreq,
            sock: libc::c_int,
            ioctl: libc::c_ulong,
            addr: u32,
        ) -> anyhow::Result<()> {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: addr },
                sin_zero: [0; 8],
            };
            // SAFETY: ifru_addr is a union field large enough for sockaddr_in;
            // the ioctl will read it as the correct type.
            std::ptr::write(
                &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut libc::sockaddr_in,
                sin,
            );
            // SAFETY: sock is a valid fd; ifr has correct interface name;
            // the ioctl code (SIOCSIFADDR or SIOCSIFNETMASK) matches the data.
            let ret = unsafe { libc::ioctl(sock, ioctl as _, ifr as *const _) };
            if ret < 0 {
                return Err(anyhow::anyhow!(
                    "ioctl failed: {}",
                    io::Error::last_os_error()
                ));
            }
            Ok(())
        }

        // SAFETY: zeroed ifreq is valid — all-zeroes is a well-defined
        // representation for this C struct.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        for (dst, src) in ifr.ifr_name[..copy_len]
            .iter_mut()
            .zip(&name_bytes[..copy_len])
        {
            *dst = *src as libc::c_char;
        }

        // SAFETY: sock and ifr are valid; set_sockaddr requires the fd to be
        // open and ifr to hold a valid interface name (copied above).
        unsafe { set_sockaddr(&mut ifr, sock, libc::SIOCSIFADDR, u32::from(addr).to_be()) }
            .inspect_err(|_| {
                // SAFETY: sock is a valid fd we own; closing on error path.
                unsafe { libc::close(sock) };
            })?;
        // SAFETY: same preconditions as SIOCSIFADDR call above.
        unsafe {
            set_sockaddr(
                &mut ifr,
                sock,
                libc::SIOCSIFNETMASK,
                u32::from(netmask).to_be(),
            )
        }
        .inspect_err(|_| {
            // SAFETY: sock is a valid fd we own; closing on error path.
            unsafe { libc::close(sock) };
        })?;

        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        // SAFETY: sock is a valid fd; ifr has correct interface name;
        // SIOCSIFMTU is the correct ioctl for setting MTU.
        let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr) };
        if ret < 0 {
            // SAFETY: sock is a valid fd we own; closing on error path.
            unsafe { libc::close(sock) };
            return Err(anyhow::anyhow!(
                "SIOCSIFMTU failed: {}",
                io::Error::last_os_error()
            ));
        }
        self.mtu.store(mtu, Ordering::Relaxed);

        // Bring up
        // SAFETY: sock is a valid fd; ifr has correct interface name;
        // SIOCGIFFLAGS is the correct ioctl for getting interface flags.
        let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &ifr) };
        if ret < 0 {
            // SAFETY: sock is a valid fd we own; closing on error path.
            unsafe { libc::close(sock) };
            return Err(anyhow::anyhow!(
                "SIOCGIFFLAGS get: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: ifru_flags was just populated by a successful SIOCGIFFLAGS;
        // OR'ing IFF_UP|IFF_RUNNING is a standard operation on the returned data.
        unsafe {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        // SAFETY: sock is a valid fd; ifr has correct interface name and
        // flags set above; SIOCSIFFLAGS brings the interface up.
        let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) };
        if ret < 0 {
            // SAFETY: sock is a valid fd we own; closing on error path.
            unsafe { libc::close(sock) };
            return Err(anyhow::anyhow!(
                "SIOCSIFFLAGS set: {}",
                io::Error::last_os_error()
            ));
        }

        // SAFETY: sock is a valid fd we own; configuration is complete,
        // the socket is no longer needed.
        unsafe { libc::close(sock) };
        tracing::info!(name = %self.name, %addr, %netmask, mtu, "Linux TUN configured");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }
}

impl AsRawFd for LinuxTun {
    fn as_raw_fd(&self) -> RawFd {
        self.async_fd.as_raw_fd()
    }
}

impl AsyncRead for LinuxTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.async_fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let dst = buf.initialize_unfilled();
            match guard.try_io(|fd| {
                let fd = fd.as_raw_fd();
                // SAFETY: fd is the TUN device fd, registered with
                // AsyncFd for readiness; dst is initialized_unfilled
                // with correct length; read() is a standard POSIX call.
                let n = unsafe { libc::read(fd, dst.as_mut_ptr() as *mut _, dst.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for LinuxTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.async_fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|fd| {
                let fd = fd.as_raw_fd();
                // SAFETY: fd is the TUN device fd, registered with
                // AsyncFd for readiness; buf is a valid read-only
                // slice with correct length; write() is standard POSIX.
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
