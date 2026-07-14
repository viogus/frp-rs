use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::task::{Context, Poll};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

use super::tun::TunDevice;

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const UTUN_OPT_IFNAME: i32 = 2;

/// macOS TUN device using utun via socket(SYSPROTO_CONTROL).
///
/// On macOS, the kernel writes a 4-byte address-family header (AF_INET=2 in
/// network byte order) at the start of every packet. We strip this on read
/// and prepend it on write so the caller sees/writes raw IP packets.
pub struct MacOSTun {
    async_fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: AtomicU16,
}

// SAFETY: AsyncFd<OwnedFd> is Send + Sync on Unix; AtomicU16 is Sync.
unsafe impl Send for MacOSTun {}

impl MacOSTun {
    pub async fn open(requested_name: &str) -> anyhow::Result<Box<dyn TunDevice>> {
        // Parse unit number from requested name (e.g. "utun3" → unit 3).
        // 0 means the kernel picks the next available unit.
        let unit: u32 = if !requested_name.is_empty() && requested_name.starts_with("utun") {
            requested_name[4..].parse().unwrap_or(0)
        } else {
            0
        };

        // SAFETY: socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) is the
        // standard macOS path to open a kernel control socket for utun.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(anyhow::anyhow!(
                "socket SYSPROTO_CONTROL failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Connect to the utun kernel control
        // SAFETY: zeroed ctl_info is valid — all-zeroes is a well-defined
        // representation; CTLIOCGINFO fills ctl_id on success.
        let mut ctl_info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let name_bytes = UTUN_CONTROL_NAME.as_bytes();
        let copy_len = name_bytes.len().min(ctl_info.ctl_name.len() - 1);
        for (dst, src) in ctl_info.ctl_name[..copy_len]
            .iter_mut()
            .zip(name_bytes[..copy_len].iter())
        {
            *dst = *src as libc::c_char;
        }

        // SAFETY: fd is a valid kernel control socket; ctl_info has been
        // zero-initialized with the utun control name; CTLIOCGINFO is the
        // correct ioctl for resolving a kernel control ID.
        let ret = unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut ctl_info) };
        if ret < 0 {
            // SAFETY: fd is a valid fd we own; closing on error path.
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "CTLIOCGINFO failed: {}",
                io::Error::last_os_error()
            ));
        }

        // SAFETY: zeroed sockaddr_ctl is valid — all fields are set
        // explicitly below before the connect call.
        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = ctl_info.ctl_id;
        addr.sc_unit = unit;

        // SAFETY: fd is a valid kernel control socket; addr is a correctly
        // populated sockaddr_ctl with the resolved ctl_id; connect() binds
        // the socket to the specific utun unit.
        let ret = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as u32,
            )
        };
        if ret < 0 {
            // SAFETY: fd is a valid fd we own; closing on error path.
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "connect utun failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Get the actual interface name assigned by the kernel
        let mut ifname = [0u8; 64];
        let mut ifname_len = ifname.len() as u32;
        // SAFETY: fd is a valid connected utun socket; SYSPROTO_CONTROL +
        // UTUN_OPT_IFNAME gets the kernel-assigned interface name; ifname
        // buffer is correctly sized (64 bytes, matching XNU max).
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut _,
                &mut ifname_len,
            )
        };
        let name = if ret == 0 {
            let len = ifname.iter().position(|&b| b == 0).unwrap_or(ifname.len());
            String::from_utf8_lossy(&ifname[..len]).to_string()
        } else {
            format!("utun{}", unit)
        };

        // Set non-blocking.
        // SAFETY: fd is a valid utun fd; F_GETFL is a standard fcntl
        // operation with no memory side effects.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 {
            // SAFETY: fd is a valid fd we own; closing on error path.
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "fcntl F_GETFL failed: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: fd is valid; F_SETFL with O_NONBLOCK is standard; flags
        // value came from successful F_GETFL above.
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            // SAFETY: fd is a valid fd we own; closing on error path.
            unsafe {
                libc::close(fd);
            }
            return Err(anyhow::anyhow!(
                "fcntl F_SETFL O_NONBLOCK failed: {}",
                io::Error::last_os_error()
            ));
        }

        // SAFETY: fd was obtained from socket() above and is now configured
        // as non-blocking; we are transferring ownership to OwnedFd.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = AsyncFd::new(owned)?;

        tracing::info!(name = %name, "macOS utun device opened");
        Ok(Box::new(MacOSTun {
            async_fd,
            name,
            mtu: AtomicU16::new(1500),
        }))
    }
}

impl TunDevice for MacOSTun {
    fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> anyhow::Result<()> {
        let name = self.name.clone();
        let addr_str = addr.to_string();
        let mask_str = netmask.to_string();
        let mtu_str = mtu.to_string();

        // Use ifconfig to configure the interface (macOS lacks Linux-style netdevice ioctls)
        let output = std::process::Command::new("ifconfig")
            .args([
                &name, "inet", &addr_str, "netmask", &mask_str, "mtu", &mtu_str, "up",
            ])
            .output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "ifconfig failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        tracing::info!(name = %self.name, %addr, %netmask, mtu, "macOS TUN configured");
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }
}

impl Drop for MacOSTun {
    fn drop(&mut self) {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "destroy"])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                tracing::info!(name = %self.name, "macOS utun interface destroyed");
            }
            Ok(o) => {
                tracing::warn!(
                    name = %self.name,
                    stderr = %String::from_utf8_lossy(&o.stderr),
                    "failed to destroy macOS utun interface"
                );
            }
            Err(e) => {
                tracing::warn!(
                    name = %self.name,
                    error = %e,
                    "failed to run ifconfig destroy for macOS utun interface"
                );
            }
        }
    }
}

impl AsRawFd for MacOSTun {
    fn as_raw_fd(&self) -> RawFd {
        self.async_fd.as_raw_fd()
    }
}

impl AsyncRead for MacOSTun {
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
                // SAFETY: fd is the utun fd registered with AsyncFd for
                // readiness; dst is initialized_unfilled with correct
                // length; read() is a standard POSIX call.
                let n = unsafe { libc::read(fd, dst.as_mut_ptr() as *mut _, dst.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    // macOS utun prepends a 4-byte AF header (AF_INET=2).
                    // Short read (n <= 4 means no packet data after AF header).
                    // Continue the read loop instead of returning 0 (which signals EOF).
                    if n <= 4 {
                        continue;
                    }
                    let actual = n - 4;
                    dst.copy_within(4..n, 0);
                    buf.advance(actual);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for MacOSTun {
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
                // Prepend 4-byte AF header: AF_INET = 2 in network byte order
                let header: [u8; 4] = [0, 0, 0, 2];
                let mut packet = Vec::with_capacity(4 + buf.len());
                packet.extend_from_slice(&header);
                packet.extend_from_slice(buf);
                // SAFETY: fd is the utun fd registered with AsyncFd for
                // readiness; packet is a Vec with correct length including
                // the 4-byte AF header; write() is standard POSIX.
                let n = unsafe { libc::write(fd, packet.as_ptr() as *const _, packet.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else if n < 4 {
                    Err(io::Error::new(io::ErrorKind::WriteZero, "TUN short write"))
                } else {
                    // Subtract 4-byte AF header; return original payload bytes written
                    Ok(n as usize - 4)
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
