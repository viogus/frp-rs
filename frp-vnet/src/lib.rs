//! Virtual network (L3 VPN) for frp-rs.
//! Provides TUN device abstraction, CIDR routing, and packet controller.

pub mod tun;
pub mod router;
pub mod controller;
pub mod msg;

#[cfg(target_os = "linux")]
mod tun_linux;
#[cfg(target_os = "macos")]
mod tun_macos;
#[cfg(target_os = "windows")]
mod tun_windows;
