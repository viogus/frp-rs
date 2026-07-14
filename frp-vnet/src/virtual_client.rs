//! Virtual in-process client — provides in-memory pipe connections for VNet integration.
//!
//! Port of Go frp v0.69.1 `pkg/virtual/client.go`.
//!
//! The virtual client maintains an [`InternalListener`] and creates paired duplex
//! connections via [`frp_core::internal_listener::pipe()`]. One end of each pair
//! goes into the listener (consumed by VNet controller via `accept()`), the other
//! is returned for use by the caller as an in-memory transport.
//!
//! ## Architecture
//!
//! ```text
//! VNet Controller
//!       │
//!       │ listener.accept()
//!       ▼
//! InternalListener ◄── pipe() ──► DuplexPair (to caller / local routing)
//! ```
//!
//! Unlike Go frp's full virtual client (which wraps an entire frpc Service),
//! this Rust version focuses on the core abstraction: in-memory pipe pairs
//! that integrate with the VNet routing table for local packet delivery.
//! The Rust VNet already uses the existing control/work connection protocol
//! for VnetPacket messages, so a full in-process frpc is not required.

use frp_core::internal_listener::{pipe, DuplexPair, InternalListener};

/// Virtual in-process client for VNet integration.
///
/// Maintains an internal listener for peer connections. Callers call
/// [`connect_pair()`] to create a paired duplex connection — one end is
/// stored in the listener (consumed by the VNet controller via `accept()`),
/// the other is returned for immediate use.
///
/// [`connect_pair()`]: VirtualClient::connect_pair
pub struct VirtualClient {
    listener: InternalListener,
    /// Proxy names registered with this virtual client.
    proxy_names: Vec<String>,
}

impl VirtualClient {
    /// Create a new virtual client with the given proxy names.
    pub fn new(proxy_names: Vec<String>) -> Self {
        let listener = InternalListener::new();
        Self {
            listener,
            proxy_names,
        }
    }

    /// Return a cloneable handle for putting connections into the listener.
    ///
    /// The VNet controller calls `accept()` on the original listener,
    /// while this handle can be shared for `put_conn()` from any task.
    pub fn peer_handle(&self) -> frp_core::internal_listener::InternalListenerHandle {
        self.listener.handle()
    }

    /// Accept a peer connection from the internal listener.
    /// Blocks until `connect_pair()` is called.
    pub async fn accept(&mut self) -> Option<DuplexPair> {
        self.listener.accept().await
    }

    /// Create a paired connection.
    ///
    /// One end is placed into the internal listener for the VNet controller
    /// to accept. The other end is returned to the caller.
    ///
    /// Returns `None` if the listener channel is full (128 pending connections).
    pub fn connect_pair(&self) -> Option<DuplexPair> {
        let (local, remote) = pipe();
        match self.listener.put_conn(remote) {
            Ok(()) => Some(local),
            Err(_) => None,
        }
    }

    /// Return the proxy names registered with this virtual client.
    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    /// Update the proxy configs for this virtual client.
    pub fn update_proxy_names(&mut self, names: Vec<String>) {
        self.proxy_names = names;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_virtual_client_connect_and_accept() {
        let mut client = VirtualClient::new(vec!["vnet-proxy-1".into()]);
        assert_eq!(client.proxy_names(), &["vnet-proxy-1"]);

        // Connect: one end returned, one end in listener.
        let mut local = client.connect_pair().expect("connect_pair should succeed");

        // Accept the other end from the listener.
        let mut remote = client.accept().await.expect("accept should succeed");

        // Write from local, read from remote.
        local.write_all(b"vnet-packet").await.unwrap();
        let mut buf = [0u8; 11];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"vnet-packet");
    }

    #[tokio::test]
    async fn test_virtual_client_bidirectional() {
        let mut client = VirtualClient::new(vec!["proxy".into()]);
        let mut local = client.connect_pair().unwrap();
        let mut remote = client.accept().await.unwrap();

        // Bidirectional: local → remote, remote → local.
        local.write_all(b"hello").await.unwrap();
        remote.write_all(b"world").await.unwrap();

        let mut buf = [0u8; 5];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        local.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn test_virtual_client_update_proxies() {
        let mut client = VirtualClient::new(vec!["a".into()]);
        client.update_proxy_names(vec!["b".into(), "c".into()]);
        assert_eq!(client.proxy_names(), &["b", "c"]);
    }
}
