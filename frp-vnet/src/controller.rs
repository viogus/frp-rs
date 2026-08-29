//! VNet controller — bidirectional TUN↔control_conn packet forwarding loop.
//! Uses frp-core protocol framing (V1/V2) with VnetPacket messages.
//!
//! TX: TUN read → route lookup → VnetPacket → write_msg on ctl_writer (control conn)
//! RX: tun_packet_rx → TUN write

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};

use frp_core::base64::encode as b64_encode;

use crate::router::RouteTable;
use crate::tun::TunDevice;

/// Size of the TUN read buffer for a given MTU.
///
/// macOS utun prepends a 4-byte AF header to every packet, so a
/// full-size packet occupies `mtu + 4` bytes on the wire. Sizing the
/// buffer exactly `mtu` truncates the tail of every full-size packet
/// by 4 bytes. The extra 4 bytes are harmless on platforms without
/// the header.
fn tun_read_buf_len(mtu: u16) -> usize {
    mtu as usize + 4
}

/// Whether a TUN write error means the device itself is gone (closed or
/// destroyed) — the only errors that should terminate the TUN pump. Any
/// other error (e.g. EMSGSIZE for an oversized datagram) is a per-packet
/// failure: drop the packet and keep pumping, so a transient device error
/// cannot strand the proxy registration.
fn is_tun_write_fatal(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        return true; // EPIPE
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        e.raw_os_error() == Some(libc::EBADF)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Manages a TUN device ↔ frp work connection packet loop.
pub struct VnetController {
    /// Shared client-side controller: routing table plus server-conn registry.
    client: Arc<ClientVnetController>,
    /// Proxy name for this controller.
    proxy_name: String,
    /// Virtual net this controller belongs to (empty = default vnet).
    /// Lookups and route updates are scoped to this vnet for isolation.
    vnet: String,
    /// Whether to use V2 protocol framing.
    v2: bool,
}

impl VnetController {
    pub fn new(
        proxy_name: String,
        client: Arc<ClientVnetController>,
        v2: bool,
        vnet: String,
    ) -> Self {
        Self {
            client,
            proxy_name,
            vnet,
            v2,
        }
    }

    /// Update the local route table from server advertisements (scoped to the
    /// controller's virtual net).
    pub async fn update_route(&self, name: &str, subnet: &str) -> anyhow::Result<()> {
        let table = self.client.route_table();
        let mut routes = table.write().await;
        routes.insert(&self.vnet, name, subnet)?;
        tracing::info!(vnet = %self.vnet, %subnet, %name, "vnet route updated");
        Ok(())
    }

    /// Remove a route (scoped to the controller's virtual net).
    pub async fn remove_route(&self, name: &str) {
        let table = self.client.route_table();
        let mut routes = table.write().await;
        routes.remove(&self.vnet, name);
    }

    /// Return the proxy name for this controller.
    pub fn proxy_name(&self) -> &str {
        &self.proxy_name
    }

    /// Run the bidirectional packet loop via the control connection.
    ///
    /// TX: TUN read → route lookup → VnetPacket → write_msg on ctl_writer
    /// RX: tun_packet_rx → TUN write
    pub async fn run(
        &self,
        mut tun: Box<dyn TunDevice>,
        ctl_writer: Arc<dyn frp_core::ControlSink>,
        mut tun_packet_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut tun_buf = vec![0u8; tun_read_buf_len(tun.mtu())];
        // Rate-limits "dropping packet" warnings (oversized TUN writes, full
        // control queue) to at most one per second: a misbehaving peer or a
        // slow control writer must not be able to flood the log at TUN read
        // rate. Initialized in the past so the first drop warns immediately.
        let mut last_drop_warn = std::time::Instant::now() - std::time::Duration::from_secs(2);

        loop {
            tokio::select! {
                // TUN → control connection: read IP packet, lookup route, send VnetPacket
                result = tun.read(&mut tun_buf) => {
                    match result {
                        Ok(0) => {
                            tracing::info!(%self.proxy_name, "TUN device closed");
                            break;
                        }
                        Ok(n) => {
                            let packet = &tun_buf[..n];
                            // Parse IPv4/IPv6 header to get destination IP.
                            let Some(dst_ip) = crate::router::packet_dst_ip(packet) else {
                                tracing::warn!(
                                    %self.proxy_name,
                                    "vnet TUN read: unsupported or malformed IP packet dropped"
                                );
                                continue;
                            };

                        // Go frp serverRouter equivalent: a packet whose
                        // destination matches a source IP learned from a
                        // virtual_net plugin work connection is returned on
                        // that connection instead of the control channel.
                        if let Some(server_tx) = self.client.server_conn_sender(&dst_ip) {
                            match server_tx.try_send(packet.to_vec()) {
                                Ok(()) => continue,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    tracing::warn!(
                                        %self.proxy_name,
                                        %dst_ip,
                                        "vnet server-conn queue full; dropping return packet"
                                    );
                                    continue;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    // Only drop the registration if it still refers to
                                    // the channel that closed; a newer connection may
                                    // have registered the same dst_ip since.
                                    self.client
                                        .unregister_server_conn_if_matches(&dst_ip, &server_tx);
                                }
                            }
                        }

                        // Fall back to control-connection VnetPacket routing
                        // (visitor host routes and peer TUN-backed proxies).
                        let routes = self.client.route_table();
                        let target = routes
                            .read()
                            .await
                            .lookup(&self.vnet, &dst_ip)
                            .map(str::to_string);
                        if let Some(target) = target {
                            let vnet_pkt = frp_core::msg::VnetPacket {
                                proxy_name: target,
                                data: b64_encode(packet),
                            };
                            let msg = frp_core::msg::FrpMessage::VnetPacket(vnet_pkt);
                            if let Err(e) = ctl_writer.send_msg(msg, self.v2) {
                                // Round 10 (MEDIUM): a transient channel-full
                                // error must not kill the whole TUN pump —
                                // the ControlSink contract is drop-when-full
                                // (Go frp parity), so only a failed writer
                                // (control connection gone) is terminal.
                                if ctl_writer.is_failed() {
                                    tracing::error!(%self.proxy_name, %e, "control write error");
                                    break;
                                }
                                let now = std::time::Instant::now();
                                if now.duration_since(last_drop_warn)
                                    >= std::time::Duration::from_secs(1)
                                {
                                    last_drop_warn = now;
                                    tracing::warn!(
                                        %self.proxy_name,
                                        %e,
                                        "vnet control queue full; dropping packet"
                                    );
                                }
                            }
                        }
                        // If no route match, packet dropped (not destined for this vnet).
                    }
                        Err(e) => {
                            tracing::error!(%self.proxy_name, %e, "TUN read error");
                            return Err(anyhow::anyhow!("TUN read error: {e}"));
                        }
                    }
                }
                // control connection → TUN: receive decoded packets from service
                packet = tun_packet_rx.recv() => {
                    match packet {
                        Some(pkt) => {
                            // Reject packets that cannot fit the device MTU
                            // before writing: Linux TUN rejects datagrams
                            // longer than the MTU with EMSGSIZE, and macOS
                            // utun does likewise for payloads over the MTU
                            // (its 4-byte AF family header sits on top of
                            // that budget). A remote peer with a larger MTU
                            // — or a malformed oversized packet — must not
                            // be able to take the whole TUN pump down.
                            if pkt.len() > tun.mtu() as usize {
                                let now = std::time::Instant::now();
                                if now.duration_since(last_drop_warn)
                                    >= std::time::Duration::from_secs(1)
                                {
                                    last_drop_warn = now;
                                    tracing::warn!(
                                        %self.proxy_name,
                                        pkt_len = pkt.len(),
                                        mtu = tun.mtu(),
                                        "vnet TUN write: oversized packet dropped"
                                    );
                                }
                                continue;
                            }
                            if let Err(e) = tun.write_all(&pkt).await {
                                // Only a device-close-class error (EBADF,
                                // EPIPE; read-side EOF is handled by the
                                // TUN read arm) terminates the pump. Any
                                // other write error is per-packet: drop the
                                // packet and keep pumping so a transient
                                // device error cannot strand the proxy
                                // registration.
                                if is_tun_write_fatal(&e) {
                                    tracing::error!(%self.proxy_name, %e, "TUN write error");
                                    return Err(anyhow::anyhow!("TUN write error: {e}"));
                                }
                                let now = std::time::Instant::now();
                                if now.duration_since(last_drop_warn)
                                    >= std::time::Duration::from_secs(1)
                                {
                                    last_drop_warn = now;
                                    tracing::warn!(
                                        %self.proxy_name,
                                        %e,
                                        "vnet TUN write failed; dropping packet"
                                    );
                                }
                            }
                        }
                        None => {
                            tracing::info!(%self.proxy_name, "tun_packet channel closed");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Shared client-side virtual network controller.
///
/// Owns the routing table used by every TUN-backed [`VnetController`] on the
/// client and tracks `virtual_net` visitor tunnels so inbound [`VnetPacket`]s
/// can be delivered to the correct STCP/XTCP visitor connection.
pub struct ClientVnetController {
    /// Local routing table: subnet → proxy/visitor name (TX direction).
    routes: Arc<RwLock<RouteTable>>,
    /// Packet delivery channels for `virtual_net` visitor tunnels, keyed by
    /// visitor name. Inbound packets from the server are forwarded into the
    /// channel, and the visitor task writes them into the tunnel connection.
    visitor_txs: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
    /// Source-IP → work-conn channels registered by the provider-side
    /// `virtual_net` plugin. Used to return TUN packets to the remote tunnel
    /// without a control-connection round trip.
    server_conns: Arc<Mutex<HashMap<IpAddr, mpsc::Sender<Vec<u8>>>>>,
}

impl ClientVnetController {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(RouteTable::new())),
            visitor_txs: Arc::new(Mutex::new(HashMap::new())),
            server_conns: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the shared route table used by TUN-backed controllers.
    pub fn route_table(&self) -> Arc<RwLock<RouteTable>> {
        Arc::clone(&self.routes)
    }

    /// Register a `virtual_net` visitor host route (e.g. `100.86.0.1/32`)
    /// mapped to the visitor name and its packet delivery channel.
    ///
    /// Visitor routes belong to the default virtual net (the advertisement is
    /// sent with `virtual_net: None`), so they are inserted under `""`.
    pub async fn register_visitor_route(
        &self,
        name: &str,
        cidr: &str,
        packet_tx: mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.routes.write().await.insert("", name, cidr)?;
        self.visitor_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_string(), packet_tx);
        tracing::info!(visitor_name = %name, cidr = %cidr, "virtual_net visitor route registered");
        Ok(())
    }

    /// Remove a `virtual_net` visitor route and its delivery channel.
    pub async fn unregister_visitor_route(&self, name: &str) {
        self.routes.write().await.remove("", name);
        self.visitor_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name);
        tracing::info!(visitor_name = %name, "virtual_net visitor route removed");
    }

    /// Deliver an inbound packet to a visitor tunnel.
    ///
    /// Returns `Ok(())` when the visitor route exists (including when the
    /// bounded channel is full and the packet is dropped), and `Err(packet)`
    /// when no visitor is registered for `name` or its channel is closed — the
    /// caller then handles the packet itself (e.g. via a TUN delivery channel).
    pub fn deliver_visitor_packet(&self, name: &str, packet: Vec<u8>) -> Result<(), Vec<u8>> {
        let mut txs = self.visitor_txs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = txs.get(name) else {
            return Err(packet);
        };
        match tx.try_send(packet) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(packet)) => {
                tracing::warn!(
                    visitor_name = %name,
                    "virtual_net visitor packet queue full; dropping packet"
                );
                drop(packet);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(packet)) => {
                // The visitor task is gone; remove the stale registration.
                txs.remove(name);
                Err(packet)
            }
        }
    }

    /// Register a provider-side work connection for packets whose destination
    /// IP equals `src_ip` (the remote host's source IP learned from the
    /// tunnel). Mirrors Go frp `serverRouter.registerSrcIP`.
    pub fn register_server_conn(&self, src_ip: IpAddr, packet_tx: mpsc::Sender<Vec<u8>>) {
        self.server_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(src_ip, packet_tx);
        tracing::debug!(%src_ip, "vnet server conn registered");
    }

    /// Remove a provider-side work connection mapping.
    pub fn unregister_server_conn(&self, src_ip: &IpAddr) {
        self.server_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(src_ip);
        tracing::debug!(%src_ip, "vnet server conn unregistered");
    }

    /// Remove a provider-side work connection mapping only when it still
    /// refers to `packet_tx`, so a newer connection is never clobbered.
    pub fn unregister_server_conn_if_matches(
        &self,
        src_ip: &IpAddr,
        packet_tx: &mpsc::Sender<Vec<u8>>,
    ) {
        let mut conns = self.server_conns.lock().unwrap_or_else(|e| e.into_inner());
        if conns
            .get(src_ip)
            .is_some_and(|tx| tx.same_channel(packet_tx))
        {
            conns.remove(src_ip);
        }
    }

    /// Return the work-conn channel registered for `dst_ip`, if any.
    pub fn server_conn_sender(&self, dst_ip: &IpAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.server_conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(dst_ip)
            .cloned()
    }

    /// IPv4-only convenience wrapper for [`Self::register_server_conn`].
    pub fn register_server_conn_v4(&self, src_ip: Ipv4Addr, packet_tx: mpsc::Sender<Vec<u8>>) {
        self.register_server_conn(IpAddr::V4(src_ip), packet_tx);
    }

    /// IPv4-only convenience wrapper for [`Self::unregister_server_conn`].
    pub fn unregister_server_conn_v4(&self, src_ip: &Ipv4Addr) {
        self.unregister_server_conn(&IpAddr::V4(*src_ip));
    }

    /// IPv4-only convenience wrapper for [`Self::unregister_server_conn_if_matches`].
    pub fn unregister_server_conn_if_matches_v4(
        &self,
        src_ip: &Ipv4Addr,
        packet_tx: &mpsc::Sender<Vec<u8>>,
    ) {
        self.unregister_server_conn_if_matches(&IpAddr::V4(*src_ip), packet_tx);
    }

    /// IPv4-only convenience wrapper for [`Self::server_conn_sender`].
    pub fn server_conn_sender_v4(&self, dst_ip: &Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.server_conn_sender(&IpAddr::V4(*dst_ip))
    }
}

impl Default for ClientVnetController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    /// Records control messages; stands in for the real writer funnel.
    #[derive(Default)]
    struct TestSink {
        msgs: std::sync::Mutex<Vec<(frp_core::msg::FrpMessage, bool)>>,
        /// When set, `send_msg` returns Err — simulating a full channel.
        full: std::sync::atomic::AtomicBool,
        /// When set, `is_failed()` reports a dead writer (control conn gone).
        failed: std::sync::atomic::AtomicBool,
    }

    impl frp_core::ControlSink for TestSink {
        fn send_msg(&self, msg: frp_core::msg::FrpMessage, v2: bool) -> Result<(), String> {
            if self.full.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("queue full".to_string());
            }
            self.msgs.lock().unwrap().push((msg, v2));
            Ok(())
        }

        fn is_failed(&self) -> bool {
            self.failed.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    fn test_sink() -> Arc<TestSink> {
        Arc::new(TestSink::default())
    }

    fn test_sink_with(full: bool, failed: bool) -> Arc<TestSink> {
        let sink = test_sink();
        sink.full.store(full, std::sync::atomic::Ordering::Relaxed);
        sink.failed
            .store(failed, std::sync::atomic::Ordering::Relaxed);
        sink
    }

    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

    struct FakeTun {
        inner: tokio::io::DuplexStream,
    }

    impl Unpin for FakeTun {}

    impl AsyncRead for FakeTun {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for FakeTun {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl TunDevice for FakeTun {
        fn configure(&self, _addr: Ipv4Addr, _netmask: Ipv4Addr, _mtu: u16) -> anyhow::Result<()> {
            Ok(())
        }

        fn name(&self) -> &str {
            "fake"
        }

        fn mtu(&self) -> u16 {
            1420
        }
    }

    #[tokio::test]
    async fn register_and_unregister_visitor_route() {
        let ctrl = ClientVnetController::new();
        let (tx, _rx) = mpsc::channel(16);
        ctrl.register_visitor_route("vnet-visitor", "100.86.0.1/32", tx)
            .await
            .unwrap();

        let routes = ctrl.route_table();
        assert_eq!(
            routes
                .read()
                .await
                .lookup("", &IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1))),
            Some("vnet-visitor")
        );

        ctrl.unregister_visitor_route("vnet-visitor").await;
        assert_eq!(
            routes
                .read()
                .await
                .lookup("", &IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1))),
            None
        );
    }

    #[tokio::test]
    async fn deliver_packet_to_visitor_connection() {
        let ctrl = ClientVnetController::new();
        let (tx, mut rx) = mpsc::channel(16);
        ctrl.register_visitor_route("vnet-visitor", "100.86.0.1/32", tx)
            .await
            .unwrap();

        let packet = vec![0x45, 0x00, 0x00, 0x14, 0x01, 0x02];
        assert!(ctrl
            .deliver_visitor_packet("vnet-visitor", packet.clone())
            .is_ok());
        assert_eq!(rx.recv().await, Some(packet));
    }

    #[tokio::test]
    async fn deliver_to_unregistered_or_closed_visitor_fails() {
        let ctrl = ClientVnetController::new();
        assert!(ctrl.deliver_visitor_packet("missing", vec![0x45]).is_err());

        let (tx, rx) = mpsc::channel(16);
        ctrl.register_visitor_route("gone", "10.0.0.1/32", tx)
            .await
            .unwrap();
        drop(rx);
        assert!(ctrl.deliver_visitor_packet("gone", vec![0x45]).is_err());
        // The stale registration is removed after the closed channel is detected.
        assert!(ctrl.deliver_visitor_packet("gone", vec![0x45]).is_err());
    }

    #[tokio::test]
    async fn server_conn_route_is_unregistered_when_matching_channel_closes() {
        let ctrl = ClientVnetController::new();
        let src = IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1));
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let tx_clone = tx.clone();
        ctrl.register_server_conn(src, tx);
        assert!(ctrl.server_conn_sender(&src).is_some());

        drop(rx);
        let (new_tx, _new_rx) = mpsc::channel::<Vec<u8>>(16);
        // A different connection must not unregister the current mapping.
        ctrl.unregister_server_conn_if_matches(&src, &new_tx);
        assert!(ctrl.server_conn_sender(&src).is_some());
        // The original connection's channel is gone; matching cleanup removes it.
        ctrl.unregister_server_conn_if_matches(&src, &tx_clone);
        assert!(ctrl.server_conn_sender(&src).is_none());
    }

    #[tokio::test]
    async fn server_conn_registry_supports_ipv6() {
        let ctrl = ClientVnetController::new();
        let src: IpAddr = "2001:db8::1".parse().unwrap();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(16);
        let tx_clone = tx.clone();
        ctrl.register_server_conn(src, tx);
        assert!(ctrl.server_conn_sender(&src).is_some());

        drop(rx);
        let (new_tx, _new_rx) = mpsc::channel::<Vec<u8>>(16);
        ctrl.unregister_server_conn_if_matches(&src, &new_tx);
        assert!(ctrl.server_conn_sender(&src).is_some());
        ctrl.unregister_server_conn_if_matches(&src, &tx_clone);
        assert!(ctrl.server_conn_sender(&src).is_none());
    }

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet
    }

    #[tokio::test]
    async fn controller_returns_tun_packets_to_server_conn_and_forwards_to_tun() {
        let client = Arc::new(ClientVnetController::new());
        let (work_tx, mut work_rx) = mpsc::channel::<Vec<u8>>(16);
        let remote_ip = IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1));
        client.register_server_conn(remote_ip, work_tx);

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink();
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer, tun_packet_rx).await.unwrap();
        });

        // TUN → work conn: destination equals the registered remote source IP.
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 100, 86, 0, 2,
            100, 86, 0, 1,
        ];
        tun_peer.write_all(&packet).await.unwrap();
        assert_eq!(work_rx.recv().await, Some(packet.clone()));

        // Work conn → TUN: packets injected through the channel reach the TUN.
        tun_packet_tx.send(packet.clone()).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tun_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &packet[..]);

        drop(tun_packet_tx);
        drop(tun_peer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn controller_returns_ipv6_packets_to_registered_server_conn() {
        let client = Arc::new(ClientVnetController::new());
        let (work_tx, mut work_rx) = mpsc::channel::<Vec<u8>>(16);
        let remote_ip: IpAddr = "2001:db8::1".parse().unwrap();
        client.register_server_conn(remote_ip, work_tx);

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink();
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer, tun_packet_rx).await.unwrap();
        });

        let packet = ipv6_packet(
            "2001:db8::2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        );
        tun_peer.write_all(&packet).await.unwrap();
        assert_eq!(work_rx.recv().await, Some(packet));

        drop(tun_packet_tx);
        drop(tun_peer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn controller_routes_ipv6_packets_through_control_connection() {
        let client = Arc::new(ClientVnetController::new());
        client
            .route_table()
            .write()
            .await
            .insert("", "v6-target", "2001:db8::/64")
            .unwrap();

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink();
        let writer_for_task = writer.clone();
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer_for_task, tun_packet_rx).await.unwrap();
        });

        let packet = ipv6_packet(
            "2001:db8::2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        );
        tun_peer.write_all(&packet).await.unwrap();
        // Poll the sink until the routed packet arrives.
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let pending = { writer.msgs.lock().unwrap().last().cloned() };
                if let Some((msg, _)) = pending {
                    return msg;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sink never received VnetPacket");
        match msg {
            frp_core::msg::FrpMessage::VnetPacket(vpkt) => {
                assert_eq!(vpkt.proxy_name, "v6-target");
                assert_eq!(frp_core::base64::decode(&vpkt.data).unwrap(), packet);
            }
            other => panic!("expected VnetPacket, got type {}", other.v1_type_byte()),
        }

        drop(tun_packet_tx);
        drop(tun_peer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[test]
    fn tun_read_buf_len_reserves_room_for_macos_af_header() {
        // macOS utun delivers [4-byte AF header][packet], so a full-size
        // packet occupies mtu + 4 bytes; sizing the buffer exactly `mtu`
        // would truncate the packet tail by 4 bytes.
        assert_eq!(tun_read_buf_len(1500), 1504);
        assert_eq!(tun_read_buf_len(1420), 1424);
        assert_eq!(tun_read_buf_len(0), 4);
    }

    #[tokio::test]
    async fn controller_cleans_up_closed_server_conn_without_clobbering_newer_registration() {
        let client = Arc::new(ClientVnetController::new());
        let remote_ip = IpAddr::V4(Ipv4Addr::new(100, 86, 0, 1));

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink();
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer, tun_packet_rx).await.unwrap();
        });

        // A packet destined for remote_ip arrives while the registered
        // server conn is already closed: the Closed error must clean up
        // exactly that (matching) registration.
        let (tx1, rx1) = mpsc::channel::<Vec<u8>>(16);
        client.register_server_conn(remote_ip, tx1);
        drop(rx1);
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 100, 86, 0, 2,
            100, 86, 0, 1,
        ];
        tun_peer.write_all(&packet).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if client.server_conn_sender(&remote_ip).is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("closed server conn was never unregistered");
        assert!(client.server_conn_sender(&remote_ip).is_none());

        // A newer registration under the same IP must not be clobbered by
        // the stale closed channel: packets reach it and it stays registered.
        let (tx2, mut rx2) = mpsc::channel::<Vec<u8>>(16);
        client.register_server_conn(remote_ip, tx2);
        tun_peer.write_all(&packet).await.unwrap();
        assert_eq!(rx2.recv().await, Some(packet.clone()));
        assert!(client.server_conn_sender(&remote_ip).is_some());

        drop(tun_packet_tx);
        drop(tun_peer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }

    #[tokio::test]
    async fn failed_writer_terminates_tun_pump() {
        // A writer whose control connection is gone (is_failed == true)
        // terminates the TUN pump instead of dropping packets forever.
        let client = Arc::new(ClientVnetController::new());
        client
            .route_table()
            .write()
            .await
            .insert("", "target", "10.0.0.0/24")
            .unwrap();

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink_with(true, true); // send fails AND writer failed
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer, tun_packet_rx).await.unwrap();
        });

        // A routable TUN packet hits the failed writer: the pump must exit.
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        tun_peer.write_all(&packet).await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("failed writer must terminate the TUN pump")
            .expect("pump task must not panic");
        drop(tun_packet_tx);
    }

    #[tokio::test]
    async fn full_but_alive_writer_drops_packet_and_keeps_pumping() {
        // A full-but-alive writer (send_msg Err, is_failed == false) must
        // not kill the pump: the packet is dropped, and the pump keeps
        // forwarding once the writer accepts again.
        let client = Arc::new(ClientVnetController::new());
        client
            .route_table()
            .write()
            .await
            .insert("", "target", "10.0.0.0/24")
            .unwrap();

        let (tun_stream, mut tun_peer) = tokio::io::duplex(4096);
        let tun = Box::new(FakeTun { inner: tun_stream });
        let writer = test_sink_with(true, false); // send fails, writer alive
        let writer_for_task = writer.clone();
        let (tun_packet_tx, tun_packet_rx) = mpsc::channel::<Vec<u8>>(16);
        let ctrl = VnetController::new(
            "plugin-proxy".to_string(),
            client.clone(),
            false,
            String::new(),
        );
        let handle = tokio::spawn(async move {
            ctrl.run(tun, writer_for_task, tun_packet_rx).await.unwrap();
        });

        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 2,
            10, 0, 0, 5,
        ];
        tun_peer.write_all(&packet).await.unwrap();

        // Give the pump a moment: the dropped packet must not terminate it.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !handle.is_finished(),
            "full-but-alive writer must not terminate the TUN pump"
        );

        // Once the writer accepts again, the pump still forwards packets.
        writer
            .full
            .store(false, std::sync::atomic::Ordering::Relaxed);
        tun_peer.write_all(&packet).await.unwrap();
        let msg = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let pending = { writer.msgs.lock().unwrap().last().cloned() };
                if let Some((msg, _)) = pending {
                    return msg;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sink never received VnetPacket");
        match msg {
            frp_core::msg::FrpMessage::VnetPacket(vpkt) => {
                assert_eq!(vpkt.proxy_name, "target");
                assert_eq!(frp_core::base64::decode(&vpkt.data).unwrap(), packet);
            }
            other => panic!("expected VnetPacket, got type {}", other.v1_type_byte()),
        }

        drop(tun_packet_tx);
        drop(tun_peer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
    }
}
