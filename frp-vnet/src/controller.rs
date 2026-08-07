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
        ctl_writer: Arc<tokio::sync::Mutex<frp_core::transport::BoxedWriteHalf>>,
        mut tun_packet_rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mtu = tun.mtu() as usize;
        let mut tun_buf = vec![0u8; mtu];

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
                                    self.client.unregister_server_conn(&dst_ip);
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
                            let mut writer = ctl_writer.lock().await;
                            let write_result = if self.v2 {
                                frp_core::protocol::write_msg_v2(&mut *writer, &msg).await
                            } else {
                                frp_core::protocol::write_msg_v1(&mut *writer, &msg).await
                            };
                            drop(writer);
                            if let Err(e) = write_result {
                                tracing::error!(%self.proxy_name, %e, "control write error");
                                break;
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
                            if let Err(e) = tun.write_all(&pkt).await {
                                tracing::error!(%self.proxy_name, %e, "TUN write error");
                                return Err(anyhow::anyhow!("TUN write error: {e}"));
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
            .unwrap()
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
        let ctl_stream: Box<dyn frp_core::transport::AsyncReadWrite> =
            Box::new(tokio::io::duplex(4096).0);
        let (_, ctl_w) = tokio::io::split(ctl_stream);
        let writer = Arc::new(tokio::sync::Mutex::new(
            Box::new(ctl_w) as frp_core::transport::BoxedWriteHalf
        ));
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
        let ctl_stream: Box<dyn frp_core::transport::AsyncReadWrite> =
            Box::new(tokio::io::duplex(4096).0);
        let (_, ctl_w) = tokio::io::split(ctl_stream);
        let writer = Arc::new(tokio::sync::Mutex::new(
            Box::new(ctl_w) as frp_core::transport::BoxedWriteHalf
        ));
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
        let (ctl_peer_raw, ctl_writer_raw) = tokio::io::duplex(4096);
        let ctl_peer_stream: Box<dyn frp_core::transport::AsyncReadWrite> = Box::new(ctl_peer_raw);
        let ctl_writer_stream: Box<dyn frp_core::transport::AsyncReadWrite> =
            Box::new(ctl_writer_raw);
        let (mut ctl_peer, _) = tokio::io::split(ctl_peer_stream);
        let (_, ctl_w) = tokio::io::split(ctl_writer_stream);
        let writer = Arc::new(tokio::sync::Mutex::new(
            Box::new(ctl_w) as frp_core::transport::BoxedWriteHalf
        ));
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
        let msg = frp_core::protocol::read_msg_v1(&mut ctl_peer)
            .await
            .unwrap();
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
}
