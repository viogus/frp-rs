//! VNet controller — bidirectional TUN↔control_conn packet forwarding loop.
//! Uses frp-core protocol framing (V1/V2) with VnetPacket messages.
//!
//! TX: TUN read → route lookup → VnetPacket → write_msg on ctl_writer (control conn)
//! RX: tun_packet_rx → TUN write

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};

use data_encoding::BASE64;

use crate::router::RouteTable;
use crate::tun::TunDevice;

/// Manages a TUN device ↔ frp work connection packet loop.
pub struct VnetController {
    /// Local routing table: remote_subnet → proxy_name (for TX direction).
    routes: Arc<RwLock<RouteTable>>,
    /// Proxy name for this controller.
    proxy_name: String,
    /// Whether to use V2 protocol framing.
    v2: bool,
}

impl VnetController {
    pub fn new(proxy_name: String, routes: Arc<RwLock<RouteTable>>, v2: bool) -> Self {
        Self {
            routes,
            proxy_name,
            v2,
        }
    }

    /// Update the local route table from server advertisements.
    pub async fn update_route(&self, name: &str, subnet: &str) -> anyhow::Result<()> {
        let mut routes = self.routes.write().await;
        routes.insert(name, subnet)?;
        tracing::info!(%subnet, %name, "vnet route updated");
        Ok(())
    }

    /// Remove a route.
    pub async fn remove_route(&self, name: &str) {
        let mut routes = self.routes.write().await;
        routes.remove(name);
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
        ctl_writer: Arc<Mutex<frp_core::transport::WriteHalf>>,
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
                            // Parse IPv4 header to get destination IP.
                            // IPv4 header: byte 0 has version (4 bits) + IHL (4 bits).
                            // Destination IP is at bytes 16-19.
                            if packet.len() < 20 || (packet[0] >> 4) != 4 {
                                // Skip non-IPv4 or malformed packet.
                                continue;
                            }
                            let dst_ip = Ipv4Addr::new(
                                packet[16], packet[17], packet[18], packet[19],
                            );

                            // Look up target proxy for this destination.
                            let routes = self.routes.read().await;
                            if let Some(target) = routes.lookup(&dst_ip) {
                                let target = target.to_string();
                                drop(routes);
                                let vnet_pkt = frp_core::msg::VnetPacket {
                                    proxy_name: target,
                                    data: BASE64.encode(packet),
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
}

impl ClientVnetController {
    pub fn new() -> Self {
        Self {
            routes: Arc::new(RwLock::new(RouteTable::new())),
            visitor_txs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the shared route table used by TUN-backed controllers.
    pub fn route_table(&self) -> Arc<RwLock<RouteTable>> {
        Arc::clone(&self.routes)
    }

    /// Register a `virtual_net` visitor host route (e.g. `100.86.0.1/32`)
    /// mapped to the visitor name and its packet delivery channel.
    pub async fn register_visitor_route(
        &self,
        name: &str,
        cidr: &str,
        packet_tx: mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.routes.write().await.insert(name, cidr)?;
        self.visitor_txs
            .lock()
            .await
            .insert(name.to_string(), packet_tx);
        tracing::info!(visitor_name = %name, cidr = %cidr, "virtual_net visitor route registered");
        Ok(())
    }

    /// Remove a `virtual_net` visitor route and its delivery channel.
    pub async fn unregister_visitor_route(&self, name: &str) {
        self.routes.write().await.remove(name);
        self.visitor_txs.lock().await.remove(name);
        tracing::info!(visitor_name = %name, "virtual_net visitor route removed");
    }

    /// Deliver an inbound packet to a visitor tunnel.
    ///
    /// Returns `true` when the visitor route exists (including when the
    /// bounded channel is full and the packet is dropped), and `false` when
    /// no visitor is registered for `name` or its channel is closed.
    pub async fn deliver_visitor_packet(&self, name: &str, packet: Vec<u8>) -> bool {
        let mut txs = self.visitor_txs.lock().await;
        let Some(tx) = txs.get(name) else {
            return false;
        };
        match tx.try_send(packet) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(packet)) => {
                tracing::warn!(
                    visitor_name = %name,
                    "virtual_net visitor packet queue full; dropping packet"
                );
                drop(packet);
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The visitor task is gone; remove the stale registration.
                txs.remove(name);
                false
            }
        }
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

    #[tokio::test]
    async fn register_and_unregister_visitor_route() {
        let ctrl = ClientVnetController::new();
        let (tx, _rx) = mpsc::channel(16);
        ctrl.register_visitor_route("vnet-visitor", "100.86.0.1/32", tx)
            .await
            .unwrap();

        let routes = ctrl.route_table();
        assert_eq!(
            routes.read().await.lookup(&Ipv4Addr::new(100, 86, 0, 1)),
            Some("vnet-visitor")
        );

        ctrl.unregister_visitor_route("vnet-visitor").await;
        assert_eq!(
            routes.read().await.lookup(&Ipv4Addr::new(100, 86, 0, 1)),
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
        assert!(
            ctrl.deliver_visitor_packet("vnet-visitor", packet.clone())
                .await
        );
        assert_eq!(rx.recv().await, Some(packet));
    }

    #[tokio::test]
    async fn deliver_to_unregistered_or_closed_visitor_fails() {
        let ctrl = ClientVnetController::new();
        assert!(!ctrl.deliver_visitor_packet("missing", vec![0x45]).await);

        let (tx, rx) = mpsc::channel(16);
        ctrl.register_visitor_route("gone", "10.0.0.1/32", tx)
            .await
            .unwrap();
        drop(rx);
        assert!(!ctrl.deliver_visitor_packet("gone", vec![0x45]).await);
        // The stale registration is removed after the closed channel is detected.
        assert!(!ctrl.deliver_visitor_packet("gone", vec![0x45]).await);
    }
}
