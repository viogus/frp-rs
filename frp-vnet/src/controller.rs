//! VNet controller — bidirectional TUN↔control_conn packet forwarding loop.
//! Uses frp-core protocol framing (V1/V2) with VnetPacket messages.
//!
//! TX: TUN read → route lookup → VnetPacket → write_msg on ctl_writer (control conn)
//! RX: tun_packet_rx → TUN write

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
