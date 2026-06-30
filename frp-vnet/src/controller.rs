//! VNet controller — bidirectional TUN↔work_conn packet forwarding loop.
//! Uses frp-core protocol framing (V1/V2) with VnetPacket messages.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

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

    /// Run the bidirectional packet loop.
    ///
    /// Takes ownership of the TUN device and the work connection halves.
    /// This function runs until either side closes or errors.
    pub async fn run(
        &self,
        mut tun: Box<dyn TunDevice>,
        mut work_conn_r: Box<dyn AsyncRead + Unpin + Send>,
        mut work_conn_w: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> anyhow::Result<()> {
        let mtu = tun.mtu() as usize;
        let mut tun_buf = vec![0u8; mtu];

        loop {
            tokio::select! {
                // TUN → work_conn: read IP packet, lookup route, send VnetPacket
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
                                let write_result = if self.v2 {
                                    frp_core::protocol::write_msg_v2(&mut work_conn_w, &msg).await
                                } else {
                                    frp_core::protocol::write_msg_v1(&mut work_conn_w, &msg).await
                                };
                                if let Err(e) = write_result {
                                    tracing::error!(%self.proxy_name, %e, "work_conn write error");
                                    break;
                                }
                            }
                            // If no route match, packet dropped (not destined for this vnet).
                        }
                        Err(e) => {
                            tracing::error!(%self.proxy_name, %e, "TUN read error");
                            break;
                        }
                    }
                }
                // work_conn → TUN: read VnetPacket, write raw IP packet to TUN.
                // Inline the read to avoid Sized issues with dyn trait objects.
                result = async {
                    if self.v2 {
                        frp_core::protocol::read_msg_v2(&mut work_conn_r).await
                    } else {
                        frp_core::protocol::read_msg_v1(&mut work_conn_r).await
                    }
                } => {
                    match result {
                        Ok(frp_core::msg::FrpMessage::VnetPacket(vpkt)) => {
                            match BASE64.decode(vpkt.data.as_bytes()) {
                                Ok(packet) => {
                                    if let Err(e) = tun.write_all(&packet).await {
                                        tracing::error!(%self.proxy_name, %e, "TUN write error");
                                        return Err(anyhow::anyhow!("TUN write error: {e}"));
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(%self.proxy_name, %e, "VnetPacket base64 decode error");
                                }
                            }
                        }
                        Ok(other) => {
                            let type_byte = other.v1_type_byte();
                            tracing::debug!(%self.proxy_name, %type_byte, "unexpected msg type 0x{type_byte:02x} on vnet work conn");
                        }
                        Err(e) => {
                            tracing::error!(%self.proxy_name, %e, "work_conn read error");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
