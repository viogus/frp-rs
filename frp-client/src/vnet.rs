//! vnet (virtual net) client support — TUN devices, route advertisement, OS routes.
//!
//! TUN-backed vnet proxies get an OS-level TUN device bridged into the frp
//! virtual net, and `virtual_net` visitor plugins advertise their destination
//! IP as a host route. This module owns the TUN lifecycle (open/register/
//! controller/remove), route advertisement/removal on the control connection,
//! and OS route injection, plus the shared type aliases for the per-proxy
//! TUN maps stored on `Service`.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, watch, Mutex};
use tracing::{info, warn};

use crate::service::ControlWriter;
use frp_core::msg::{self, FrpMessage};
use frp_core::transport::IoStream;

use crate::service::{Service, VISITOR_PLUGIN_VIRTUAL_NET};

/// (subnet, tun_name, virtual_net) of a peer vnet route.
pub(crate) type VnetPeerRoute = (String, String, String);

/// Shared TUN devices for vnet proxies, keyed by proxy name. Work connection
/// tasks take ownership of the TUN device via `Option::take()`.
pub(crate) type VnetTunMap = Arc<Mutex<HashMap<String, Option<Box<dyn frp_vnet::tun::TunDevice>>>>>;

/// Per-proxy TX channels for forwarding received VnetPackets to TUN devices.
pub(crate) type VnetTunTxMap = Arc<std::sync::Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>;

/// Per-proxy cancellation senders for running vnet controllers.
pub(crate) type VnetTunCancelMap = Arc<Mutex<HashMap<String, watch::Sender<bool>>>>;

/// Build a VnetRouteAdvertise for a `virtual_net` visitor, advertising its
/// destinationIP as a host route through the frp vnet routing path.
///
pub(crate) fn virtual_net_visitor_route_adv(
    v: &frp_core::config::VisitorConfig,
) -> Option<msg::VnetRouteAdvertise> {
    if v.plugin.as_ref()?.plugin_type != VISITOR_PLUGIN_VIRTUAL_NET {
        return None;
    }
    let ip: std::net::IpAddr = v.plugin.as_ref()?.destination_ip.parse().ok()?;
    Some(msg::VnetRouteAdvertise {
        proxy_name: v.name.clone(),
        subnet: frp_vnet::router::host_route_cidr(&ip),
        virtual_net: None,
    })
}

/// Advertise a vnet visitor's host route on the control connection after its
/// registration succeeds. Shared by both visitor-registration response paths
/// (NewVisitorConnResp and the Go frps ReqWorkConn ack) in the pipelined
/// registration read loop.
pub(crate) async fn advertise_vnet_visitor_route(
    control_stream: &mut IoStream,
    v2: bool,
    v: &frp_core::config::VisitorConfig,
) {
    if let Some(adv) = virtual_net_visitor_route_adv(v) {
        let send_result = if v2 {
            control_stream
                .write_v2_frame(&FrpMessage::VnetRouteAdvertise(adv))
                .await
        } else {
            control_stream
                .write_v1_frame(&FrpMessage::VnetRouteAdvertise(adv))
                .await
        };
        if let Err(e) = send_result {
            warn!(visitor_name = %v.name, error = %e, "failed to send vnet route advertisement for visitor '{}'", v.name);
        } else {
            info!(visitor_name = %v.name, "vnet route advertised for visitor '{}'", v.name);
        }
    }
}

impl Service {
    /// Open and register the TUN device for a vnet proxy, if configured.
    pub(crate) async fn open_vnet_tun_for_proxy(
        &self,
        proxy: &frp_core::config::ProxyConfig,
        cfg: &frp_core::config::ClientConfig,
    ) -> anyhow::Result<()> {
        let Some(params) = vnet_tun_params(proxy, &cfg.virtual_net.address) else {
            return Ok(());
        };
        let tun = frp_vnet::tun::open_tun("").await?;
        register_vnet_tun(
            &self.vnet_tuns,
            &self.vnet_tun_names,
            &proxy.name,
            params,
            tun,
        )
        .await?;
        if let Some(cidr) = vnet_tun_cidr(proxy, &cfg.virtual_net.address) {
            self.vnet_tun_subnets
                .lock()
                .await
                .insert(proxy.name.clone(), cidr);
        }
        Ok(())
    }
}

/// Compute the set of virtual nets this client participates in.
///
/// Every vnet/TUN proxy contributes its `virtual_net` (empty string for the
/// default net), and every `virtual_net` visitor joins the default net. Used
/// to filter inbound `VnetRouteAdvertise`: a route for a virtual net we are
/// not part of is ignored (design spec: different virtual nets have isolated
/// routing tables).
pub(crate) fn local_vnet_set(
    cfg: &frp_core::config::ClientConfig,
) -> std::collections::HashSet<String> {
    let mut vnets = std::collections::HashSet::new();
    for p in &cfg.proxies {
        if vnet_tun_params(p, &cfg.virtual_net.address).is_some() {
            vnets.insert(if p.virtual_net.is_empty() {
                String::new()
            } else {
                p.virtual_net.clone()
            });
        }
    }
    for v in &cfg.visitors {
        if v.plugin
            .as_ref()
            .is_some_and(|pl| pl.plugin_type == VISITOR_PLUGIN_VIRTUAL_NET)
        {
            vnets.insert(String::new());
        }
    }
    vnets
}

/// Resolve the local TUN address, netmask, and MTU for a vnet proxy.
pub(crate) fn vnet_tun_params(
    p: &frp_core::config::ProxyConfig,
    global_address: &str,
) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr, u16)> {
    let (ip, netmask, mtu) = if p.proxy_type == "vnet" && !p.vnet_ip.is_empty() {
        (p.vnet_ip.clone(), p.vnet_netmask.clone(), p.vnet_mtu)
    } else if p
        .plugin
        .as_ref()
        .is_some_and(|pl| pl.plugin_type == "virtual_net")
        && !global_address.is_empty()
    {
        (
            global_address.to_string(),
            "255.255.255.0".to_string(),
            1420,
        )
    } else {
        return None;
    };
    Some((ip.parse().ok()?, netmask.parse().ok()?, mtu))
}

/// Snapshot the vnet-relevant proxy fields that `reload::config_snapshot`
/// currently omits, so TUN reloads also react to subnet/IP/mask changes.
pub(crate) fn vnet_proxy_snapshot(p: &frp_core::config::ProxyConfig) -> String {
    let plugin_type = p
        .plugin
        .as_ref()
        .map(|pl| pl.plugin_type.as_str())
        .unwrap_or("");
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        p.proxy_type,
        p.virtual_net,
        p.advertise_subnet,
        p.vnet_ip,
        p.vnet_netmask,
        p.vnet_mtu,
        plugin_type
    )
}

/// Compute the subnet CIDR owned by a local TUN proxy.
pub(crate) fn vnet_tun_cidr(
    p: &frp_core::config::ProxyConfig,
    global_address: &str,
) -> Option<String> {
    let (ip, netmask, _) = vnet_tun_params(p, global_address)?;
    let prefix = u32::from(netmask).count_ones();
    if prefix > 32 {
        return None;
    }
    let network = u32::from(ip) & u32::from(netmask);
    Some(format!("{}/{}", std::net::Ipv4Addr::from(network), prefix))
}

/// Store an opened TUN device in the shared proxy maps.
pub(crate) async fn register_vnet_tun(
    vnet_tuns: &VnetTunMap,
    vnet_tun_names: &Arc<Mutex<HashMap<String, String>>>,
    proxy_name: &str,
    params: (std::net::Ipv4Addr, std::net::Ipv4Addr, u16),
    tun: Box<dyn frp_vnet::tun::TunDevice>,
) -> anyhow::Result<()> {
    let tun_name = tun.name().to_string();
    if let Err(e) = tun.configure(params.0, params.1, params.2) {
        tracing::warn!(proxy_name = %proxy_name, error = %e, "TUN configure failed");
    } else {
        tracing::info!(proxy_name = %proxy_name, name = %tun_name, "TUN device ready");
    }
    vnet_tun_names
        .lock()
        .await
        .insert(proxy_name.to_string(), tun_name);
    vnet_tuns
        .lock()
        .await
        .insert(proxy_name.to_string(), Some(tun));
    Ok(())
}

/// Spawn the controller for a registered TUN and publish its TX channel.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_vnet_tun_controller(
    vnet_tuns: &VnetTunMap,
    vnet_tun_tx: &VnetTunTxMap,
    vnet_tun_cancels: &VnetTunCancelMap,
    vnet_controller: &Arc<frp_vnet::controller::ClientVnetController>,
    proxy_name: &str,
    vnet: &str,
    writer: &Arc<ControlWriter>,
    v2: bool,
) -> Option<()> {
    let tun = {
        let mut tuns = vnet_tuns.lock().await;
        tuns.get_mut(proxy_name)?.take()
    }?;
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);
    vnet_tun_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(proxy_name.to_string(), tun_tx);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    vnet_tun_cancels
        .lock()
        .await
        .insert(proxy_name.to_string(), cancel_tx);
    let ctl_writer = writer.clone();
    let client_controller = vnet_controller.clone();
    let pn = proxy_name.to_string();
    let vn = vnet.to_string();
    tokio::spawn(async move {
        let ctrl = frp_vnet::controller::VnetController::new(pn.clone(), client_controller, v2, vn);
        tokio::select! {
            result = ctrl.run(tun, ctl_writer, tun_rx) => {
                if let Err(e) = result {
                    tracing::error!(proxy_name = %pn, error = %e, "vnet controller exited with error");
                }
            }
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    tracing::info!(proxy_name = %pn, "vnet controller cancelled");
                }
            }
        }
        tracing::info!(proxy_name = %pn, "vnet controller stopped");
    });
    Some(())
}

/// Send a VnetRouteAdvertise for a `type = vnet` proxy that owns a subnet.
pub(crate) async fn send_vnet_route_advertise(
    writer: &Arc<ControlWriter>,
    v2: bool,
    p: &frp_core::config::ProxyConfig,
) {
    if p.proxy_type != "vnet" || p.advertise_subnet.is_empty() {
        return;
    }
    let adv = msg::VnetRouteAdvertise {
        proxy_name: p.name.clone(),
        subnet: p.advertise_subnet.clone(),
        virtual_net: if p.virtual_net.is_empty() {
            None
        } else {
            Some(p.virtual_net.clone())
        },
    };
    let msg = FrpMessage::VnetRouteAdvertise(adv);
    let result = writer.send(msg, v2);
    if let Err(e) = result {
        tracing::warn!(proxy_name = %p.name, error = %e, "failed to send VnetRouteAdvertise");
    } else {
        tracing::info!(proxy_name = %p.name, subnet = %p.advertise_subnet, "VnetRouteAdvertise sent");
    }
}

/// Drop a TUN proxy's maps, cancel its controller, remove its OS/routing
/// table entries, and notify the server so peer clients invalidate their
/// routes for this proxy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn remove_vnet_tun(
    vnet_tuns: &VnetTunMap,
    vnet_tun_tx: &VnetTunTxMap,
    vnet_tun_cancels: &VnetTunCancelMap,
    vnet_tun_names: &Arc<Mutex<HashMap<String, String>>>,
    vnet_tun_subnets: &Arc<Mutex<HashMap<String, String>>>,
    route_table: &Arc<tokio::sync::RwLock<frp_vnet::router::RouteTable>>,
    vnet_peer_routes: &Arc<Mutex<HashMap<String, VnetPeerRoute>>>,
    writer: &Arc<ControlWriter>,
    v2: bool,
    proxy_name: &str,
    vnet: &str,
) {
    if let Some(cancel) = vnet_tun_cancels.lock().await.remove(proxy_name) {
        let _ = cancel.send(true);
    }
    vnet_tuns.lock().await.remove(proxy_name);
    vnet_tun_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(proxy_name);
    let tun_name = vnet_tun_names.lock().await.remove(proxy_name);
    // Remove the OS route for the local TUN subnet (the kernel also cleans it
    // up on TUN teardown, but explicit removal keeps add/remove symmetric).
    if let Some(cidr) = vnet_tun_subnets.lock().await.remove(proxy_name) {
        if let Some(ref tun_name) = tun_name {
            remove_os_route(&cidr, tun_name);
        }
    }
    // Defensively drop any peer route recorded under this proxy name so a
    // stale OS route never survives the proxy's removal.
    if let Some((subnet, peer_tun_name, _)) = vnet_peer_routes.lock().await.remove(proxy_name) {
        remove_os_route(&subnet, &peer_tun_name);
    }
    route_table.write().await.remove(vnet, proxy_name);
    // Notify the server so peer clients invalidate their routes for this proxy.
    let rem = msg::VnetRouteRemove {
        proxy_name: proxy_name.to_string(),
        virtual_net: if vnet.is_empty() {
            None
        } else {
            Some(vnet.to_string())
        },
    };
    let msg = FrpMessage::VnetRouteRemove(rem);
    if let Err(e) = writer.send(msg, v2) {
        tracing::warn!(proxy_name, error = %e, "failed to send VnetRouteRemove for '{}'", proxy_name);
    } else {
        tracing::info!(proxy_name, "VnetRouteRemove sent for '{}'", proxy_name);
    }
}

/// Validate a CIDR/IP string before passing it to `ip route`/`route`.
/// The subnet comes from a peer's VnetRouteAdvertise broadcast, so it must
/// be a well-formed IP prefix — not an option-injection vector (`-...` is
/// parsed as a global option by `ip`) or garbage that pollutes the table.
pub(crate) fn valid_cidr(subnet: &str) -> bool {
    if subnet.is_empty() || subnet.len() > 64 || subnet.starts_with('-') {
        return false;
    }
    match subnet.split_once('/') {
        Some((ip, prefix)) => {
            let Ok(len) = prefix.parse::<u8>() else {
                return false;
            };
            let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() else {
                return false;
            };
            // Reject out-of-family prefixes (10.0.0.0/99) — invalid CIDR.
            let max_prefix = if parsed_ip.is_ipv4() { 32 } else { 128 };
            if len > max_prefix {
                return false;
            }
            // Reject the default-route hijack prefix: `0.0.0.0/0` / `::/0`
            // (`ip route add ... dev tun`) would redirect the ENTIRE
            // outbound traffic into the TUN. Also reject ANY `/1` — every
            // /1 covers the default-route half once the route table masks
            // the base, so non-canonical spellings (`10.0.0.0/1`,
            // zero-padded IPv6) are just as much a hijack (round-17 review
            // MEDIUM). A /2+/3+ is still a wide route but not a full
            // default-route hijack — the server independently refuses these
            // (nathole.rs `is_route_hijack_prefix`); this is defense-in-depth.
            let hijack = len <= 1;
            !hijack
        }
        None => subnet.parse::<std::net::IpAddr>().is_ok(),
    }
}

/// Inject an OS-level route directing traffic for `subnet` through the
/// given TUN interface. This makes the kernel send matching packets to
/// the TUN device instead of the physical NIC / default gateway.
pub(crate) fn add_os_route(subnet: &str, tun_name: &str) {
    if !valid_cidr(subnet) {
        tracing::warn!("refusing invalid subnet for OS route: {subnet}");
        return;
    }
    if tun_name.is_empty() || tun_name.chars().any(|c| c.is_whitespace() || c == '/') {
        tracing::warn!("refusing invalid TUN name for OS route: {tun_name:?}");
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["route", "add", subnet, "dev", tun_name])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let (net, _mask) = match subnet.split_once('/') {
            Some(s) => s,
            None => {
                tracing::warn!("invalid subnet format for OS route: {subnet}");
                return;
            }
        };
        let _ = std::process::Command::new("route")
            .args(["add", "-net", net, "-interface", tun_name])
            .output();
    }
}

/// Remove an OS-level route previously injected by [`add_os_route`].
/// Best-effort: a missing route (e.g. after interface reset) is not fatal.
pub(crate) fn remove_os_route(subnet: &str, tun_name: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["route", "del", subnet, "dev", tun_name])
            .output();
    }
    #[cfg(target_os = "macos")]
    {
        let (net, _mask) = match subnet.split_once('/') {
            Some(s) => s,
            None => {
                tracing::warn!("invalid subnet format for OS route: {subnet}");
                return;
            }
        };
        let _ = std::process::Command::new("route")
            .args(["delete", "-net", net, "-interface", tun_name])
            .output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cidr_rejects_default_route_hijack() {
        // Route-hijack MED: `0.0.0.0/0` and `::/0` would send the ENTIRE
        // outbound traffic into the TUN via `ip route add ... dev tun`.
        assert!(!valid_cidr("0.0.0.0/0"));
        assert!(!valid_cidr("::/0"));
        // The /1 splits that together cover a whole family must also be
        // refused — including non-canonical bases, which are the same
        // network once the route table masks the base (round-17 review
        // MEDIUM).
        assert!(!valid_cidr("0.0.0.0/1"));
        assert!(!valid_cidr("128.0.0.0/1"));
        assert!(!valid_cidr("::/1"));
        assert!(!valid_cidr("8000::/1"));
        assert!(!valid_cidr("10.0.0.0/1"));
        assert!(!valid_cidr("200.0.0.0/1"));
        assert!(!valid_cidr("8000:0000:0000:0000:0000:0000:0000:0000/1"));
    }

    #[test]
    fn valid_cidr_accepts_real_networks() {
        // Legitimate vnet shapes are still accepted.
        assert!(valid_cidr("10.0.0.0/24"));
        assert!(valid_cidr("192.168.1.0/24"));
        assert!(valid_cidr("10.0.0.5/32"));
        assert!(valid_cidr("fd00::/8"));
        assert!(valid_cidr("fd00::1/128"));
        assert!(valid_cidr("100.64.0.0/10"));
        // Garbage / malformed still refused (unchanged behavior).
        assert!(!valid_cidr("not-a-cidr"));
        assert!(!valid_cidr("10.0.0.0/99"));
        assert!(!valid_cidr(""));
        assert!(!valid_cidr("-x"));
    }
}
