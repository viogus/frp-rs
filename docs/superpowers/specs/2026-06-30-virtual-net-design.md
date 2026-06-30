# Virtual Net: L3 VPN with TUN Device Routing

**Issue:** [#48](https://github.com/viogus/frp-rs/issues/48)
**Date:** 2026-06-30
**Status:** Design approved, awaiting implementation plan

## Overview

Add a Layer 3 VPN feature (`type = "vnet"`) to frp-rs. Each frpc client creates a TUN virtual network interface with a configured IP address. IP packets destined for other virtual network subnets are routed through frp tunnels. The server acts as a packet router between vnet clients. This enables full IP connectivity between machines connected via frp — not just port-level proxying.

**Go frp reference:** `pkg/vnet/` (~3000 lines) — TUN device creation (water/wireguard-go tun library), client router (destination-based CIDR), server router (source-based IP matching), IPv4+IPv6 support.

**Current state:** `virtual_net: String` field exists in `ProxyConfig`, `NewProxy`, and `ProxyInfo` for STCP/XTCP isolation only. Zero TUN device implementation.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Crate structure | New `frp-vnet` crate | Isolate TUN platform deps from frp-core; match Go frp `pkg/vnet/` pattern |
| Proxy type | New `type = "vnet"` | Clean separation from existing proxy types |
| Platform support | Linux + macOS + Windows | Full cross-platform from start |
| Routing model | Client-advertised subnets | Each client advertises subnet it owns; server builds routing table |
| TUN library | None — write directly | ~150 lines/platform; no dependency policy violation |
| Feature gate | `vnet` feature at all crate levels | Full includes it; tiny/micro exclude it |
| IPv6 | Not in initial implementation | YAGNI; IPv4 only for Phase 1 |

## Architecture

### New Crate: `frp-vnet`

```
frp-vnet/
├── Cargo.toml          # deps: frp-core, tokio, libc, socket2, optional windows-sys
├── src/
│   ├── lib.rs          # module declarations + re-exports
│   ├── tun.rs          # TunDevice trait + platform dispatch
│   ├── tun_linux.rs    # /dev/net/tun via ioctl TUNSETIFF
│   ├── tun_macos.rs    # utun via socket SYSPROTO_CONTROL
│   ├── tun_windows.rs  # Wintun via windows-sys
│   ├── router.rs       # CIDR routing table, client/server route management
│   ├── controller.rs   # TUN + router coordination loop
│   └── msg.rs          # VNet-specific message types (RouteAdvertise, IPPacket)
└── tests/
    └── vnet_tests.rs   # Unit + loopback integration tests
```

### Feature Flag Chain

```
Workspace Cargo.toml:
  [workspace.dependencies]
  frp-vnet = { path = "frp-vnet" }

frp-core/Cargo.toml:
  [features]
  default = [..., "vnet"]           # vnet ON by default (full builds)
  vnet = []                         # marker feature only

frp-server/Cargo.toml:
  [features]
  default = [..., "vnet"]
  vnet = ["frp-core/vnet", "dep:frp-vnet"]

frp-client/Cargo.toml:
  [features]
  default = [..., "vnet"]
  vnet = ["frp-core/vnet", "dep:frp-vnet"]

frps / frpc:
  full = includes vnet (via default)
  tiny = excludes vnet (explicit feature list, no vnet)
  micro = excludes vnet
```

### Binary Size Impact

| Tier | frps | frpc | Delta |
|------|------|------|-------|
| full | ~4.6→5.0 MB | ~3.4→3.8 MB | +~400KB |
| tiny | ~2.8 MB | ~2.6 MB | 0 (no vnet) |
| micro | ~1.5 MB | ~1.9 MB | 0 (no vnet) |

## Component Design

### 1. TUN Device Abstraction

```rust
/// Cross-platform TUN device — reads/writes raw IP packets (L3 only, no Ethernet).
pub trait TunDevice: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn configure(&self, addr: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Result<()>;
    fn name(&self) -> &str;
    fn mtu(&self) -> u16;
}
```

**Linux (`/dev/net/tun`):**
- Open `/dev/net/tun`, ioctl `TUNSETIFF` with `IFF_TUN | IFF_NO_PI`
- Configure: ioctl `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCSIFMTU` via socket
- Async: `fcntl O_NONBLOCK` + tokio fd registration
- No packet info header (`IFF_NO_PI`)

**macOS (`utun`):**
- `socket(SYSPROTO_CONTROL)` → `getsockopt(UTUN_OPT_IFNAME)` for interface name
- Configure: `AF_SYSTEM` socket with `SIOCSIFADDR` etc.
- 4-byte AF header on read/write: strip `AF_INET=2` on read, prepend on write
- Async: same non-blocking + tokio fd approach

**Windows (Wintun):**
- `wintun.dll`: `WintunCreateAdapter` → `WintunOpenAdapter` → `WintunStartSession`
- Configure: `WintunSetAdapterAddress` (assigns IP + netmask)
- Read/Write: `WintunAllocateSendPacket` / `WintunReceivePacket` with pooled buffers
- Async: blocking thread + channel for read; write is non-blocking at packet rate
- `wintun.dll` bundled with binary or documented as system requirement

### 2. Message Types

New V1 type bytes and V2 type IDs added to `frp-core/src/msg.rs` (feature-gated):

```rust
// V1 type bytes
TYPE_VNET_ROUTE_ADVERTISE = 0x40
TYPE_VNET_PACKET         = 0x41
TYPE_VNET_ROUTE_REMOVE   = 0x42

// V2 type IDs
V2_TYPE_VNET_ROUTE_ADVERTISE = 42
V2_TYPE_VNET_PACKET           = 43
```

**`VnetRouteAdvertise`:**
- `proxy_name: String` — which proxy this route belongs to
- `subnet: String` — CIDR subnet, e.g. `"10.0.0.0/24"`
- `virtual_net: Option<String>` — virtual network name for isolation
- Sent by client on control connection after TUN device is configured

**`VnetPacket`:**
- `proxy_name: String` — target proxy name (routing key for server)
- `data: String` — base64-encoded raw IP packet
- Bidirectional: client→server and server→client
- Carried on work connections

**`VnetRouteRemove`:**
- `proxy_name: String`
- `virtual_net: Option<String>`
- Sent by client when vnet proxy shuts down

### 3. Client-Side Controller (`VnetController`)

Spawned per vnet proxy inside `frp-client`. Reuses existing work connection pool.

The controller maintains a local routing table:
```
subnet_to_proxy: HashMap<String, String>  // "10.0.1.0/24" → "vnet-datacenter"
```
Built from route advertisements forwarded by the server.

```
Startup:
  1. Open TUN device, assign IP/netmask/MTU
  2. Send VnetRouteAdvertise on control connection
  3. On receiving peer route advertisements: update subnet_to_proxy,
     add OS routes via `ip route`/`route add`
  4. Spawn read loops

Main loop (tokio::select!):
  A. TUN → work_conn:
     Read raw IP packet from TUN
     → Classify IPv4 header (extract dst IP)
     → If dst is local subnet → write back to TUN (local delivery)
     → Else → lookup dst IP in subnet_to_proxy to find target proxy_name
     → Wrap in VnetPacket { proxy_name, data }, write to work connection

  B. work_conn → TUN:
     Read VnetPacket from work connection
     → Base64-decode data
     → Write raw IP packet to TUN device

Shutdown:
  1. Send VnetRouteRemove
  2. Remove OS routes
  3. Close TUN device
```

### 4. Server-Side Router

Integrated into `frp-server/src/control/mod.rs` control message handling.

```rust
// AppState additions (behind #[cfg(feature = "vnet")]):
vnet_routes: RwLock<HashMap<(String, String), (String, String)>>
// key: (virtual_net, subnet) → value: (run_id, proxy_name)
```

**Message handling:**
- `VnetRouteAdvertise` → Insert into `vnet_routes` (scoped by `virtual_net`). Forward advertisement to other vnet clients on same virtual net.
- `VnetPacket` → Look up `proxy_name` in `ProxyManager`, find work connection for that client, forward packet. If destination is local (same run_id), deliver directly.
- `VnetRouteRemove` → Remove from `vnet_routes`. Broadcast removal to peers.

**Subnet conflict detection:** If two clients advertise overlapping subnets on the same virtual net, reject the second registration with an error in `NewProxyResp`.

### 5. Configuration

```toml
# ProxyConfig additions (frp-core/src/config.rs)
[[proxies]]
name = "vnet-office"
type = "vnet"
advertise_subnet = "10.0.0.0/24"   # Subnet this client OWNS
vnet_ip = "10.0.0.1"               # TUN device IP (this client)
vnet_netmask = "255.255.255.0"     # TUN netmask (default: 255.255.255.0)
vnet_mtu = 1420                    # TUN MTU (default: 1420)
virtual_net = "corp-net"           # Virtual network name for isolation
```

**New fields on `ProxyConfig`:**
| Field | Type | Default | Alias |
|-------|------|---------|-------|
| `advertise_subnet` | `String` | `""` | `advertiseSubnet` |
| `vnet_ip` | `String` | `""` | `vnetIp` |
| `vnet_netmask` | `String` | `"255.255.255.0"` | `vnetNetmask` |
| `vnet_mtu` | `u16` | `1420` | `vnetMtu` |

**CLI single-proxy mode:**
```bash
frpc vnet --server-addr 1.2.3.4 --server-port 7000 --token "..." \
  --proxy-name "vnet-office" --advertise-subnet "10.0.0.0/24" \
  --vnet-ip "10.0.0.1" --virtual-net "corp-net"
```

### 6. Route Injection

When a client receives route advertisements from peers, it adds OS routes:
- Linux: `ip route add <subnet> dev <tun_name>`
- macOS: `route add -net <subnet> -interface <tun_name>`
- Windows: `route add <subnet> mask <mask> <gateway>`

On shutdown: corresponding delete commands.
Route injection failure is non-fatal (log warning, continue).

### 7. Work Connection Integration

VNet reuses the existing work connection pool. When server sends `StartWorkConn` with `proxy_type = "vnet"`:
- Client spawns `VnetController` instead of connecting to a local TCP port
- Work connection becomes a persistent IP packet tunnel
- `VnetController` owns read/write halves of the work connection

## Error Handling

| Scenario | Behavior |
|----------|----------|
| TUN open fails (no root/CAP_NET_ADMIN) | Error logged, proxy marked as failed in admin API |
| Subnet conflict | Server rejects registration with error in `NewProxyResp` |
| Work connection drops | VnetController exits, routes removed, server cleans up routing table |
| Malformed IP packet | Log warning, drop packet, continue |
| Route injection fails | Log warning, continue (vnet works but OS routing incomplete) |
| `virtual_net` mismatch | Routes scoped by virtual_net; different virtual nets have isolated routing tables |

## Testing Strategy

| Layer | What | Requirements |
|-------|------|-------------|
| Unit — TUN | CIDR matching, route table insert/lookup/remove, VnetPacket serde | None |
| Unit — Router | Route advertise/remove, subnet conflict detection, longest prefix match | None |
| Integration — loopback | Full packet flow using tokio duplex as fake TUN | None (runs everywhere) |
| Integration — real TUN | Two frpc + one frps, ping between virtual IPs | Root/CAP_NET_ADMIN, Linux only, skipped on CI |
| Compat | None — vnet is beyond Go frp | N/A |

## Implementation Phases

| Phase | Files | Est. Lines |
|-------|-------|-----------|
| 1. TUN device | `frp-vnet/src/tun*.rs` (4 files) | ~400 |
| 2. Messages + config | `msg.rs`, `config.rs`, `frp-vnet/src/msg.rs` | ~200 |
| 3. Router + controller | `frp-vnet/src/router.rs`, `controller.rs` | ~400 |
| 4. Server integration | `frp-server/src/control/` additions, `state.rs` | ~300 |
| 5. Client integration | `frp-client/src/service.rs`, `work_conn.rs` additions | ~300 |
| 6. Feature flags + Cargo | 6 `Cargo.toml` files | ~50 |
| 7. Tests | `frp-vnet/tests/`, server integration tests | ~500 |
| **Total** | **~20 files** | **~2150** |

## Out of Scope (YAGNI)

- IPv6 support (IPv4 only)
- DHCP-like dynamic IP assignment (static config only)
- NAT/masquerading between virtual networks
- Bandwidth limiting on vnet tunnels
- Custom encryption on vnet (relies on existing control/work connection encryption)
- DNS resolution for virtual net hostnames
- TUN device hot-reload (requires full proxy restart for config changes)
