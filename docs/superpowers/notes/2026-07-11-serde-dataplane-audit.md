# serde Data-Plane Audit

**Date:** 2026-07-11
**Context:** CPU-efficiency sub-project, Task 3
**Conclusion:** No change (YAGNI). TCP/STCP/XTCP bridging carries raw bytes with zero per-chunk serde. The only per-packet serde is `UDPPacket` JSON, exercised exclusively by UDP proxies (not the TCP throughput baseline).

---

## 1. Enumerated serde_json call sites

97 matches across 14 files (excluding `#[cfg(test)]`). Classified below.

### 1.1 Wire protocol dispatch layer (central)

| File | Line(s) | Call | Classification |
|------|---------|------|----------------|
| `frp-core/src/protocol.rs` | 13 | `serde_json::to_vec(msg)` | **Dispatch point** — serializes ALL V1 messages. Control messages: per-event. `UDPPacket`: per-packet. |
| `frp-core/src/protocol.rs` | 490 | `serde_json::to_vec(msg)` | **Dispatch point** — serializes ALL V2 messages. Same dual nature. |
| `frp-core/src/protocol.rs` | 102-229 | `serde_json::from_slice(...)` (23 variants) | **Dispatch point** — deserializes ALL V1/V2 messages by type byte/ID. `UDPPacket` at line 162, `VnetPacket` at lines 203,209. |

### 1.2 Control-plane only (per-connection or per-event, never per-byte)

| File | Line(s) | What | Trigger frequency |
|------|---------|------|-------------------|
| `frp-core/src/v2_handshake.rs` | 342,352,422,427,455,465 | ClientHello/ServerHello JSON | Once per connection |
| `frp-server/src/ssh_gateway.rs` | 431,1220 | VirtualControl messages | Once per SSH virtual-control connection |
| `frp-server/src/dashboard.rs` | 567 | Dashboard metrics JSON | Per metric-scrape event |
| `frp-server/src/plugin/http.rs` | 74,96 | Plugin event/response JSON | Per HTTP proxy event |
| `frp-server/src/control/mod.rs` | 287 | Admin API response JSON | Per API request |
| `frp-core/src/auth.rs` | 250,307,537,600 | OIDC/OAuth config parsing | One-time at startup |
| `frp-core/src/config.rs` | 921,928,1013,1331 | Config deserialization | Startup / reload |
| `frp-server/src/store.rs` | 48,65 | Proxy config store | Startup / reload |
| `frp-client/src/control.rs` | 348,406,407 | Debug `to_string` for NewProxy/NewVisitorConn | Debug-level logging (non-production path) |
| `frp-client/src/visitor.rs` | 313,358 | Debug `to_string` for NewVisitorConn | Debug-level logging (non-production path) |
| `frp-client/src/admin.rs` | 115 | Admin API JSON response | Per API request |
| `frp-client/src/work_conn.rs` | 353,415 | `NatHoleSid` deserialization from work-conn preamble | Once per NAT-hole-punch work connection |

### 1.3 Data-plane (per-packet, forwarded bytes go through JSON)

| File | Line(s) | What | Trigger frequency |
|------|---------|------|-------------------|
| UDPPacket (V1) | `msg.rs:669` (dispatch), `protocol.rs:13` (serialize), `protocol.rs:162` (deserialize) | JSON `{c: base64(content), l: local_addr, r: remote_addr}` | Every UDP packet |
| UDPPacket (V2) | `protocol.rs:490` (serialize), `protocol.rs:504+` (deserialize) | Same JSON envelope, V2 framing | Every UDP packet |
| VnetPacket | `protocol.rs:203,209` (deserialize), `protocol.rs:13` (serialize) | Per-packet JSON for experimental vnet mode | Every vnet packet (experimental feature) |

### 1.4 Call sites in UDP proxy data-plane code

Server-side (`frp-server/src/control/bridge.rs`):
- Line 181-187: `read_msg_v1`/`read_msg_v2` → `FrpMessage::UDPPacket(up)` — deserializes every incoming UDP packet from JSON
- Line 224-234: `FrpMessage::UDPPacket(...)` → `write_msg_v1`/`write_msg_v2` — serializes every outgoing UDP packet to JSON

Client-side (`frp-client/src/work_conn.rs`):
- Line 509: `Ok(FrpMessage::UDPPacket(up))` — deserializes every incoming UDP packet from JSON
- Line 565: `FrpMessage::UDPPacket(...)` — serializes every outgoing UDP packet to JSON

---

## 2. bridge.rs: zero per-chunk serde

```
$ grep -c serde_json frp-core/src/bridge.rs
0
```

`bridge_plain` and `bridge_encrypted` in `frp-core/src/bridge.rs` carry raw bytes. The per-chunk operations are:

1. `user_r.read(buf)` — raw read into pool buffer
2. `compress_chunk(payload, use_compression)` — Snappy compress (optional)
3. `enc_work_w.write_all(processed)` / `work_w.write_all(processed)` — raw write
4. `enc_work_r.read(buf)` — raw read (decrypted)
5. `decompress_chunk(&mut decompressor, decrypted)` — Snappy decompress (optional)
6. `user_w.write_all(plaintext)` — raw write

No JSON, no base64, no serde, no heap-allocated string in the hot path (outside of optional Snappy compression which produces a `Vec<u8>` for compressed chunks). Bandwidth limiting is purely counter-based (`lim.consume(n).await`), no message framing.

This is true for all TCP, STCP, and XTCP proxy bridging — after the initial `StartWorkConn` setup message, the entire data plane is raw bytes.

---

## 3. Decision

**No change (YAGNI).**

- TCP/STCP/XTCP data plane carries raw bytes with zero per-chunk serde — already optimal.
- The only per-packet serde is `UDPPacket` JSON+base64, exercised exclusively by UDP proxies. This is outside the TCP throughput baseline and is a Go-frp wire-compatibility requirement.
- If UDP-proxy throughput enters scope, the target would be replacing per-packet JSON+base64 encoding for `UDPPacket` with a binary format (e.g., TLV header with raw content bytes). This would require a protocol version bump or a separate UDP work-conn mode, as it breaks Go frp wire compatibility.

Reference: CPU-efficiency spec (`.superpowers/sdd/`).

---

## 4. Additional note: VnetPacket

The experimental `VnetPacket` message type also uses per-packet JSON serialization (lines 203, 209 in `protocol.rs`). This is the vnet (virtual network/TUN) feature and is also outside the TCP throughput baseline. Same YAGNI reasoning applies.

---

## 5. Audit metadata

- **Grep command for call sites:** `grep -rn "serde_json::\(to_\|from_\)" frp-core/src frp-server/src frp-client/src | grep -v test`
- **Grep command for bridge.rs:** `grep -c serde_json frp-core/src/bridge.rs`
- **Grep command for UDPPacket:** `grep -n "UDPPacket\|to_string\|from_str" frp-core/src/msg.rs`
- **Files examined:** `frp-core/src/bridge.rs`, `frp-core/src/protocol.rs`, `frp-core/src/msg.rs`, `frp-core/src/v2_handshake.rs`, `frp-server/src/control/bridge.rs`, `frp-server/src/control/mod.rs`, `frp-server/src/ssh_gateway.rs`, `frp-server/src/dashboard.rs`, `frp-server/src/plugin/http.rs`, `frp-server/src/store.rs`, `frp-client/src/work_conn.rs`, `frp-client/src/control.rs`, `frp-client/src/visitor.rs`, `frp-client/src/admin.rs`, `frp-core/src/auth.rs`, `frp-core/src/config.rs`
