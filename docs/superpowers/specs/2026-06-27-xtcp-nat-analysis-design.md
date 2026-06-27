# XTCP NAT Analysis Engine — Design Spec

> Full Go frp v0.69.1 XTCP cross-compat: server-side NAT coordination with classification, analysis, and behavior recommendation.

## Problem

frp-rs XTCP server echoes visitor's own addresses back in `NatHoleResp`. Go frp server coordinates both sides: collects visitor AND provider STUN addresses, classifies NAT types, runs analysis to recommend hole-punch behavior, and sends each side the OTHER side's addresses as `candidate_addrs` with `detect_behavior` instructions.

**Root cause**: Server doesn't wait for provider's `NatHoleClient` (with STUN addresses) before responding to visitor. `NatHoleClient` struct is missing `mapped_addrs`, `assisted_addrs`, `protocol`, `sid` fields. `NatHoleResp` struct is missing `detect_behavior`. No NAT classification/analysis engine exists.

## Solution Overview

Implement Go frp's `pkg/nathole/` package in Rust as `frp-server/src/nathole/`. Enhanced message structs with missing fields. Provider does STUN discovery and reports its addresses to server. Server coordinates: waits for both sides' addresses, classifies NATs, queries analyzer, sends coordinated `NatHoleResp` to both sides.

## Architecture

```
frp-core/src/msg.rs              — NatHoleClient: +sid, +protocol, +mapped_addrs, +assisted_addrs
                                    NatHoleResp:  +detect_behavior (new NatHoleDetectBehavior)
                                    New types: NatHoleDetectBehavior, PortsRange

frp-server/src/nathole/          — New module (~800 lines)
├── mod.rs                       — Re-exports, NatHoleTimeout constant (10s)
├── controller.rs                — Controller (replaces NatHoleCoordinator)
├── classify.rs                  — NatFeature, ClassifyNATFeature, ClassifyFeatureCount
├── analysis.rs                  — Analyzer, RecommandBehavior, 5 mode tables, scoring
├── discovery.rs                 — STUN discovery (doSTUNRequest, Discover)

frp-server/src/service.rs        — handle_nat_hole_visitor: wait for provider's
                                    NatHoleClient, run analysis, send NatHoleResp to both

frp-server/src/control/mod.rs    — Provider-side: on NatHoleClient InternalMsg,
                                    do STUN discovery, reply with NatHoleClient

frp-server/src/nat_hole.rs       — REMOVED (replaced by nathole/controller.rs)
```

## Message Flow (Go frp Compat)

```
Visitor              frp-rs Server              Provider
  |                       |                         |
  |-- NatHoleVisitor ---->|                         |
  |  (mapped_addrs,       |                         |
  |   sign_key, protocol) |                         |
  |                       |-- InternalMsg --------->|
  |                       |  (NatHoleClient notify) |
  |                       |                         |-- STUN discover
  |                       |                         |   (own addresses)
  |                       |<-- NatHoleClient -------|
  |                       |  (mapped_addrs,         |
  |                       |   assisted_addrs, sid)  |
  |                       |                         |
  |                       | classify both NATs      |
  |                       | query analyzer          |
  |                       | build vResp, cResp      |
  |                       |                         |
  |<-- NatHoleResp -------|                         |
  |  (candidate_addrs =   |-- NatHoleResp --------->|
  |   provider's mapped)  |  (candidate_addrs =     |
  |  + detect_behavior    |   visitor's mapped)     |
  |                       |  + detect_behavior      |
  |== TCP simultaneous == open =====================|
  |                       |                         |
  |                       |<-- NatHoleReport -------|
  |                       |-- NatHoleReport ------->|
```

## Data Structures

### New: `NatHoleDetectBehavior`
```rust
pub struct NatHoleDetectBehavior {
    pub mode: i32,                                    // 0-4
    pub role: Option<String>,                         // "sender" | "receiver"
    pub ttl: i32,                                     // default 0
    pub send_delay_ms: i32,                           // delay before sending
    pub read_timeout_ms: i32,                         // timeout for read
    pub send_random_ports: i32,                       // random ports to send
    pub listen_random_ports: i32,                     // random ports to listen
    pub candidate_ports: Option<Vec<PortsRange>>,     // port ranges for candidates
}
```

### New: `PortsRange`
```rust
pub struct PortsRange {
    pub from: i32,
    pub to: i32,
}
```

### Modified: `NatHoleClient`
Add fields (all with `#[serde(default)]` for backward compat):
- `sid: Option<String>`
- `protocol: Option<String>`
- `mapped_addrs: Option<Vec<String>>`
- `assisted_addrs: Option<Vec<String>>`

### Modified: `NatHoleResp`
Add field:
- `detect_behavior: Option<NatHoleDetectBehavior>`

## Module Details

### `classify.rs`

Constants: `EasyNAT`, `HardNAT` (NatType), `BehaviorNoChange`, `BehaviorIPChanged`, `BehaviorPortChanged`, `BehaviorBothChanged` (Behavior).

`NatFeature` struct: `nat_type: String`, `behavior: String`, `ports_difference: i32`, `regular_ports_change: bool`, `public_network: bool`.

`ClassifyNATFeature(addresses: &[String], local_ips: &[String]) -> Result<NatFeature>`:
- Requires `addresses.len() > 1`
- Iterates addresses, splits IP:port, detects if IP is in local_ips
- Tracks IP/port differences from first entry
- Classifies: both changed → HardNAT/BothChanged, IP changed → HardNAT/IPChanged, port changed → HardNAT/PortChanged, neither → EasyNAT/NoChange
- If port changed and diff 1-5 inclusive → `regular_ports_change = true`

`ClassifyFeatureCount(features: &[NatFeature]) -> (i32, i32, i32)`:
- Returns (easy_count, hard_count, ports_changed_regular_count)

### `analysis.rs`

`RecommandBehavior` struct: `role: String`, `ttl: i32`, `send_delay_ms: i32`, `ports_range_number: i32`, `ports_random_number: i32`, `listen_random_ports: i32`.

5 behavior mode tables (mode0 through mode4). Each mode has a vector of `(RecommandBehavior, RecommandBehavior)` tuples — one per side.

`Analyzer` struct: `records: HashMap<String, MakeHoleRecords>`, `data_reserve_duration: Duration`.

`MakeHoleRecords`: per-key storage with `scores: Vec<BehaviorScore>`, `last_update_time: Instant`. Initialized from c_feature + v_feature classification counts.

`GetRecommandBehaviors(key, c_feature, v_feature) -> (mode, index, c_behavior, v_behavior)`:
1. Lookup or create records for key
2. `records.recommand()` → select max score, decrement by 1
3. `get_behavior_by_mode_and_index(mode, index)` → get behavior pair
4. Apply role swap rules per mode
5. Return

`ReportSuccess(key, mode, index)`: +2 to matching score, cap at 10.

`Clean()`: remove entries older than `data_reserve_duration`.

### `controller.rs`

`Controller` struct: `client_cfgs: RwLock<HashMap<String, ClientCfg>>`, `sessions: RwLock<HashMap<String, Session>>`, `analyzer: Analyzer`.

Replaces current `NatHoleCoordinator`. Methods: `ListenClient`, `CloseClient`, `HandleVisitor`, `HandleClient`, `HandleReport`, `GenNatHoleResponse`, `analysis`, `GenSid`, `CleanWorker`.

### `discovery.rs`

`Discover(stun_server: &str) -> Result<Vec<String>>`:
- Bind local UDP socket
- Send STUN Binding Request
- Parse XOR-MAPPED-ADDRESS / MAPPED-ADDRESS from response
- Send second request to ChangedAddress if present
- Return list of discovered external addresses

Uses `stun` crate (Rust equivalent of Go's `pion/stun`).

## Server Integration

### `service.rs` — `handle_nat_hole_visitor` changes

Current: sends NatHoleResp immediately (with visitor's own addresses), then waits for report.

New: after validation, sends NatHoleClient to provider via InternalMsg, **waits** for provider's response with `mapped_addrs`/`assisted_addrs`, then runs Controller.analysis(), sends NatHoleResp to visitor AND provider, waits for report.

### `control/mod.rs` — provider handler changes

On receiving `InternalMsg::NatHoleClient { ... }`:
1. Extract transaction_id
2. Run STUN discovery (if not disabled)
3. Construct `NatHoleClient` message with `sid`, `protocol`, `mapped_addrs`, `assisted_addrs`
4. Send back to server via control channel
5. Server's `HandleClient` picks it up, signals session's notify channel

### `Cargo.toml` changes

`frp-server/Cargo.toml`: add `stun = "0.1"` (or equivalent crate)
`frp-core/Cargo.toml`: no new deps (only struct changes)

## Testing

### Unit tests
- `classify.rs`: All NAT type combinations (EasyNAT, HardNAT with each behavior, RegularPortsChange detection, PublicNetwork detection)
- `analysis.rs`: Mode selection, score initialization per classification count, ReportSuccess scoring, role swap logic per mode, Clean expiration

### Integration tests
- Update `frp-server/tests/xtcp_hole_punch.rs`:
  - Provider sends NatHoleClient with mapped_addrs after receiving InternalMsg
  - Visitor receives NatHoleResp with provider's candidate_addrs + detect_behavior
  - Verify detect_behavior mode/role fields
  - Verify candidate_addrs contain provider's addresses, not visitor's

### Compat test
- `test_g2r_xtcp` in `scripts/compat-test.sh`:
  - Go frpc provider → Rust frps
  - Go frpc visitor → Rust frps
  - Expected: data round-trips through XTCP tunnel

## Files Changed

| File | Change |
|------|--------|
| `frp-core/src/msg.rs` | Add PortsRange, NatHoleDetectBehavior; extend NatHoleClient, NatHoleResp |
| `frp-server/src/nathole/mod.rs` | New: module re-exports |
| `frp-server/src/nathole/controller.rs` | New: Controller, Session, ClientCfg |
| `frp-server/src/nathole/classify.rs` | New: NatFeature, ClassifyNATFeature |
| `frp-server/src/nathole/analysis.rs` | New: Analyzer, RecommandBehavior, 5 mode tables |
| `frp-server/src/nathole/discovery.rs` | New: STUN discovery |
| `frp-server/src/service.rs` | Rewrite handle_nat_hole_visitor |
| `frp-server/src/control/mod.rs` | Provider NatHoleClient handler: STUN + reply |
| `frp-server/src/nat_hole.rs` | Remove (replaced by nathole/) |
| `frp-server/src/lib.rs` | Update mod declarations |
| `frp-server/Cargo.toml` | Add stun crate dep |
| `frp-core/Cargo.toml` | No changes (struct additions only) |

## Non-Goals

- Client-side XTCP retry/keepalive logic (already implemented)
- QUIC-based NAT detection (Go frp uses STUN, not QUIC, for address discovery)
- V2 protocol integration
- Client admin /api/metrics endpoint
