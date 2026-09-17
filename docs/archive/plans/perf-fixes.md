# Performance Fixes Plan

Branch: `worktree-perf-fixes`
Base: deadlock fix already applied (registry.rs lock ordering).

## Global Constraints

- All changes must pass `cargo test --workspace --all-features`
- All changes must pass `cargo clippy --workspace --all-targets --all-features -D warnings`
- All changes must pass `cargo fmt --all -- --check`
- No new dependencies
- Keep Go frp wire compatibility intact

## Tasks

### Task 1: KCP socket — pre-allocate tick Vecs + O(1) FEC lookup

Files: `frp-core/src/kcp/socket.rs`, `frp-core/src/kcp/session.rs`

1. `socket.rs:147` — `to_remove: Vec::new()` every 10ms tick. Pre-allocate once, `.clear()` each tick.
2. `socket.rs:196` — `expired: Vec::new()` every 10ms tick. Same pattern.
3. `socket.rs:314-315` — `.keys().find(|(_,a)| *a==src)` O(n) scan per FEC miss. Maintain reverse `HashMap<SocketAddr, u32>` index for O(1).
4. `session.rs:182,263` — `packets: Vec::new()` per update()/force_flush(). Reuse via `.clear()`.
5. `session.rs:213-214` — `shard_refs: Vec<&[u8]>` per parity batch. Reuse scratch Vec.

### Task 2: Protocol — reduce Vec allocs in V1/V2 frame write

Files: `frp-core/src/protocol.rs`

1. `write_v1_frame` (line ~25-28): serialize JSON to Vec, then alloc second Vec with header+payload. Use a single Vec: serialize JSON, then insert 9-byte header at front (or use writev-style two-part write).
2. `write_msg_v2` (line ~433-438): three Vec allocs (serde_json::to_vec + write_v2_frame_raw capacity + inner with_capacity). Combine: pre-allocate buffer pool slot, serialize directly.
3. `read_v2_frame_raw` (line ~413): no buffer pool usage. Use pool for payloads up to BUFFER_SIZE, matching V1 path.

### Task 3: AEAD — eliminate plaintext.to_vec() per encrypted frame

Files: `frp-core/src/crypto.rs`

1. `crypto.rs:579` — first frame write: `plaintext.to_vec()` alloc + memcpy before `encrypt()`. Write plaintext directly into `pending` Vec, hand to encrypt which extends in-place with tag.
2. `crypto.rs:616` — subsequent frames: same pattern. Same fix.

### Task 4: Client service quick wins

Files: `frp-client/src/service.rs`

1. `service.rs:1113,1306,1554` — `std::sync::Mutex` on `health_cancels`/`health_proxy_configs` in async paths. Switch to `tokio::sync::Mutex`.
2. `service.rs:508` — `self.cfg.proxies.clone()` deep-clones all proxy configs on every reconnect. Wrap `proxies` in `Arc<Vec<ProxyConfig>>` so read path borrows.
3. `service.rs:1129` — NAT hole punch (`xtcp_p2p_connect_yamux` with 5s timeout) runs inline in control `select!` loop, starving ping/health/reload. Spawn into detached task, signal result via oneshot.

### Task 5: V2 handshake + STUN + config — string alloc cleanup

Files: `frp-core/src/v2_handshake.rs`, `frp-core/src/stun.rs`, `frp-core/src/config.rs`, `frp-server/src/control/mod.rs`, `frp-server/src/nathole/controller.rs`

1. `v2_handshake.rs:213` — `transport.to_string()` per handshake. Use `Cow<'static, str>`.
2. `v2_handshake.rs:260,273,288` — `"json".to_string()` (3×), `"true".to_string()`. Use `&'static str` constants.
3. `stun.rs:42` — redundant `addr_str.to_string()`, `lookup_host` takes `&str`. Remove.
4. `config.rs:233` — `to_uppercase()` alloc. Use `eq_ignore_ascii_case`.
5. `mod.rs:168` — `Duration::from_secs(...)` recreated every loop iter. Cache outside `select!`.
6. `controller.rs:511` — `seen.insert(a.clone())`. Use `HashSet<&str>` with `a.as_str()`.

### Task 6: KCP session FEC dedup + vnet router cache

Files: `frp-core/src/kcp/session.rs`, `frp-vnet/src/router.rs`

1. `session.rs:182-230` vs `session.rs:263-301` — byte-identical FEC encode block duplicated. Extract to shared method.
2. `session.rs:409-419` — `decode_shards` clones+resizes every shard. Minimize allocations.
3. `router.rs:46-51` — `contains()` recomputes netmask each call. Cache `mask: u32` field in `Ipv4Net`.
4. `router.rs:97-103` — `insert()` re-sorts entire Vec O(n log n) per insertion. Use sorted-insert O(n).

### Task 7: Server control — combined lookups + Arc allow_ports + unconditional clones

Files: `frp-server/src/control/proxy_ops.rs`, `frp-server/src/control/nathole.rs`

1. `proxy_ops.rs:296` — `state.reloadable.read_ok().allow_ports.clone()` on every UDP proxy registration. Wrap in Arc.
2. `proxy_ops.rs:1037-1051` — 3 sequential async lookups in group dispatch. Combine into one compound lookup.
3. `nathole.rs:232-277` — unconditional field clones before branching. Move clones inside the branch that uses them.

### Task 8: Client — double JSON serialization + UDP Mutex + visitor IP cache

Files: `frp-client/src/control.rs`, `frp-client/src/work_conn.rs`, `frp-client/src/visitor.rs`, `frp-core/src/cipher_stream.rs`

1. `control.rs:470,535-536` — double `serde_json::to_string` for debug logs. Guard with `if tracing::enabled!(Debug)`.
2. `work_conn.rs:587,661` — `last_remote` Mutex per UDP packet, bidirectional. Use `ArcSwap<Option<UdpAddr>>`.
3. `visitor.rs:670,737` — `list_local_ips()` reads /proc/net/fib_trie + creates UDP socket per XTCP connection. Cache result with 30s TTL.
4. `cipher_stream.rs:148` — `iv_buf: Vec<u8>` for fixed 16 bytes. Use `[u8; 16]`.
