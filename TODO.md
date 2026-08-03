# TODO — frp-rs Feature Backlog

> **Reconciled against code 2026-07-12** (was auto-generated 2026-06-30; Status
> columns were stale on ~20 items — every claim below re-verified against
> current source with file:line evidence).
> **Milestone**: [v0.69.1 — Go frp parity + innovation](https://github.com/viogus/frp-rs/milestone/1) — 25/25 closed.
> **Parity**: 100% vs Go frp v0.69.1. All tracked issues closed.

---

## ⚠️ GitHub issue-label discrepancy

Three issues were marked **CLOSED/COMPLETED** on GitHub but the feature was
**absent from code** (verified 2026-07-12 — no deps, no `.proto`, no source).
Each was reopened to correct the false label, then re-closed **not-planned**
after a necessity review:

| Issue | Feature | Reality | Disposition |
|-------|---------|---------|-------------|
| [#51](https://github.com/viogus/frp-rs/issues/51) | gRPC management API | no `tonic`/`.proto`/`AdminService` in tree | **CLOSED not-planned** (redundant with REST+WS) |
| [#52](https://github.com/viogus/frp-rs/issues/52) | WASM/WASI plugin system | no `wasmtime`, no wasm loader | **CLOSED not-planned** (parked — dep size vs mission) |
| [#63](https://github.com/viogus/frp-rs/issues/63) | Traffic mirroring | no `mirror_to` field, no mirror logic | **CLOSED not-planned** (out-of-scope — see 4.5) |

All three verified never-implemented (reopen corrected the false COMPLETED
label); each close is a separate necessity judgment. 0 open issues remain.

---

## Shipped since 2026-06-30 (verified DONE)

Reconciliation confirmed all of these landed after the doc's original scan:

**Parity / protocol**
- 1.1 V2 full transport wiring — V2 over bare TCP, QUIC, KCP, WebSocket (not just yamux). `frp-client/src/control.rs:178-256`, `frp-server/src/service.rs:289-302,371-376,520-556,1024-1039,1958-1986`
- 2.1 V2 + QUIC interop — composed; old `control.rs:147` TODO gone. `frp-client/src/control.rs:220-254`
- 2.2 V2 without yamux (bare TCP) — accept + dial paths. `frp-server/src/service.rs:1958-1986`, `frp-client/src/work_conn.rs:207-269`
- 2.3 `CloseProxyResp` + `Error` V2 type IDs — assigned 19/20, in roundtrip tests. `frp-core/src/msg.rs:57-58,587-588`
- 1.2 Server plugin hooks Ping/NewWorkConn/NewUserConn — all fire. `frp-server/src/control/mod.rs:1043,525,551`, `handlers.rs:614`
- 1.3 Virtual Net (L3 VPN) — `frp-vnet` crate behind `vnet` feature
- 1.4 / 5.5 Work-conn warm-start pool — server eager `ReqWorkConn ×pool_count`, client eager spawn. `frp-server/src/control/mod.rs:372-384`, `frp-client/src/service.rs:724-726`
- 1.5 Config store file persistence — atomic write, load-on-startup. `frp-server/src/store.rs`, `dashboard.rs:468-539`

**Observability**
- 3.1 OpenTelemetry tracing — `otel` feature, OTLP exporter, 13 `#[instrument]` sites, all log calls use structured fields (completed 2026-07-12). `frps/Cargo.toml:24`, `frps/src/main.rs:64-150`
- 3.3 `/metrics` auth — `EnablePrometheus` gate + admin Basic auth. `frp-server/src/dashboard.rs:669-702`
- 4.4 Admin WebSocket event stream — `GET /api/events`, `ServerEvent` broadcast. `frp-server/src/event.rs`, `dashboard.rs:550-640`
- 4.3 Plugin hot-reload on client — live kill+restart, no frpc restart. `frp-client/src/service.rs:1285-1470`

**Perf / size**
- 5.1 / #100 Buffer pooling — `PoolGuard`, no raw `vec![0u8;65536]`, `BUFFER_SIZE=32768`. `frp-core/src/bridge.rs`, `buffer_pool.rs`
- 5.2 axum out of frp-core TLS — axum now under `frp-server` `dashboard` feature only. `frp-core/Cargo.toml:49-50`
- 5.3 `webpki-roots` → `rustls-platform-verifier` — done, zero webpki-roots refs

**Engineering**
- 6.1 Protocol fuzz tests — proptest over V1/V2 frames + all type bytes. `frp-core/src/protocol.rs:946-1145`
- 6.2 Config-normalization property tests — idempotency + flat/nested equivalence. `frp-core/src/config.rs:1888-2121`
- 6.4 TLS cert hot-reload — 60s mtime poll + SIGUSR1. `frp-server/src/service.rs:1210-1276`
- 6.5 Graceful connection drain — counter + timeout on SIGINT/SIGTERM. `frp-server/src/service.rs:2088-2108`
- 6.6 Admin API TLS — `TlsListener`, shares hot-reload acceptor. `frp-server/src/dashboard.rs:19-80,719-726`

**Performance program (4-axis, 2026-07)** — throughput → CPU → latency → memory:
- CPU: `aes` 0.8→0.9 runtime HW-AES autodetect (~10× encrypt on aarch64)
- Latency: `TCP_NODELAY` at 24 raw-TCP data-path sites (steady RTT p50 −21%)
- Memory: bridge buffer 64→32 KB (−43% idle_encrypt/conn), `CipherWriter` scratch reuse
- Harnesses: `scripts/{throughput,latency,memory}-baseline.sh`, `mem-profile` counting allocator

---

## Open Work

### Quick / polish (low effort — all done)

*No remaining items. All polish completed this pass.*

### Done this pass

- **6.3 Benchmark expansion — DONE** (2026-07-12, `0780a54`). Scoping corrected the item: protocol ser/de was already covered (`protocol_all_types`, all 21 V1+V2 types — TODO's "missing" claim was stale); connection-accept latency belongs in the e2e harness (`latency-baseline.sh setup` mode), not a criterion microbench (kernel/TLS noise dominates). The one genuine gap — **proxy-registration throughput** — added as `frp-server/benches/proxy_registration.rs` (register_single / register_1000 / register_with_group / proxy_info_construct). Also fixed a latent no-op: `crypto_bridge.rs` `v2_serialize_{name}` was duplicating V1 `serde_json` and discarding output; now measures the real `write_msg_v2` framing path.
- **3.2 `/healthz` readiness — DONE** (2026-07-12, `1aad907`). Readiness now checks `shutdown_token.is_cancelled()` BEFORE the lock probes — a draining server returns 503 "draining" so orchestrators stop routing new traffic (liveness still OK). Added `ProxyManager::is_responsive()` (non-blocking `try_read()` on the proxy registry), probed alongside `used_ports` and `run_id_to_ctl_tx`. Integration test verifies fresh server returns 200. (Draining unit test not feasible: `AppState::new` takes 22 internal params and has no test constructor — the draining check is a one-liner with clear semantics.)
- **3.1 structured-log conversion — DONE** (2026-07-12, `4e9dbfd`). Scope was dramatically smaller than the original 0.5d estimate: of ~62 `info!`/`warn!`/`debug!` calls, only 5 had variable interpolation at all, 2 already used `{var}` capturing (structured), so only 3 flat calls needed converting (`cipher_stream.rs` IV-EOF warn, `service.rs` KCP debug, `control/mod.rs` Ping plugin-hook debug). All log calls now use structured fields. The other ~59 `info!("plain text")` calls without interpolation are already fine — no dynamic data to structure.

### Performance remaining (perf program follow-ups)

- **5.6 Zero-copy encrypted bridge — DONE** (2026-07-12, `7be6aa7`). `CipherReader`/`CipherStream` `poll_read` now decrypt in-place into the caller's `ReadBuf` — drops one alloc + one copy per chunk on the encrypted `work_to_user` path. Reviewed (CFB partial-read hand-traced), compat 57/0. `frp-core/src/cipher_stream.rs`.
- **5.7 `quinn` slim wrapper — REJECTED** (2026-07-12). Prototyped `quinn-proto` wrapper: measured only **~32KB (frps) / ~16KB (frpc)** saved, not the ~800KB estimate — quinn-proto (the bulk) still links; LTO already stripped quinn's async glue. Not worth +1349 loc of hand-rolled QUIC state machine on an untrusted-network transport. Prototype discarded; re-derive from `quinn-proto` if the premise ever changes.

### Innovation — CLOSED not-planned (necessity review 2026-07-12)

- **4.1 gRPC management API — CLOSED not-planned** ([#51](https://github.com/viogus/frp-rs/issues/51)). Redundant with the complete REST admin API + Admin WebSocket event stream (#59); off-mission (Go frp has no gRPC); `tonic`+`prost`+`.proto` codegen fights the tiny/micro size philosophy; no demand. Reopen only for a concrete consumer REST+WS cannot serve.
- **4.2 WASM/WASI plugin system — CLOSED not-planned (parked)** ([#52](https://github.com/viogus/frp-rs/issues/52)). Genuine differentiator, but a `wasmtime` runtime is a multi-MB dependency that can never enter default/tiny/micro; ~5d+ speculative effort, no demand. Reopen with (a) a real use case AND (b) a size-acceptable host (e.g. `extism`, or a full-only build).
- **4.5 Traffic mirroring — CLOSED not-planned** ([#63](https://github.com/viogus/frp-rs/issues/63), 2026-07-12). `mirror_to` byte-tee. Out-of-scope after necessity review: off Go-frp-parity mission, no real demand (auto-generated issue), better served by front-proxy mirroring (envoy/nginx/Istio at the correct layer), adds a permanent path to the data-plane bridge + a data-exfil footgun. Reopen only on a real use case the front-proxy alternatives can't serve.

### Declined

- **5.4 `snap` → `lz4_flex` — NOT PLANNED** ([#66](https://github.com/viogus/frp-rs/issues/66)). Evaluation declined; `snap` retained. Reopen only with a benchmark showing lz4 wins on frp traffic + size.

---

## Summary

| Bucket | Count |
|--------|-------|
| Shipped (DONE) | 25 |
| Open — polish (PARTIAL) | 0 |
| Open — perf | 0 (5.6 shipped, 5.7 rejected) |
| Open — innovation | 0 (#51/#52 closed not-planned) |
| Closed / declined | 5 (#51 gRPC, #52 WASM, #63 mirror, #66 lz4, 5.7 quinn-slim) |

**Backlog fully empty.** 0 open issues. Perf follow-ups resolved (5.6 shipped,
5.7 rejected on measurement); benches + docs done; observability polish
(3.1/3.2) done. All innovation closes reviewed.

### Go frp v0.70.1 parity — closed (2026-08-02 parity pass)

Closed in the `fix/go-parity-2026-08-02` branch:

- Multi-tenant wire proxy names (`{user}.{proxy}`), visitor transport options,
  `tls2raw` tunnel-side TLS termination, TCPMux passthrough.
- OIDC client config (map `additionalEndpointParams`, `tokenSource`, audience
  omission, timestamp preservation), QUIC client options + mTLS propagation,
  WebSocket pipelined frames + AEAD-aware frame cap, KCP+TLS client.
- HTTP bridge plugin requestHeaders + InsecureSkipVerify backends, UDP packet
  size / PROXY header / v1 IPv6 family, proxy URL userinfo (HTTP Basic +
  SOCKS5 RFC1929) + socks5h remote DNS, dnsServer scope, admin reload/config
  endpoints + secret_key redaction, visitor reload.
- Server: allowPorts `{single=N}` + invalid-entry validation, port accounting
  (only tcp/udp consume), 24h per-name reservation, HTTPS vhost SNI
  passthrough, Go HTTP server-plugin contract (fail-closed), vhost
  X-Forwarded-For/requestHeaders + proxyBindAddr, SSH gateway `ssh -R`
  (tcpip-forward/forwarded-tcpip), dashboard root auth / pprof / offline
  clients / Go v1 client fields / store 0600 / file tokenSource.

Remaining known gaps (documented, architectural):

- HTTP vhost `responseHeaders`, 504 timeouts, h2c — **implemented**:
  responseHeaders via the server-side `ResponseHeaderInjector` bridge,
  per-request 504s via `vhost_http_timeout` on the response-header read
  (byte-level and h2c), and h2c via `h2`-crate decoding on the vhost port
  (routed like HTTP/1.1, forwarded to providers as HTTP/1.1, responses
  re-encoded as HTTP/2).
- HTTP plugin `enableHTTP2` (byte-level bridge).
- XTCP **data plane**: hole-punching/coordination is complete (17/17 XTCP
  pairwise compat incl. the QUIC data plane, 2026-08). Rust supports both
  KCP+yamux and QUIC for the P2P stream, selected by the `protocol` field
  (Rust visitor `protocol="quic"` ↔ Go provider works). Known limitation: a
  **Go** visitor with the default `protocol="quic"` cannot talk to a Rust
  provider — Go frp v0.70.1 sends `"ip:port"` as the QUIC SNI (Go 1.25
  `hostnameInSNI` no longer strips the port), which rustls rejects; rewriting
  the ClientHello would break the TLS 1.3 transcript. Such a Go visitor must
  set `protocol = "kcp"`. (See plan
  `docs/superpowers/plans/2026-08-02-go-parity-all-fixes.md`.)
- VirtualNet isolation/routing reload — **implemented**: `RouteTable` is now
  partitioned per virtual net (same subnet may coexist in different vnets,
  lookups are vnet-scoped); removing/updating a vnet proxy cleans its OS routes
  and sends `VnetRouteRemove`; the server scopes `VnetRouteAdvertise`/`VnetRouteRemove`
  broadcasts to same-vnet controls, broadcasts removals on proxy close, and
  drops `VnetPacket`s whose source run_id is not in the target route's virtual
  net; clients ignore advertisements for virtual nets they do not participate
  in. (See plan
  `docs/superpowers/plans/2026-08-02-go-parity-all-fixes.md`.)
