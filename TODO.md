# TODO — frp-rs Feature Backlog

> **Reconciled against code 2026-07-12** (was auto-generated 2026-06-30; Status
> columns were stale on ~20 items — every claim below re-verified against
> current source with file:line evidence).
> **Milestone**: [v0.69.1 — Go frp parity + innovation](https://github.com/viogus/frp-rs/milestone/1) — 25/25 closed.
> **Parity**: 100% vs Go frp v0.69.1. All tracked issues closed.

---

## ⚠️ GitHub issue-label discrepancy

Three issues are marked **CLOSED/COMPLETED** on GitHub but the feature is
**absent from code** (verified 2026-07-12 — no deps, no `.proto`, no source):

| Issue | Feature | Reality |
|-------|---------|---------|
| [#51](https://github.com/viogus/frp-rs/issues/51) | gRPC management API | no `tonic`/`.proto`/`AdminService` in tree |
| [#52](https://github.com/viogus/frp-rs/issues/52) | WASM/WASI plugin system | no `wasmtime`, no wasm loader |
| [#63](https://github.com/viogus/frp-rs/issues/63) | Traffic mirroring | no `mirror_to` field, no mirror logic |

These should be **reopened** (or documented as deliberately out-of-scope). They
are listed under Open Work below.

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
- 3.1 OpenTelemetry tracing — `otel` feature, OTLP exporter, 13 `#[instrument]` sites. `frps/Cargo.toml:24`, `frps/src/main.rs:64-150` *(minor remainder: not all flat `info!("{x}")` lines converted to structured fields — see Open Work)*
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

### Quick / polish (low effort)

- **3.2 `/healthz` readiness — PARTIAL.** Liveness OK; readiness (`?probe=readiness`) only try-locks two RwLocks. Plan wanted "internal channels alive, proxy manager responsive". `frp-server/src/dashboard.rs:361-388`. Effort: 1h.
- **3.1 structured-log conversion — remainder.** OTLP + `#[instrument]` done, but many `info!("foo {bar}")` lines not yet `info!(bar=%bar, "foo")` for queryability. Effort: 0.5d, mechanical.
- **6.3 Benchmark expansion — PARTIAL.** Have `crypto_bridge.rs` + `nathole.rs` + perf-program baselines. Missing: protocol serialize/deserialize, connection-accept latency, proxy-registration throughput. Effort: 0.5d.

### Performance remaining (perf program follow-ups)

- **5.6 Zero-copy encrypted bridge — GAP.** Encrypted path still `read → decompress(new Vec) → write`. Share `Bytes` between decrypt output and write to drop one copy. Plain path already `copy_bidirectional` (kernel zero-copy). `frp-core/src/bridge.rs:164-192`. Effort: High. *Natural 5th perf axis.*
- **5.7 `quinn` slim wrapper — GAP.** Full `quinn` 0.11 (~800KB). Long-term: thin wrapper over `quinn-proto` + reuse existing rustls config. Effort: High, low priority.

### Innovation (not built — issues mislabeled, see top)

- **4.1 gRPC management API — GAP** ([#51](https://github.com/viogus/frp-rs/issues/51)). `tonic` + `.proto` `AdminService` side-by-side with REST. Note: earlier backlog notes called gRPC out-of-scope (Go frp has none). Decide: build or close as won't-do. Effort: 3d.
- **4.2 WASM/WASI plugin system — GAP** ([#52](https://github.com/viogus/frp-rs/issues/52)). `wasmtime` sandboxed hot-loadable plugins. Effort: 5d.
- **4.5 Traffic mirroring — GAP** ([#63](https://github.com/viogus/frp-rs/issues/63)). `mirror_to = "staging-proxy"` config + tee logic. Effort: Medium.

### Declined

- **5.4 `snap` → `lz4_flex` — NOT PLANNED** ([#66](https://github.com/viogus/frp-rs/issues/66)). Evaluation declined; `snap` retained. Reopen only with a benchmark showing lz4 wins on frp traffic + size.

---

## Summary

| Bucket | Count |
|--------|-------|
| Shipped (DONE) | 21 |
| Open — polish (PARTIAL) | 3 |
| Open — perf GAP | 2 |
| Open — innovation GAP (mislabeled closed) | 3 |
| Declined | 1 |

No parity gaps remain. Remaining work is optional: observability polish, two
perf follow-ups (zero-copy bridge, quinn slim), and three innovation features
whose GitHub issues need reopening or closing-as-won't-do.
