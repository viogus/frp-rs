# Repo Refactor Design — 2026-07-10

## Goal

Reduce duplication and sharpen module boundaries across the workspace without
changing any observable behavior. Land two in-flight, uncommitted work items
cleanly first, then perform four targeted deduplication/boundary refactors.

Every unit is behavior-preserving: no wire-protocol change, no new dependencies,
the `tiny` and `micro` feature variants must still build, and the cross-compat
suite (`scripts/compat-test.sh`) must stay green against Go frp v0.69.1.

## Strategy (Approach A — incremental)

Six independent units, ordered 1 → 6. Each unit:

- gets its own git worktree (`EnterWorktree`) — no direct edits on `main`;
- is implemented by one subagent, reviewed before the next unit starts;
- ends with build + relevant tests + (where it touches a compat-tested path)
  `scripts/compat-test.sh --verbose`, then a single focused commit / PR.

Ordering rationale: land already-finished work first (units 1–2), then take the
riskiest data-plane change (unit 3) while attention is fresh, and finish with
the purely cosmetic dashboard dedup (unit 5) and mechanical struct grouping
(unit 6).

## Current state (context)

Uncommitted changes sit on `main` (violating the worktree rule) and mix **two
unrelated pieces**:

1. **Work-conn pool observability + buffer pool** (frp-core + frp-server):
   `frp-core/src/buffer_pool.rs` (new), `bridge.rs`, `state.rs`,
   `control/mod.rs`, `dashboard.rs`, `metrics/prom.rs`.
2. **frp-client `service.rs` method extraction**: `spawn_health_checks`,
   `spawn_admin_server`, `handle_nat_hole_client` pulled out of `run()`.

Both already compile (`cargo build --workspace` exits 0).

---

## Unit 1 — Commit pool feature (frp-core + frp-server)

**Type:** land existing WIP. No code change.

**Scope:** `buffer_pool.rs`, `bridge.rs`, `state.rs` (`PoolStats`, AppState
`pool_hits/misses/drops`, `pool_idle_timeout`), `control/mod.rs` (pool counters
+ idle-conn expiry), `dashboard.rs` (pool fields in status/clients responses),
`metrics/prom.rs` (5 new gauges).

**Verify:**
- `cargo build --workspace`
- `cargo build --release -p frps -p frpc --no-default-features --features tiny`
- `cargo build --release -p frps -p frpc --no-default-features --features micro`
- `cargo test --workspace`
- `bash scripts/compat-test.sh --verbose` (bridge PoolGuard is the hot-path touch)

**Commit:** `perf(server): work-conn pool observability + buffer pool`

**Risk:** low. Already compiling; only hot-path touch is the bridge buffer swap.

---

## Unit 2 — Commit client `service.rs` extraction (frp-client)

**Type:** land existing WIP. Pure code move (net +38 lines).

**Scope:** `frp-client/src/service.rs` — `run()` shrunk by extracting
`spawn_health_checks`, `spawn_admin_server`, `handle_nat_hole_client`.

**Verify:** build + `cargo test --workspace` + `bash scripts/compat-test.sh
--verbose` (XTCP path is touched by `handle_nat_hole_client` — run the guarded
XTCP pairwise matrix locally if Go frp source build is available).

**Commit:** `refactor(client): extract run() helpers`

**Risk:** low-medium. XTCP handler relocated; guarded XTCP compat confirms parity.

---

## Unit 3 — Bridge loop dedup (frp-core/bridge.rs)

**Problem:** `bridge_encrypted`, `bridge_plain`, `bridge_plain_rate_limited`
contain 6 near-identical read → process → write half-loops. Each reads into a
`PoolGuard` buffer, optionally compresses/decompresses, and `write_all`s.

**Change:** extract one generic pump routine parameterized by:
- a per-chunk transform closure (identity / compress / decompress), and
- an optional pre-write async hook (rate limiter) for the rate-limited variant.

Framing stays where it already lives (`CipherWriter` length-prefix framing,
`SnappyDecompressor` streaming). The pump only moves plaintext chunks through
the transform.

**Invariants to preserve exactly:**
- `PoolGuard::acquire()` buffer use (no re-introduced per-call `vec![0u8; 65536]`);
- metrics counters `bytes_in` / `bytes_out` increment at the same points;
- EOF (`Ok(0) => break`) and error-break semantics unchanged;
- compress-before-encrypt ordering unchanged;
- rate-limited variant keeps its limiter await between read and write.

**Test:** `cargo test -p frp-core`, `cargo bench -p frp-core --no-run`,
`bash scripts/compat-test.sh --verbose` (plain / encrypt / compress matrix — this
is the data plane).

**Risk:** high (data plane). Isolated single-file change keeps any regression
bisectable; compat suite is the gate.

---

## Unit 4 — Work-conn pool dedup (frp-server/control/mod.rs)

**Problem:** 4 `work_pool.pop_front()` sites repeat the same shape:
`pop_front → pool_hits += 1 → update pool_size → assign_work_to_proxy`, else
`pool_misses += 1 → send ReqWorkConn → push pending_requests → update pending`.

**Change:** extract one `assign_or_queue(...)` helper covering the common
proxy/visitor assignment case (STCP visitor, `ProxyUserConn`, `VisitorConn`,
`NewWorkConn` drain).

**Leave specialized:** the `NatHoleSidOnWorkConn` path (sends StartWorkConn +
NatHoleSid, not `assign_work_to_proxy`) and the UDP path — do not force these
into the helper.

**Invariants:** biased-select ordering, every `pool_stats` atomic store, and all
counter increments stay identical.

**Test:** build + `cargo test --workspace` + `bash scripts/compat-test.sh
--verbose` (STCP / TCP / HTTP).

**Risk:** medium.

---

## Unit 5 — Dashboard handler dedup (frp-server/dashboard.rs)

**Problem:** `handle_status` and `handle_serverinfo` are byte-identical; the
pool-fold aggregation is copy-pasted.

**Change:** extract `build_status_response(&state) -> StatusResponse`; both
handlers call it. `/api/serverinfo` stays a Go-frp-compat alias with identical
output.

**Test:** build + `cargo test -p frp-server`.

**Risk:** low.

---

## Unit 6 — AppState grouping (frp-server/state.rs)

**Problem:** `AppState` is a god-struct (proxy manager, port set, sk_index,
vhost, nat_hole, oidc, pool counters, …).

**Change:** group cohesive fields into sub-structs, moderately (YAGNI — no
over-grouping):
- `pool: PoolMetrics { hits, misses, drops, idle_timeout }`
- `oidc: OidcState { verifier, subjects }`
- `xtcp: XtcpState { nat_hole, sk_index }`

One construction site (`AppState::new`) updates cleanly; the churn is mechanical
`state.field` → `state.group.field` accessor updates across the server crate.
No test currently constructs `AppState` directly.

**Invariants:** field semantics unchanged; feature-gated fields (`#[cfg(...)]`)
keep their gates.

**Test:** build + feature matrix (tiny/micro) + `cargo test --workspace` +
`bash scripts/compat-test.sh --verbose`.

**Risk:** medium (breadth of accessor churn, not logic).

---

## Cross-cutting constraints (all units)

- No new dependencies (see CLAUDE.md dependency policy).
- `tiny` and `micro` feature variants must build.
- Cross-compat suite green vs Go frp v0.69.1; XTCP guarded matrix where the
  XTCP path is touched (units 2, and indirectly 4/6).
- Worktree + subagent per unit; review between units.

## Success criteria

- All six units merged, each behavior-preserving.
- Duplication removed at the four identified hotspots; `AppState` boundaries
  cohesive.
- `cargo test --workspace` green; compat suite green; tiny/micro build clean.
- No wire-protocol or dependency changes.
