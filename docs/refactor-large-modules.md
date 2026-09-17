# Refactoring the large modules

**Status: proposal — no code has been changed.** Opened 2026-09-17 at `9c84ada`,
from the backlog item *"Very large source files"* in [`../TODO.md`](../TODO.md).

The backlog item quoted raw line counts. Measuring them properly **changed the
conclusion**, so the first two sections are the measurements and the corrections
they forced.

---

## Headline

**The real problem is single functions, not files — and ranking by file size is
actively misleading.**

`frp-server/src/service.rs` ranks only **11th** by file size (2074 production
lines), yet it contains the largest production function in the repository:

| # | Function | Location | **Code lines** |
|---|---|---|---:|
| 1 | **`run`** | **`frp-server/src/service.rs:308`** | **1291** |
| 2 | `run_message_loop` | `frp-client/src/service.rs:2752` | 697 |
| 3 | `handle_new_proxy` | `frp-server/src/control/proxy_ops.rs:1849` | 546 |
| 4 | `authenticate` | `frp-server/src/control/login.rs:617` | 510 |
| 5 | `run_visitor_listener` | `frp-client/src/visitor.rs:1141` | 502 |
| 6 | `spawn_work_conn` | `frp-client/src/work_conn.rs:1634` | 469 |
| 7 | `handle_tls_connection` | `frp-server/src/handlers/transport.rs:42` | 463 |
| 8 | `handle_nat_hole_visitor` | `frp-server/src/handlers/dispatch.rs:368` | 447 |
| 9 | `run_udp_work_conn` | `frp-client/src/work_conn.rs:754` | 419 |
| 10 | `handle_websocket_connection` | `frp-server/src/handlers/transport.rs:674` | 412 |

`run` is **1.85× larger than the next function** and is the single best
refactoring target in the codebase — and, unusually, also the **safest** (see
below). It was invisible to a file-size ranking, and it was invisible to the
first draft of this document, which had the priority order wrong. That is the
argument for [`scripts/large-functions.sh`](../scripts/large-functions.sh) being
part of this proposal rather than a prose analysis: the measurement changed the
conclusion twice.

Also corrected from raw line counts: 30–55% of the "large" files are inline
tests, and 36–77% of the "giant" functions are comments. `poll_read` in
`control/bridge.rs` — 664 lines and alarming on paper — is **236 lines of code**.

## How the numbers were measured

Two mistakes were made and corrected while producing this document. They are
recorded because the same traps will catch anyone re-measuring.

- **Raw `wc -l` counts test code as if it were production.** Fixed by locating
  each `#[cfg(test)] mod …` block by brace matching and excluding it.
- **"Last function absorbs the trailing test module."** Function size was
  computed as `next_function_start − this_start`; for the final function in a file
  that end is EOF, so it swallowed the test module and reported nonsense (e.g.
  `assign_work_to_proxy` as "2329 lines"). Fixed by clamping each function's end at
  the next test-module start.

Both are now measured by [`scripts/large-functions.sh`](../scripts/large-functions.sh),
which is read-only and never fails a build:

```bash
bash scripts/large-functions.sh          # per-file production LOC + top 12 functions
bash scripts/large-functions.sh --top 25
```

Every number in this document comes from that script. The script itself also had
a bug worth recording: a whole-file test module (`frp-core/src/config/tests.rs`)
carries no `#[cfg(test)]` inside it — the attribute is on the `mod` declaration
that includes it — so it was counted as **6005 lines of production code** until
files named `tests.rs` and directories named `tests/` were excluded.

---

## Measurements

### Production vs inline tests

| File | Total | Inline tests | **Production** |
|---|---:|---:|---:|
| `frp-client/src/service.rs` | 6382 | 1452 | **4930** |
| `frp-client/src/visitor.rs` | 3850 | 165 | **3685** |
| `frp-server/src/control/proxy_ops.rs` | 8044 | 4432 | **3612** |
| `frp-server/src/control/bridge.rs` | 5445 | 2122 | **3323** |
| `frp-server/src/vhost.rs` | 6312 | 3148 | **3164** |
| `frp-server/src/dashboard.rs` | 3910 | 987 | 2923 |
| `frp-server/src/ssh_gateway.rs` | 4865 | 2123 | 2742 |
| `frp-core/src/auth.rs` | 3791 | 1924 | 1867 |

Note `frp-client/src/visitor.rs`: 3685 production lines with only **165 lines of
tests** — the largest production-to-test ratio in the repository, and it is the
XTCP/STCP/SUDP/vnet data plane.

### Comment density in the largest functions

| Function | Total | Comments | **Code** | Code % |
|---|---:|---:|---:|---:|
| `run_message_loop` (`service.rs`) | 1116 | 401 | **697** | 62% |
| `handle_new_proxy` (`proxy_ops.rs`) | 779 | 211 | **546** | 70% |
| `run_visitor_listener` (`visitor.rs`) | 650 | 124 | **502** | 77% |
| `register_proxies` (`service.rs`) | 607 | 205 | **394** | 65% |
| `reload_from_sources` (`service.rs`) | 516 | 139 | **351** | 68% |
| `run_udp_work_conn` (`bridge.rs`) | 421 | 130 | **291** | 69% |
| `poll_read` (`bridge.rs`) | 664 | **419** | **236** | **36%** |
| `handle_http1_request` (`vhost.rs`) | 505 | **306** | **189** | **37%** |

The heavy commentary is deliberate and valuable — it carries the Go-parity
reasoning that makes this code reviewable. **It is not the problem.** But it does
mean any refactor must preserve the comments alongside the code they justify, and
that line-count-driven prioritisation is misleading here.

### Churn and defect concentration

Last 400 commits, and the subset whose subject matches
`fix|audit|hardening|blocker|regression`:

| File | Commits touching it | Touches in fix/audit commits | Production lines |
|---|---:|---:|---:|
| `frp-client/src/service.rs` | **53** | **230** | **4930** |
| `frp-server/src/control/proxy_ops.rs` | 47 | 112 | 3612 |
| `frp-server/src/vhost.rs` | 40 | 94 | 3164 |
| `frp-server/src/control/login.rs` | 40 | — | — |
| `frp-client/src/work_conn.rs` | 37 | 85 | — |
| `frp-server/src/control/bridge.rs` | 36 | 100 | 3323 |
| `frp-client/src/visitor.rs` | 31 | 85 | 3685 |

This **validates** the backlog's claim that defect-prone code clusters in these
files — and it is why the corrected priority is `service.rs`.

### Interface surface (good news for refactoring)

| File | functions | `pub` | pub % |
|---|---:|---:|---:|
| `frp-server/src/control/bridge.rs` | 94 | 2 | 2% |
| `frp-server/src/control/proxy_ops.rs` | 123 | 11 | 9% |
| `frp-server/src/vhost.rs` | 107 | 13 | 12% |
| `frp-client/src/visitor.rs` | 54 | 8 | 15% |
| `frp-client/src/service.rs` | 72 | 14 | 19% |

These are overwhelmingly private internals. Extraction does **not** require
widening the public API — most seams can stay `pub(crate)` or module-private,
which is what keeps the risk low.

### Feature-gate entanglement

| File | `#[cfg(feature = …)]` sites |
|---|---:|
| `frp-client/src/service.rs` | **84** |
| `frp-client/src/visitor.rs` | 17 |
| `frp-server/src/control/proxy_ops.rs` | 14 |
| `frp-server/src/vhost.rs` | 3 |
| `frp-server/src/control/bridge.rs` | 0 |

`service.rs` is by far the most cfg-entangled. **Any split of it must be a pure
move** — no logic edits — and must be verified against the tiny/micro feature
builds, not just `--all-features`.

---

## Step 0 — the universal first move: file-ify the inline tests

Before any production code moves, do this in every file that has a large inline
`#[cfg(test)] mod tests`:

```bash
git mv frp-server/src/control/proxy_ops.rs frp-server/src/control/proxy_ops/mod.rs
# declare the test modules, then move each body into a sibling file
#   #[cfg(test)] pub(crate) mod unregister_generation_tests;
#   #[cfg(test)] mod subdomain_conflict_tests;
```

This is **zero-risk and unusually high-yield**, because a file module and an
inline module have the *same module path* and the same `use super::*` semantics
(`super` is the parent either way). Nothing outside can tell the difference; the
only textual change is one level of de-indentation.

| File | Now | After | Reduction |
|---|---:|---:|---:|
| `frp-server/src/control/proxy_ops.rs` | 8044 | ~3610 | **55%** |
| `frp-server/src/vhost.rs` | 6312 | ~3160 | 50% |
| `frp-server/src/control/bridge.rs` | 5445 | ~3320 | 39% |
| `frp-server/src/ssh_gateway.rs` | 4865 | ~2740 | 44% |
| `frp-client/src/service.rs` | 6382 | ~4930 | 23% |

Two things make it more than cosmetic:

- It **shrinks the apparent problem to its real size**, so the remaining decisions
  are made against production code rather than test code.
- `proxy_ops.rs` and `vhost.rs` each hold a single 1800–3100-line interleaved test
  suite spanning many functions. Leaving those inline keeps every production edit
  surrounded by thousands of lines of tests, which is part of why these files are
  churned so heavily.

Constraints that make it safe, and the one that makes it fail:

- The three test modules in `proxy_ops.rs` are referenced **by path** from seven
  other files (`crate::control::proxy_ops::unregister_generation_tests::{proxy_info,
  test_state}` — `metrics/prom.rs`, `dashboard.rs`, `handlers/dispatch.rs`,
  `control/bridge.rs`, `control/proxy.rs`, `control/mod.rs`, `control/pool.rs`).
  A `mod`-declaration-based file split preserves that path; moving the module
  *content* anywhere else breaks it. Declare, do not relocate.
- `unregister_generation_tests`'s nested `port_error_text_tests` uses
  `use super::super::*`, which must keep resolving.
- Renaming `proxy_ops.rs` → `proxy_ops/mod.rs` requires matching `pub(crate) use`
  re-exports for everything external code imports (`err_msg`, `handle_new_proxy`,
  `unregister_control`, `release_udp_port_with_owner_check`,
  `remove_proxy_and_release_client_counts`), so no caller needs editing.
- Validation: `cargo test --workspace --all-features` must report the same test
  names; `git diff -M` must show moves plus whitespace only; and, as a hard check
  for any "pure move", `git diff -U0 | grep -E '^[+-].*"'` must be **empty** — no
  string literal may change.

---

## Recommendation

Ranked by *risk reduction per unit of disruption*, using the measurements above.

| Priority | Target | Why | Shape |
|---|---|---|---|
| **P0** | **File-ify the inline test modules** in all five files below | Zero production change, same module paths, ~40–55% line reduction in the worst files; see [Step 0](#step-0--the-universal-first-move-file-ify-the-inline-tests) | one commit per file |
| **P1** | `frp-server/src/service.rs::run` | Largest function in the repo (1291 code lines); **a linear startup sequence**, so extraction is mechanical and low-risk; `handlers/` already sets the precedent for this exact kind of split | ~10 listener blocks → named methods |
| **P2** | `frp-client/src/service.rs` | #1 production file size (4930), #1 churn (53), #1 fix density (230), 84 cfg gates | 5 seams, ~1900 lines |
| **P3** | `frp-client/src/visitor.rs` | #2 production size (3685) and **almost untested** (165 test lines) | 3–4 seams |
| **P4** | `frp-server/src/control/proxy_ops.rs` | `handle_new_proxy` 546 code lines; 2nd-highest fix density | 2–3 seams |
| **P5** | `frp-server/src/control/login.rs::authenticate` (510) and `frp-client/src/work_conn.rs` (`spawn_work_conn` 469, `run_udp_work_conn` 419) | Surfaced only by the measurement script; not on any file-size list | 1 seam each |
| **P6** | `frp-server/src/control/bridge.rs` | Hot data path, highest risk per line changed. Only the UDP family and the injector adapter clearly pay | 2 seams |
| **P7** | `frp-server/src/vhost.rs` | Not urgent for production, but **a 3147-line test extraction with zero production change**, then 4 low-risk seams | 1 free step + 4 seams |
| **P8** | `frp-server/src/ssh_gateway.rs` | Already decomposed (largest fn 310 code lines); the win is the test extraction plus `args.rs`, the cleanest seam in the repo | 1 free step + 6 seams |
| — | `frp-server/src/handlers/` | The product of an earlier successful split; largest fn 463 code lines | leave alone |

**Do one block per pull request.** Each is a pure move plus `mod`/`use` plumbing.

---

## Per-file analysis

### P1 — `frp-server/src/service.rs::run` (1291 code lines) — do this first

`run` is not a tangled algorithm. It is a **linear startup sequence**: ~10
independent "if this port is configured, start that listener" blocks, three
one-shot background tasks, the main accept loop, and a graceful-drain tail. That
makes it the safest large-scale extraction available anywhere in this codebase —
far safer than `run_message_loop`, where `select!` fairness is load-bearing.

`service.rs` has only **10 production functions**; `run` is 1291 of its 2074
production lines. The connection-*handling* half of this file was already split
into `frp-server/src/handlers/` (`dispatch.rs` 1568, `transport.rs` 2043); the
listener-*startup* half never was. This finishes that job.

Block inventory, from the function's own comment landmarks:

| Lines | Block | Proposed home |
|---:|---|---|
| ~357–646 | WebSocket listener (~290 lines) | `service/listeners.rs` |
| ~649–668 | HTTP vhost listener | `service/listeners.rs` |
| ~673–693 | HTTPS vhost listener | `service/listeners.rs` |
| ~695–717 | TCPMux listener | `service/listeners.rs` |
| ~720–744 | SSH tunnel gateway | `service/listeners.rs` |
| ~747–1248 | **KCP listener (~500 lines — the biggest block)** | `service/listeners.rs` |
| ~1251–1417 | QUIC listener (~167) | `service/listeners.rs` |
| ~1420–1458 | Dashboard server | `service/listeners.rs` |
| ~1465–1484 | NAT-hole session cleanup task | `service/tasks.rs` |
| ~1485–1490 | Port-reservation pruner (calls `spawn_port_reservation_pruner` in `proxy_ops.rs`) | `service/tasks.rs` |
| ~1491–1558 | TLS cert hot-reload task | `service/tasks.rs` |
| ~1563–1603 | SIGINT/SIGTERM handler task | `service/tasks.rs` |
| ~1604–1768 | Stale-control reaper task | `service/tasks.rs` |
| ~1769–1908 | Main accept loop | **stays in `run`** |
| ~1909–1949 | Graceful drain + OIDC stop | **stays in `run`** |

Recommended method: extract **one listener block at a time**, as an
`async fn start_kcp_listener(&self) -> Result<()>`-shaped method, starting with
KCP (largest) or WebSocket. No ordering change, no control-flow change, no error
text change — each block already binds its own port and spawns its own task.

*Risk:* **low** — no shared mutable state beyond `&self`/`AppState`, no cfg
entanglement in this file (35 inline-test lines only), and the extraction is
verifiable by inspection of the diff.

*Validation:* `cargo clippy -D warnings`, `cargo test --workspace --all-features`,
`scripts/compat-test.sh` (KCP/QUIC/WS are all compat-covered),
`scripts/protocol-matrix.sh` (this is exactly the 11-row transport matrix — the WS
and KCP rows would catch a listener that stops starting), and the `health` CI job.

### P2 — `frp-client/src/service.rs` (4930 production lines, 34 production fns)

The crate already has a modular intent (`health.rs` 1530, `work_conn.rs` 2910,
`nat_hole.rs` 1060, `admin.rs` 1046, `reload.rs` 421) — `service.rs` has become
the orchestration dumping ground. The function names alone expose five seams:

| Proposed module | Functions to move (line) | Notes |
|---|---|---|
| `service/health.rs` | `health_check_monitored` (157), `spawn_health_checks` (4124), `healthy_resets_error_count` (4837) | `health.rs` already owns the probe mechanics; this is the monitoring/verdict half. Same responsibility, currently in two files. |
| `service/reload.rs` | `reload_from_sources` (4321), `request_reload` (1133), `try_reload` (4307), `close_wire_name_for_reload` (755), `filter_active_proxies` (4873), `filter_active_visitors` (4903) | `reload.rs` today holds only the snapshot types; this moves the logic next to them. |
| `service/registration.rs` | `register_proxies` (1798), `reg_frame_header_read` (591), `reg_frame_payload_read` (674) | Self-contained: frame-by-frame registration with its own retry/backoff. |
| `service/session.rs` | `run` (1166), `connect_and_login` (1553), `spawn_session_tasks` (2405), `teardown_session` (3868), `shutdown_visitor_tasks` (728), `cancel_detached_tasks` (4224), `spawn_admin_server` (4250), `record_plugin` (921) | The per-connection lifecycle. |
| *(stays)* | `run_message_loop` (2752) | The control-plane state machine. See below. |

**`run_message_loop` is the real target and it is a `select!` loop, not a pile of
unrelated code.** Its leading ~150 lines are comments documenting the persisted
read future (audit S3) and the heartbeat-watchdog timer. Recommended treatment is
**not** to move it but to extract its arms' bodies into named methods on a small
`SessionCtx`-carrying type, one arm per PR, leaving the `select!` skeleton in
place. Ordering and fairness (`no biased;`) are load-bearing here and are pinned
by a regression test — do not restructure the `select!` itself.

*Interface exposed:* each seam needs the fields its functions read from `Service`
and the session context. Expect to pass a `&mut` session struct rather than many
individual fields.

*Risk:* **medium-high** — 84 cfg gates, task-spawn ordering, shutdown/cancellation
semantics. Mitigation: pure moves only, one seam per PR, tiny/micro builds checked.

*Validation:* `cargo check --no-default-features --features tiny|micro` for every
seam; `cargo test --workspace --all-features`; `scripts/compat-test.sh`;
`scripts/protocol-matrix.sh`; and specifically the client integration tests that
exercise reload (`frp-client/tests/`) since reload is a seam here.

### P3 — `frp-client/src/visitor.rs` (3685 production lines, 36 production fns, 165 test lines)

Four parallel listener implementations live in one file, each with its own loop:

| Proposed module | Functions to move | Notes |
|---|---|---|
| `visitor/stcp.rs` | `run_visitor_listener` (1141) — 502 code lines, the file's largest | STCP/XTCP visitor accept + bridge |
| `visitor/xtcp.rs` | `do_hole_punch` (395), plus the STUN/punch helpers | Shares the STCP path's tail; split only after stcp |
| `visitor/sudp.rs` | `run_sudp_visitor_listener` (1791), `run_sudp_worker` (2207), `connect_sudp_visitor_stream` (2078) | Cohesive UDP family |
| `visitor/vnet.rs` | `run_virtual_net_visitor` (2476), `run_virtual_net_tunnel_io`, `list_local_ips`, `deliver_tunnel_ingress` | Could live beside `frp-client/src/vnet.rs` |

*Risk:* **medium** — lower cfg entanglement (17) but **this is the least-tested
large file in the repo**, which cuts both ways: a pure move is safe, but there is
little to catch a mistake in the moved code. Recommend doing this **after**
`service.rs`, and adding coverage before touching the xtcp/vnet arms.

*Validation:* as above, plus the XTCP e2e tests
(`frp-server/tests/xtcp_hole_punch.rs`, `frp-core/tests/xtcp_p2p.rs`) and the daily
`xtcp-compat.yml` matrix.

### P4 — `frp-server/src/control/proxy_ops.rs` (3612 production lines, 34 production fns)

Production code is lines 1–3610; the remaining 4432 lines are inline tests. **So
the first move here is [Step 0](#step-0--the-universal-first-move-file-ify-the-inline-tests)**:
convert to `proxy_ops/mod.rs` and file-ify the three test modules, which takes the
file from 8044 to ~3610 lines with no logic and no path change.

Two structural facts dominate everything after that:

**(a) Path-preserving is mandatory and cheap.** Seven files reach into
`proxy_ops::` by path — five production importers (`err_msg`, `handle_new_proxy`,
`unregister_control`, `release_udp_port_with_owner_check`,
`remove_proxy_and_release_client_counts`) and seven test importers of
`crate::control::proxy_ops::unregister_generation_tests::{proxy_info, test_state}`.
Converting to a directory with `pub(crate) use` re-exports keeps **every external
path byte-identical**, so no caller is edited.

**(b) No `AppState` field is private** (only the three group controllers are
`pub(crate)`), so **no field-visibility change is needed for any seam**. There is
no `unsafe` in the file.

Seams, in the order they should be attempted:

| Order | New module | Moves | Risk |
|---|---|---|---|
| 0 | *(directory + test modules)* | see Step 0 | **lowest** |
| 1 | `proxy_ops/validate.rs` | `validate_new_proxy` (891–961, pure), `duplicate_domain` (68–77) + its test module | low — zero `AppState` coupling, self-testing |
| 2 | `proxy_ops/vhost.rs` | `register_http_vhost` (968–1213), `register_https_vhost` (1221–1441) | low — already fully extracted; no test region references them |
| 3 | `proxy_ops/tcp_group.rs` | `tcp_group_listener` (3273–3426), `handle_tcp_group_member_registration` (3437–3547) | low — leaves, owned args |
| 4 | `proxy_ops/registry.rs` | `build_proxy_info`, `register_sk_index`, `register_proxy_entry`, the three `rollback_*`, `remove_proxy_and_release_client_counts` | medium-low |
| 5 | `proxy_ops/ports.rs` | `PortError`, `allocate_proxy_port` (171–409), the rollback/free helpers, the reservation pruner + its `impl AppState` | medium-low |
| 6 | `proxy_ops/teardown.rs` | `unregister_control` (2869–3262) — one function, 394 lines | medium |
| 7 | `proxy_ops/listener.rs` | `bind_proxy_listener`, `bind_tcp_proxy_with_retry`, `setup_proxy_listeners` (1456–1839), `listen_and_proxy` | medium — largest move, 13-arg interface |
| 8 | `proxy_ops/tcpmux.rs` | the inline tcpmux arm (2267–2546, 276 lines) lifted out of `handle_new_proxy` | **medium — the only seam that rewrites control flow** |

Notes on the hardest ones:

- **`unregister_control` (seam 6) is the most safety-critical function in the
  file**: four phases with explicit lock-order comments, generation filtering at
  six sites, and the `https_proxy_count` non-decrement invariant. Move it as a
  pure text move in its own commit, and only *after* seam 5, so the other half of
  the lock-order invariant already has a stable home.
- **The tcpmux arm (seam 8) is a genuine code change**, not a move: `return`-heavy
  code becomes `async fn register_tcpmux_proxy(...) -> bool` mirroring the existing
  `register_http_vhost` / `register_https_vhost` shape. It is the highest-value
  reduction of the 771-line `handle_new_proxy`, and the riskiest. Its Go error text
  is the densest in the file ("unknown multiplexer [{}]", group constants, etc.).
- `handle_new_proxy`'s smaller arms (plugin hook, quota check, vnet route
  registration) are each 72–115 lines and can be lifted later. **`quota` is the
  lowest-risk of the three**; `vnet` needs its three depth-sensitive
  `super::nathole::` paths rewritten to `crate::control::nathole::` if it lands one
  level deeper.

**Do not:**

- **Split `unregister_generation_tests` as test logic.** It is one interleaved
  suite over `handle_new_proxy` (50 refs), `unregister_control` (21) and
  `free_replaced_port` (11). File-ify it; do not re-cut it.
- **Turn `handle_new_proxy` into a pipeline/middleware chain.** The order
  plugin → validate → quotas → allocate → register → vhost/vnet/tcpmux → listeners
  is Go-parity-critical (documented in the function itself).
- **Create a 25-line `response.rs`** for `err_msg`/`write_resp`/`reject_new_proxy`.
  Keep `err_msg` in `mod.rs` and only re-export if moved.
- **Object-ify `write_resp`/`reject_new_proxy`** — they are `async` and generic
  over `impl AsyncWriteExt`, which matters on the V1/V2 hot path.

Hazards specific to this file:

- **A deadlock-critical invariant spans the proposed modules.** The lock order
  `used_ports → port_reservations` is asserted at four sites (`allocate_proxy_port`,
  `handle_new_proxy`'s TCP-group join, and twice in `unregister_control`); tokio's
  `RwLock` is not reentrant. If `ports.rs` and `teardown.rs` are separated, the
  invariant must be restated in **both** module docs, or someone will "optimize"
  one side into a deadlock of the control `select!` loop.
- **`#[inline(never)]` is deliberate at 12 sites** (170, 413, 492, 511, 719, 740,
  762, 793, 890, 967, 1220, 1455). Losing one changes release codegen under
  `opt-level=z` + LTO. They must travel with their functions.
- **Three depth-sensitive relative paths**: `super::nathole::is_route_hijack_prefix`
  and `super::nathole::MAX_VNET_ROUTES_PER_CLIENT`; everything else in production is
  `crate::`-absolute.
- **`#[cfg]` on an `if` expression** (the vnet arm, 2135) is easy to mangle when
  lifting code — `cargo test --workspace --all-features` is required to compile
  those arms at all.
- **Error-text literals are the compat contract**, including three identical copies
  of "subdomain is not supported because this feature is not enabled in server"
  (991, 1243, 2309) — a search-replace across a seam would be dangerous. Note that
  the *summary* strings in non-detailed mode are a documented frp-rs divergence, so
  the unit tests pin them, not `compat-test.sh`.
- `#[allow(clippy::too_many_arguments)]` at 1454/1847/3436 must be preserved or
  clippy `-D warnings` fails (13-, 9- and 12-arg functions).

*Validation:* `cargo test --workspace --all-features`;
`scripts/compat-test.sh --verbose` for anything on the registration/teardown path;
`scripts/protocol-matrix.sh`; and for pure moves, the empty-string-literal diff
check from Step 0. The `tcpmux_group_*` / `tcpmux_route_conflict*` /
`tcpmux_unknown_multiplexer_rejected_empty_accepted` tests drive `handle_new_proxy`
end-to-end and cover seam 8.

### P5 — `frp-server/src/control/login.rs::authenticate` (510) and `frp-client/src/work_conn.rs`

Neither file appears on a file-size ranking, yet each holds a function in the
repository's top ten by code size:

- `authenticate` (`login.rs:617`, 510 code lines) — the login handshake and every
  authentication path. `login.rs` has the 2nd-highest fix density in the server
  (`40` commits touching it in the last 400). Sub-splitting by auth method
  (token / OIDC / replay+throttle) is the obvious seam; note that the *order* of
  those checks is Go-parity-critical (run_id validation before `VerifyLogin`,
  replay rejection outside the lock), so extract by method, never by reordering.
- `spawn_work_conn` (`work_conn.rs:1634`, 469) and `run_udp_work_conn`
  (`work_conn.rs:754`, 419) — the client work-connection family. `work_conn.rs`
  already exists as its own module (2910 lines), so this is an intra-module split.

These are the clearest illustration of why this document exists: **file-size
ranking would never have found them.**

*Risk:* medium for `authenticate` (auth ordering, throttle/replay semantics),
low for the work-conn pair.

*Validation:* `scripts/compat-test.sh` covers login and auth paths and asserts Go's
exact error text; run the OIDC scenarios specifically
(`compat-test.sh --test go-to-rust-oidc-proxy`).

### P6 — `frp-server/src/control/bridge.rs` (3323 production lines, 41 production fns, 0 cfg gates)

**First, a correction to an assumption this document started with:** the actual
byte pump is *not* here. It is `frp-core/src/bridge.rs` (2957 lines, 11
`bridge_*`/`relay_plain_*` functions). This file is three separate things:

1. one self-contained response-header injector,
2. server-side UDP / SUDP plumbing,
3. work-connection assignment and dispatch.

Seams, ranked by value ÷ risk. All pure moves, no statement edits:

| Order | New module | Moves | Risk |
|---|---|---|---|
| **1** | `control/bridge/injector.rs` | `ResponseHeaderInjector` (120–1544) + `Discard` / `DeclaredFraming` / `ChunkedSkip` / `ChunkedState` / `DISCARD_WARN_THROTTLE`, plus its own tests | **low** |
| 2 | `control/bridge/udp.rs` | `UdpFrameReader` / `UdpFrameFut` / `udp_frame_fut` / `run_udp_work_conn` / `UDP_WORK_CONN_READ_TIMEOUT` / `request_udp_work_conn_replacement` / `assign_udp_work_conn` / `udp_dest_socket_addr` (~1550–2346) + tests | low |
| 3 | `control/bridge/assign.rs` | `build_start_work_conn`, `http_leg_head_deadline`, `assign_work_to_proxy` (3108–3321) + tests | low |
| 4 | `control/bridge/sudp.rs` | `run_sudp_message_bridge` only | low — **but see the gap below** |
| — | *deferred* | `run_work_bridge` + `relay_plain_fast` + `UserSide` (the root) | — |

**Ship the injector first, alone.** It is a self-contained `AsyncRead` adapter: the
type is referenced outside this file **only in comments**
(`vhost_h2c.rs:530,1769`, `vhost.rs:664`), so there is no reverse coupling at all,
and extracting it removes roughly 2900 lines including its tests — the single
largest reduction available in the file. Needs `try_split_work_halves` and
`log_bridge_panic` exposed as `pub(super)`; `assign_udp_work_conn` and
`assign_work_to_proxy` keep their existing `pub(crate)` signatures.

**Do not split `poll_read`** (905–1543). It is 236 code lines inside one `AsyncRead`
state machine whose four sections (complete gate 916–951, emission gate 977–1010,
C3b discard 1025–1170, gather loop 1177–1524, post-boundary serve 1526–1542) share
all 16 fields and depend on *which poll they are in* — in particular a poll that
filled the caller's `ReadBuf` must never return `Pending` (comment 989–1009).
Extracting helpers would have to thread that invariant through a params struct;
that is how this file's historical bugs happened.

**Verification gap worth fixing before seam 4:** `run_sudp_message_bridge` has no
unit test and, per `scripts/compat-test.sh`, only the same-encoding go→rust SUDP
path is covered — the mixed-codec routing at 2461–2490 is untested. A pure move is
still safe, but there is nothing to catch a mistake in the moved code.

Hazards to preserve exactly (from a read of the file):

- `head_scanner` reset must accompany **every** buffer replacement (163–178;
  sites 253/259/296/1395).
- `raw_head_fully_served` terminal malformed path (248–262).
- Filled-`ReadBuf`-then-`Pending` byte drop (989–1009, 1123–1136).
- Waker registration after a Ready inner read (1513–1522) and after discard
  (1149–1151).
- Manual `impl<R: Unpin> Unpin` (220–224) — the file contains **no** `unsafe`.
- `no_flush = try_tcp().is_some() && !use_enc` (1632) + conditional flush
  (1910–1916) — write timing is load-bearing for throughput.
- UDP partial-frame persistence via `read_fut` (1707–1739) and the
  biased-select idle arm **last** (1711–1756); 100 ms drain windows (1986–2003).
- SUDP Ping/Pong direction asymmetry (2959–2962 vs 3039–3048), 64-packet metrics
  batching (2928, 2995–3099), and `tokio::join!` rather than `select!` (3090).
- `StartWorkConn` double write+flush and the xtcp `NatHoleSid` ordering
  (3190–3239).

*Risk:* **medium-high for the pump, low for injector/udp/assign.** Do not
introduce a params struct for the four `#[allow(clippy::too_many_arguments)]` sites
(1591, 2068, 2429, 2855) in the same change as a move.

*Validation:* `scripts/compat-test.sh` **and** `scripts/protocol-matrix.sh` — the
latter is what catches "connects but bridges zero bytes", which is the failure mode
a botched injector or UDP move would produce. Plus `scripts/ab-matrix.sh` if
anything on the pump path is touched (a pure move should not be).

### P7 — `frp-server/src/vhost.rs` — the zero-risk win is its tests

`vhost.rs` was going to be listed as "leave alone", because its largest production
function (`handle_http1_request`) is only ~189 code lines and half the file is
tests. That was half right: the *production* code does not need urgent attention,
but there is a **free 3147-line reduction with zero production change** — and five
ranked seams after it.

**First step, and it is genuinely zero-risk:** move the inline
`#[cfg(test)] mod tests` (3164–6311, 3147 lines, 61 test functions) to
`frp-server/src/vhost/tests.rs`. Because `tests` stays a *child* of `vhost`,
`use super::*` still reaches every private item — **no visibility edits, no
production change**. `vhost.rs` drops from 6311 to ~3160 lines. Gate: the same 61
test names still run, plus clippy with `--all-targets`.

**A layout trap to know before touching this file.** `vhost.rs` declares
`#[path = "vhost_h2c.rs"] mod vhost_h2c;` (17–19) — so the `mod vhost_h2c` inside
`vhost.rs` and the sibling `frp-server/src/vhost_h2c.rs` are **the same file**, with
exactly one owner (a child module of `vhost`). Their entire cross-file contract is
three names: `resolve_vhost_request` / `VhostResolveError` (used at
`vhost_h2c.rs:43`) and `clamp_vhost_timeout` (149, 533). Consequently: create
`src/vhost/` for children and keep `vhost.rs` as the parent (edition 2021 resolves
`mod x;` in `vhost.rs` to `src/vhost/x.rs`). **Do not** rename `vhost.rs` to
`vhost/mod.rs` casually — the `#[path]` attribute would then resolve against
`src/vhost/` and break the build; that route requires moving `vhost_h2c.rs` in the
same commit.

Remaining seams, in order:

| Order | New module | Contents | Risk |
|---|---|---|---|
| 2 | `src/vhost/head.rs` | head parsing / request line / byte sets / basic-auth extraction / authority + host extraction (~640 lines, all pure `&str` → verdict/`&str`, no state, no IO) | low |
| 3 | `src/vhost/router.rs` | routing table: `VhostRoute`, `VhostRouteMatch`, `RouterConfigConflict`, `find_matching_route`, `get_locked`, `sort_by_longest_location`, `VhostTables`, `VhostManager` | low-medium |
| 4 | `src/vhost/forward.rs` | `resolve_vhost_request`, `VhostForward`, `VhostResolveError`, rewrite/inject (~560 lines) | low-medium |
| 5 | `src/vhost/https.rs` | HTTPS/SNI listener + not-TLS stub (**must move as a pair**), `read_client_hello_prefix`, `extract_sni_from_client_hello` | medium |

External re-export paths that must be preserved (each verified against a caller):
`extract_sni_from_client_hello` (`tests/vhost_https_sni.rs:125`),
`run_vhost_http_listener` / `run_vhost_https_listener` (`service.rs:660,685`),
`count_host_headers` (`tcpmux.rs:465`), `write_not_found_response`
(`tcpmux.rs:517,714`), `clamp_vhost_timeout` (`bridge.rs:3105`), `VhostManager`
(`state.rs:28`, `dashboard.rs`, `control/proxy.rs`, `proxy_ops.rs`).

**Do not split the orchestration core** (`serve_vhost_request`,
`handle_http1_request`, `run_vhost_http_listener`): `request_text` borrows
`pre_read` (925–933) while `pre_read` is *moved* at 1155, and the `wrap: impl
FnOnce` (831) is consumed once at 1209. Those lifetimes are the function.

Contract details a move must not disturb: the gate order (Malformed 983–987 →
duplicate-Host 400 at 1011–1015 → 505 at 1016–1036 → missing-Host 1050–1053 →
Detailed 1089–1097) is pinned byte-exactly by tests; header order is XFF 2788 →
XFH 2799 → XFP 2808 → configured 2815; error literals at 886/956/985/1013/1026/1051/1094.

One stale comment to ignore rather than honour: `vhost.rs:2932` claims
`canonicalize_authority` is shared with `vhost_h2c.rs`, but that file defines its
own `host_from_authority` (580–617) and never imports it. Do not promote it to a
shared API on that basis.

### P8 — `frp-server/src/ssh_gateway.rs` — already decomposed; the win is tests + `args.rs`

Unlike the others, this file's size is **not** a structure problem: 56 production
functions spread over ~10 independent concerns, and the largest is `run` at **310
code lines**. So it was going to be listed as "leave alone", and that is *half*
right — but [Step 0](#step-0--the-universal-first-move-file-ify-the-inline-tests)
applies here too (2129 test lines, 44% of the file), and there is one genuinely
clean seam.

| Order | New module | Moves | Notes |
|---|---|---|---|
| 0 | `ssh_gateway/tests.rs` | the inline test module (1992–3785, 1794 lines, 67 fns) | zero source-token change |
| 1 | `ssh_gateway/args.rs` | the whole 33–765 arg-parsing cluster (15 fns, `ParsedProxyArgs`, `FLAG_SPELLINGS`) + its parse tests | **cleanest seam in the file**: zero references to the rest of the module; deps are only `rand` and `frp_core::hex_encode` |
| 2 | `ssh_gateway/virtual_control.rs` | `VirtualControl` + `WorkConnRequest` + `channel` (783–911) | zero session/listener deps |
| 3 | `ssh_gateway/stream.rs` | `CloseableSshStream`, `CloseState`, `SshStreamCloser`, `terminate_ssh_session` | struct + its 4 trait impls must stay in one file |
| 4 | `ssh_gateway/keys.rs` | `parse_authorized_keys`, `parse_authorized_key_line`, `load_or_generate_host_key` | `#[cfg(unix)] PermissionsExt` and `Path` imports must travel |
| 5 | `ssh_gateway/frame.rs` | `build_v1_frame_from_args` + 5 helpers | single consumer |
| 6 | `ssh_gateway/bridge.rs` | `handle_work_conn_requests`, `bridge_ssh_side` | add the duplicated map type aliases here first |
| 7 | `ssh_gateway/session.rs` | `SshSession` + `impl Handler` (12 methods) + `write_text_and_close` | **last**; needs six `pub(super)` widenings for surviving tests |
| — | `preauth.rs` | 53 lines | **skip** unless `run` is edited anyway |

**Do not** split `impl Handler for SshSession` (1161–1755): one trait impl cannot
span files, and extracting the auth methods is a ~120-line body refactor with
medium risk around exact `Auth::Reject` shapes. **Do not** extract
`SshListener::run`'s accept loop either — 310 lines, but it is one per-connection
lifecycle (handshake timeout → auth wait → permit release → control-exit/idle
select → cleanup) where the teardown ordering is the point.

**The validation trap, and it matters more than the seams:** `scripts/compat-test.sh`
**does not exercise the SSH gateway at all** — its only "ssh" references are XTCP
VPS remote-key plumbing. A green compat run proves nothing here. The real nets are
`frp-server/tests/ssh_gateway.rs` (16 e2e tests) and the 79 in-file unit tests, so
those must be run *before and after* each step, not just a compile check.

*Risk:* low for steps 0–5, medium for 6–7. `run`'s body is the only place where
the "already decomposed" verdict is load-bearing.

### Not a target — `frp-server/src/handlers/`

`handlers/` is the *product* of an earlier successful split of the server's
connection dispatch (`dispatch.rs` 1568, `transport.rs` 2043). Its largest function
is 463 code lines and its concerns are already separated. Rearranging it would be
churn, not risk reduction.

## Validation strategy for any split

Every seam is a **pure move**. The bar:

1. **Byte-identical behaviour.** No logic edits, no reordering, no reworded error
   strings, no renamed log fields. Comments move *with* their code — in this
   codebase the comments are the specification.
2. `cargo fmt --all -- --check` and
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
3. `cargo test --workspace --all-features` **and** `cargo check
   --no-default-features --features tiny|micro` (mandatory for `service.rs`, with
   its 84 cfg gates).
4. `bash scripts/compat-test.sh` — the only hard compatibility evidence.
5. `bash scripts/protocol-matrix.sh` — catches data-plane breakage that compiles
   and connects fine.
   **But check what a gate actually covers before trusting it:** `compat-test.sh`
   does *not* exercise the SSH gateway (its only "ssh" hits are XTCP VPS remote-key
   plumbing), so for `ssh_gateway.rs` the relevant gates are
   `frp-server/tests/ssh_gateway.rs` and the in-file unit tests. Likewise
   `run_sudp_message_bridge` has no compat coverage for the mixed-codec path.
6. For `bridge.rs` seams: `scripts/ab-matrix.sh` if the move touches anything on
   the pump path. A pure file move should not, but verify rather than assume.
7. Prefer `git mv`-style moves that keep the diff *visibly* a move, so a reviewer
   can confirm nothing was rewritten. A split PR whose diff is not obviously
   mechanical should be rejected.

---

## What NOT to do

- **Do not split for line count.** The measurements above are the whole argument
  for the corrected priority; acting on the raw numbers would put effort in the
  wrong file.
- **Do not restructure the `select!` loops** in `service.rs::run_message_loop` or
  `frp-server/src/control/mod.rs`. Their fairness (deliberately no `biased;`) and
  the persisted-read-future trick are load-bearing and pinned by regression tests.
- **Do not split `bridge.rs::poll_read`.** 236 code lines in one state machine is
  appropriate.
- **Do not mix a move with a fix.** If a seam review turns up a real bug, that is a
  separate PR with its own compat evidence.
- **Do not extract tests and production code in the same commit.**

---

## Open decisions (need the maintainer)

1. **Is the `pub` surface deliberately minimal, or accidental?** Seams can stay
   crate-private, but only if nothing outside needs them today.
2. **`service.rs` seams: new `service/` subdirectory, or extend the existing flat
   modules** (`health.rs`, `reload.rs`)? Both work; the flat layout is the current
   convention and keeps `frp-client/src/*.rs` uniform, but a `service/` directory
   would signal that these are parts of one orchestrator.
3. **`visitor.rs` has almost no tests (165 lines for 3685 production lines).** Is
   adding coverage a prerequisite for splitting it, or is a pure move acceptable?
   I lean towards: pure move now, coverage as its own item.
4. ~~Worth automating?~~ **Done** — [`scripts/large-functions.sh`](../scripts/large-functions.sh)
   measures production LOC per file and the largest production functions by code
   lines. It is what found `frp-server/src/service.rs::run`. Keeping the numbers in
   prose would have repeated this repository's recurring mistake.

---

## Related

- [`../TODO.md`](../TODO.md) — the backlog item this plan discharges
- [`architecture.md`](architecture.md) — what these modules *do*
- [`developing.md`](developing.md#pre-release-checklist) — the gates a split must pass
- [`developing.md`](developing.md#what-a-green-test-run-does-and-does-not-prove) — why
  `compat-test.sh`, not the unit suite, is the evidence that matters here
