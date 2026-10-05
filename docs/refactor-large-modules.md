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
| 2 | `run_message_loop` | `frp-client/src/service.rs:2890` | 697 |
| 3 | `handle_new_proxy` | `frp-server/src/control/proxy_ops/mod.rs:1279` | 546 |
| 4 | `authenticate` | `frp-server/src/control/login.rs:617` | 510 |
| 5 | `run_visitor_listener` | `frp-client/src/visitor.rs:1141` | 502 |
| 6 | `spawn_work_conn` | `frp-client/src/work_conn.rs:1634` | 469 |
| 7 | `handle_tls_connection` | `frp-server/src/handlers/transport.rs:42` | 461 |
| 8 | `handle_nat_hole_visitor` | `frp-server/src/handlers/dispatch.rs:368` | 447 |
| 9 | `run_udp_work_conn` | `frp-client/src/work_conn.rs:754` | 418 |
| 10 | `handle_websocket_connection` | `frp-server/src/handlers/transport.rs:674` | 411 |

*This table is the plan-time snapshot (2026-09-17 at `9c84ada`). It is kept as written
because the argument rests on the ranking it forced; later seams move rows.
`authenticate` is now `frp-server/src/control/login.rs:254` (492 code lines) and ranks 5th —
see **P5**.*

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
bash scripts/large-functions.sh --all    # every classified file, test modules shown at 0
```

Every number in this document comes from that script, and the script is
**cross-checked against an independent line-by-line read** of the files (5
functions agree exactly). That check was necessary, because the tool was wrong
four times before it was right — each bug produced numbers that looked plausible:

1. A whole-file test module (`frp-core/src/config/tests.rs`) carries no
   `#[cfg(test)]` inside it — the attribute is on the `mod` that includes it — so
   it counted as **6005 lines of production code**. Fixed by excluding `tests.rs`
   and `tests/` directories.
2. Function size was "distance to the next `fn`", which charges intervening
   `struct`/`enum`/`const` definitions to the preceding function. It reported
   `health_check_monitored` (really **3** lines) as **434**, and a nested 19-line
   `record_plugin` as **212**. Fixed by brace-matching the body.
3. That brace matcher then treated Rust **lifetimes** (`'static`, `'a`) as char
   literals, swallowing everything to the next `'` and corrupting the brace count
   — `run` came out as 940 lines instead of 1642, and `frp-core`'s `debug_name`
   appeared as a 1042-line function.
4. An off-by-one: the end index is *just past* the closing brace, so an inclusive
   "is this line inside a test module" test dropped any function whose body ends
   on the line before a test module — which silently hid `authenticate`, the 4th
   largest function in the repository, from the ranking entirely.

None of these four would have been noticed without an independent read. That is
the argument for treating this document's tables as *generated*, and for
re-running the script before acting on them.

---

## Measurements

### Production vs inline tests

> **Measurement provenance.** Every figure in this section was measured on the
> pre-Step-0 single file `frp-server/src/control/proxy_ops.rs`, which is now the
> `frp-server/src/control/proxy_ops/` directory (Step 0, plus seams 1 and 2 —
> see the seam table below). Rows that name the directory carry those same
> pre-Step-0 counts unless noted. The Step 0 figures were re-measured at
> `a618f281` and corrected from the originally recorded `8044 / 4432 / 3612` to
> `8054 / 4444 / 3610`. **That boundary — production = every line before the
> first `#[cfg(test)]` — applies to the `proxy_ops` row only** (base lines
> 1–3610; head `mod.rs` lines 1–3040 — the script's per-file table reads that file
> at **3043** production, because the blank lines between the three
> `#[cfg(test)] mod X;` declaration blocks fall outside this boundary). The other
> rows were measured at earlier
> revisions on other files and do not all share it; PR #452's note under the
> Step 0 table states the convention those rows use (`Total` = `Inline tests`
> + `Production`).

| File | Total | Inline tests | **Production** |
|---|---:|---:|---:|
| `frp-client/src/service.rs` | 6382 | 1452 | **4930** |
| `frp-client/src/visitor.rs` | 3850 | 165 | **3685** |
| `frp-server/src/control/proxy_ops.rs` (pre-Step-0) | 8054 | 4444 | **3610** |
| `frp-server/src/control/bridge.rs` | 5445 | 2122 | **3323** |
| `frp-server/src/vhost.rs` | 6331 | 3151 ✅ | **3180** |
| `frp-server/src/dashboard.rs` | 3910 | 987 | 2923 |
| `frp-server/src/ssh_gateway.rs` | 4865 | 2123 | 2742 |
| `frp-core/src/auth.rs` | 3791 | 1924 | 1867 |

Note `frp-client/src/visitor.rs`: 2906 production lines with **959 lines of
tests** — the largest production-to-test ratio in the repository, and it is the
XTCP/STCP/SUDP/vnet data plane.

### Comment density in the largest functions

| Function | Total | Comments | **Code** | Code % |
|---|---:|---:|---:|---:|
| `run_message_loop` (`service.rs`) | 1109 | 412 | **697** | 63% |
| `handle_new_proxy` (`proxy_ops/mod.rs`) | 771 | 225 | **546** | 71% |
| `run_visitor_listener` (`visitor.rs`) | 631 | 129 | **502** | 80% |
| `register_proxies` (`service.rs`) | 594 | 200 | **394** | 66% |
| `reload_from_sources` (`service.rs`) | 503 | 153 | **350** | 70% |
| `run_udp_work_conn` (`control/bridge.rs`) | 415 | 124 | **291** | 70% |
| `poll_read` (`control/bridge.rs`) | 639 | **411** | **228** | **36%** |
| `handle_http1_request` (`vhost.rs`) | 469 | **291** | **178** | **38%** |

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
| `frp-server/src/control/proxy_ops/` | 47 | 112 | 3610 |
| `frp-server/src/vhost.rs` | 40 | 94 | 3180 |
| `frp-server/src/control/login.rs` | 40 | — | — |
| `frp-client/src/work_conn.rs` | 37 | 85 | — |
| `frp-server/src/control/bridge.rs` | 36 | 100 | 3323 |
| `frp-client/src/visitor.rs` | 31 | 85 | 3685 |

The `Production lines` column uses the same **pre-extraction** basis as the `Production`
column of the measurement table above (`Total` minus inline tests): `frp-server/src/vhost.rs`
therefore reads **3180** here while the file is now **3179** lines.

This **validates** the backlog's claim that defect-prone code clusters in these
files — and it is why the corrected priority is `service.rs`.

### Interface surface (good news for refactoring)

| File | functions | `pub` | pub % |
|---|---:|---:|---:|
| `frp-server/src/control/bridge.rs` | 94 | 2 | 2% |
| `frp-server/src/control/proxy_ops/` | 123 | 11 | 9% |
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
| `frp-server/src/control/proxy_ops/` | 14 |
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
#   #[cfg(test)] mod tcp_auto_bind_retry_tests;
```

This is **zero-risk and unusually high-yield**, because a file module and an
inline module have the *same module path* and the same `use super::*` semantics
(`super` is the parent either way). Nothing outside can tell the difference; the
only textual change is one level of de-indentation.

| File | Now | After | Reduction |
|---|---:|---:|---:|
| `frp-server/src/control/proxy_ops.rs` | 8054 | 3610 | **55%** |
| `frp-server/src/vhost.rs` | 6331 | **3179** | **50%** ✅ |
| `frp-server/src/control/bridge.rs` | 5445 | ~3320 | 39% |
| `frp-server/src/ssh_gateway.rs` | 4865 | ~2740 | 44% |
| `frp-client/src/service.rs` | 6382 | ~4930 | 23% |

Every row is measured on the **pre-extraction** file and follows the same convention as the other
rows: `Total` = `Inline tests` + `Production`. The `frp-server/src/vhost.rs` row was re-measured in
PR #452 (branch `refactor/fileify-vhost-tests`, code head `7ff46a60`, based on `f881d15e`, rebased
onto `18bcd1ad`): its base file was **6331** lines, not 6312, split into **3151** inline-test lines
(`vhost.rs:3180-6330`, the extracted body) and a **3180**-line remainder — 3178 production lines plus
the 2 module-scaffolding lines (`#[cfg(test)]`, `mod tests;`). The row is
**landed**: the body now lives formatted (3144 lines) in `frp-server/src/vhost/tests.rs` and
`frp-server/src/vhost.rs` is **3179** lines. See P7.

**Landed** (`refactor/fileify-proxy-ops`, PR #453, commit `aae3a484`): the base
file measured 8054 lines (not 8044); it split into
`frp-server/src/control/proxy_ops/mod.rs` (3618 lines) plus
`unregister_generation_tests.rs` (3790), `subdomain_conflict_tests.rs` (155) and
`tcp_auto_bind_retry_tests.rs` (430) — production lines 3610, i.e. the row above
was re-measured and the stale `8044 / 4432 / 3612` corrected to
`8054 / 4444 / 3610`. The same PR then landed seams 1 and 2, taking `mod.rs` to
3049 lines (3043 production, same boundary). Caveat at the time: `scripts/large-functions.sh`
treated the sibling test files as production once they were ordinary `.rs` files, so
`frp-server/src/control/proxy_ops/` had to be read as a whole rather than trusted per-file. That
is fixed now — the script classifies a whole-file test module (`tests.rs`, `*_tests.rs`,
`*_test.rs`, anything under a `tests/` directory) and a `#[cfg(test)] mod X;` sibling as test, and
charges the parent only for the declaration lines.

Two things make it more than cosmetic:

- It **shrinks the apparent problem to its real size**, so the remaining decisions
  are made against production code rather than test code.
- `proxy_ops/` and `vhost.rs` each hold a single 1800–3100-line interleaved test
  suite spanning many functions. Leaving those inline keeps every production edit
  surrounded by thousands of lines of tests, which is part of why these files are
  churned so heavily.

Constraints that make it safe:

- The test modules in `proxy_ops.rs` are referenced **by path** from seven other
  files (`crate::control::proxy_ops::unregister_generation_tests::{proxy_info,
  test_state}` — `metrics/prom.rs`, `dashboard.rs`, `handlers/dispatch.rs`,
  `control/bridge.rs`, `control/proxy.rs`, `control/mod.rs`, `control/pool.rs`).
  A `mod`-declaration-based file split preserves that path; moving the module
  *content* anywhere else breaks it. Declare, do not relocate.
- `unregister_generation_tests`'s nested `port_error_text_tests` uses
  `use super::super::*`; keeping it nested inside its parent module (rather than
  hoisting it to a top-level file) leaves that path resolving unchanged.
- **Measured (PR #453): no `pub(crate) use` re-export is needed.** A file module
  and an inline module have the same module path, so `err_msg`,
  `handle_new_proxy`, `unregister_control`,
  `release_udp_port_with_owner_check` and
  `remove_proxy_and_release_client_counts` keep resolving at their original
  visibility. `git diff --name-only` for `aae3a484` lists only the five
  `proxy_ops*` paths — no external referencing file was touched. (There is also an
  eighth production caller, `frp-server/src/service.rs:1678`
  `crate::control::proxy_ops::unregister_control(`, which resolves the same way.)
- Validation: `cargo test -p frp-server --lib -- --list` must report an identical
  test-name set; and the move must be visible in `git diff -M --name-only`.
  **Correction (PR #453):** do *not* require `git diff -M` to report the move as a
  rename — it does not. The `proxy_ops.rs` → `proxy_ops/mod.rs` pair measures
  **R041 (41%)** across `01fb93e3..HEAD` and **R049 (49%)** for the Step-0 commit
  alone, both below git's 50% default, so `--summary` reports `delete` + `create`
  (measured: `git diff -M1% --raw 01fb93e3 HEAD`). `--name-only` is the checkable
  form.
- **Correction to the "empty literal grep" hard check.** `git diff -U0 |
  grep -E '^[+-].*"'` **cannot** be empty for any file-to-file move: a move emits
  every relocated line as both a `-` and a `+`, so every relocated string literal
  appears twice. Calibrated on the already-merged pure move `771294a3` (PR #436):
  the count is 1520, unchanged under `-w -M -C --find-copies-harder`. The
  operative check is instead a **multiset of extracted string/char-literal
  VALUES** before vs after (0 changes), plus `cmp` of
  `rustfmt(dedent(original_body))` against the committed extracted file, with the
  raw grep count reported as-is.

---

## Recommendation

Ranked by *risk reduction per unit of disruption*, using the measurements above.

| Priority | Target | Why | Shape |
|---|---|---|---|
| **P0** | **File-ify the inline test modules** in all five files below | Zero production change, same module paths, ~40–55% line reduction in the worst files; see [Step 0](#step-0--the-universal-first-move-file-ify-the-inline-tests) | one commit per file |
| **P1** | `frp-server/src/service.rs::run` | Largest function in the repo at the plan's base (1291 code lines; **429** now); **a linear startup sequence**, so extraction is mechanical and low-risk; `handlers/` already sets the precedent for this exact kind of split | ~10 listener blocks → named methods |
| **P2** | `frp-client/src/service.rs` | #1 production file size (5108), #1 churn (53), #1 fix density (230), 106 cfg gates | 5 seams, ~1900 lines |
| **P3** | `frp-client/src/visitor.rs` | #2 production size (2906) and lightly tested (959 test lines) | 3–4 seams |
| **P4** | `frp-server/src/control/proxy_ops/` | `handle_new_proxy` 546 code lines; 2nd-highest fix density | 2–3 seams |
| **P5** | `frp-server/src/control/login.rs::authenticate` (492) and `frp-client/src/work_conn.rs` (`spawn_work_conn` 469, `run_udp_work_conn` 419) | Surfaced only by the measurement script; not on any file-size list | 1 seam each |
| **P6** | `frp-server/src/control/bridge.rs` | Hot data path, highest risk per line changed. Only the UDP family and the injector adapter clearly pay | 2 seams |
| **P7** | `frp-server/src/vhost.rs` | Not urgent for production, but **a 3151-line test extraction with zero production change**, then 4 low-risk seams | 1 free step + 4 seams |
| **P8** | `frp-server/src/ssh_gateway.rs` | Already decomposed (largest fn 310 code lines); the win is the test extraction plus `args.rs`, the cleanest seam in the repo | 1 free step + 6 seams |
| — | `frp-server/src/handlers/` | The product of an earlier successful split; largest fn 463 code lines | leave alone |

**Do one block per pull request.** Each is a pure move plus `mod`/`use` plumbing.

---

## Per-file analysis

### P1 — `frp-server/src/service.rs::run` (1291 code lines at the plan's base; **429** now) — do this first

`run` is not a tangled algorithm. It is a **linear startup sequence**: ~10
independent "if this port is configured, start that listener" blocks, three
one-shot background tasks, the main accept loop, and a graceful-drain tail. That
makes it the safest large-scale extraction available anywhere in this codebase —
far safer than `run_message_loop`, where `select!` fairness is load-bearing.

`service.rs` has only **10 production functions**; `run` is 1291 of its 2074 at the plan's base (**429** now)
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
| ~1485–1490 | Port-reservation pruner (calls `spawn_port_reservation_pruner` in `proxy_ops/`) | `service/tasks.rs` |
| ~1491–1558 | TLS cert hot-reload task | `service/tasks.rs` |
| ~1563–1603 | SIGINT/SIGTERM handler task | `service/tasks.rs` |
| ~1604–1768 | Stale-control reaper task | `service/tasks.rs` |
| ~1769–1908 | Main accept loop | **stays in `run`** |
| ~1909–1949 | Graceful drain + OIDC stop | **stays in `run`** |

**Landed from this table so far: every row that was going to move — all eight listener rows and all five task
rows. P1 is complete.** The WebSocket listener (#436), KCP (#450), QUIC (#481), dashboard server (#482), TCPMux
(#483), SSH tunnel gateway (#484), HTTP vhost listener (#485) and HTTPS vhost listener (#486) moved to
`service/listeners.rs`; the NAT-hole cleanup task (#487), the port-reservation pruner and the signal listener
(#488), and the TLS certificate hot-reload task and stale-control reaper (#489) opened and completed
`service/tasks.rs`. Of the table's rows, nothing movable is left in `run`: what remains there is exactly the two
`**stays in run**` rows (the main accept loop and the graceful drain + OIDC stop), which stay by design,
alongside the extracted seams' call sites and the startup preamble. Each landed seam has an entry under "Landed so far" below.

**Landed so far** (one block per PR, pure move, per the bar below):

- WebSocket listener → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_websocket_listener(&self, rate_limiter_enabled: bool)` — PR #436 at
  code head `0f1b94c2` (based on `13a29d26`): 289 payload lines byte-identical, and because no test
  had ever reached the dedicated port the move was shipped with
  `frp-server/tests/transport_e2e_websocket_port.rs` and the `websocket`-without-`kcp` CI lane. See
  the `TODO.md` progress paragraph.
- KCP listener → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_kcp_listener(&self, rate_limiter_enabled: bool)` — PR #450 at code head
  `88da2d38` (based on `f881d15e`): 501 payload lines / 44 390 bytes byte-identical, and
  `frp-server/src/service.rs` 2386 → 1886 lines. Unlike the WebSocket seam the KCP transport is
  already covered end to end (`scripts/protocol-matrix.sh`'s KCP rows and
  `scripts/compat-test.sh`'s KCP+TLS / KCP+tcpMux scenarios), so the move ships without a new test;
  `mod listeners` is now gated on `any(websocket, kcp)`. See the `TODO.md` progress paragraph.
- QUIC listener → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_quic_listener(&self, rate_limiter_enabled: bool)` — PR #481 at code head
  `df0cd9a7` (based on `bf952988`): payload `service.rs:844-1009` is **166 lines / 9503 bytes
  `cmp`-identical** (sha256 `5215d3e983cfa846227283089120738c29151ad8bdea04e4294e92549aaaf4f9`), and
  `frp-server/src/service.rs` 2266 → 2104. The convention was calibrated against the KCP entry above by
  re-extracting its payload (which reproduces the recorded 501 lines / 44 390 bytes / `349e49b2…`), so the
  landmark comment and the `#[cfg]` stay at the call site. Like KCP and unlike WebSocket the dedicated
  `quic_bind_port` path is already reached (six `scripts/compat-test.sh` QUIC scenarios,
  `scripts/protocol-matrix.sh`'s `quic` row, `frp-server/tests/transport_e2e_quic.rs`), so no new test; `mod
  listeners` is now gated on `any(websocket, kcp, quic)` and the `AsyncReadExt`/`RwLockExt` imports were
  narrowed so a `quic`-only build still compiles clean. See the `TODO.md` progress paragraph.
- Dashboard server → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_dashboard_listener(&self)` — PR #482 at code head `284b7431` (based on `48e547a9`):
  payload `service.rs:851-888` is **38 lines / 1650 bytes `cmp`-identical** (sha256
  `dc70b3124bfa4b4d28f2d6e8a01499a9e3028d1d9b38d991fb2172cabaae5f45`), and `frp-server/src/service.rs`
  2104 → 2075. The block never used `rate_limiter_enabled`, so the method takes `&self` alone; `mod listeners`
  is now gated on `any(websocket, kcp, quic, dashboard)` and the `Duration`/`tracing::warn`/`spawn_boxed`
  imports were narrowed to `any(websocket, kcp, quic)` (a `dashboard`-only build is the shape that proves it).
  The block is reached end to end — `frp-server/tests/dashboard_integration.rs` and `dashboard_v2_integration.rs`
  spawn the real `frps` binary with `[web_server] port` set through `Service::run` — so, like KCP and QUIC, no
  new test; the payload's non-empty-cert TLS branch stays unexercised. See the `TODO.md` progress paragraph.
- SSH tunnel gateway → `frp-server/src/service/listeners.rs`,
  `#[cfg(feature = "ssh")] pub(super) async fn start_ssh_tunnel_gateway(&self)` — PR #484 at code head
  `c23b5205` (based on `eede43dc`): payload `service.rs:803-826` is **24 lines / 1157 bytes
  `cmp`-identical** (sha256 `bee86663af2ec9de1ef285dfa831488a366daf6f165fd7602f4093690287ff4f`), and
  `frp-server/src/service.rs` 2054 → 2039. The block's `read_ok()` needed `RwLockExt`, which `listeners.rs`
  imported only under `all(tls, any(websocket, kcp))` — false for an `ssh`-only build — so that gate widened to
  `any(ssh, all(tls, any(websocket, kcp)))`, and `service.rs`'s own copy of the import had to be **retained**
  (`write_ok()` is still used there). Coverage: no new test — `frp-server/tests/ssh_gateway.rs` has 17 tests,
  13 of which set the gateway port through `Service::run`; the 70 in-file unit tests drive `SshListener`
  directly. See the `TODO.md` progress paragraph.
- HTTP vhost listener → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_http_vhost_listener(&self)` — PR #485 at code head `a9ca3bc1` (based on
  `2bb230ea`): payload `service.rs:761-779` is **19 lines / 886 bytes `cmp`-identical** (sha256
  `468d2d5e7b2de72c27fc5b59d8e9145fd3bed5aa4bbdbbf9e396823e1d0219c4`), and `frp-server/src/service.rs`
  2039 → 2027. No `#[cfg]` on the block and no gate or import change was needed (`mod listeners;` is already
  unconditional). The block is reached in process by 54 tests across seven files (`common::start_test_server`
  → `Service::run`; witness `frp-server/tests/vhost_http_timeout.rs:56`) and by nine `go-to-rust-http*` compat
  scenarios that start the release frps with `vhost_http_port` and assert the port is listening, so no new
  test; the HTTPS vhost listener is a separate block and is **not** claimed. See the `TODO.md` progress
  paragraph.
- HTTPS vhost listener → `frp-server/src/service/listeners.rs`,
  `pub(super) async fn start_https_vhost_listener(&self)` — PR #486 at code head `a6382daf` (based on
  `d3b0f418`): payload `service.rs:773-792` is **20 lines / 916 bytes `cmp`-identical** (sha256
  `89000dc0d04b1d512b0698e0bb49ce8c74f0630681bfcb68bab5f6d0274c01ec`), and `frp-server/src/service.rs`
  2027 → 2014. No `#[cfg]` and no gate/import change: the ungated call site is legal in every shape because
  `run_vhost_https_listener` has a same-signature `#[cfg(not(feature = "tls"))]` stub at `vhost.rs:1837`.
  Coverage: no new test — four in-process tests set the port through `Service::run` (witness
  `frp-server/tests/vhost_https_sni.rs:166`, plus `vhost_audit_fixes.rs:1656` with a real rustls handshake)
  and `scripts/compat-test.sh:5518` (`test_g2r_https`, Rust frps) is the only compat lane that reaches it
  (the other three readiness assertions — two of them the WSS scenarios — run the Go frps, and the matrix never sets
  `vhost_https_port`). This seam also **adds** one live cite (the `service.rs` module comment →
  `vhost.rs:1837`), so `checked` and `guard_cites`/`guard_cites_floor` moved 576 → 577 together. See the
  `TODO.md` progress paragraph.
- NAT-hole session cleanup task → **new module** `frp-server/src/service/tasks.rs`,
  `pub(super) fn spawn_nat_hole_cleanup_task(&self)` — PR #487 at code head `a687feed` (based on `e8d63b7c`):
  payload `service.rs:804-824` is **21 lines / 1070 bytes `cmp`-identical with no re-indent** (sha256
  `60e05ed0b27aca58125c80ed7e05c013b9dc65b744de47fb80ae7f6681f1da34`), and `frp-server/src/service.rs`
  2014 → 2000. The method is deliberately **sync**, not `async fn`: the block awaited nothing before its
  `tokio::spawn`, so an `async fn` would add an await point that never existed. `mod tasks;` is unconditional
  beside `mod listeners;` (both `self.state.xtcp` and `crate::nathole` exist in every shape); later gated tasks
  carry their own `#[cfg]`. One disclosed consequence: the moved block's `tracing` target becomes
  `frp_server::service::tasks` — verified safe empirically, because `frp-core/src/logging.rs::filter_from_env`
  builds a `tracing_subscriber::filter::Targets` (prefix matching) rather than an `EnvFilter`, and a live run
  with `RUST_LOG=frp_server::service=debug` still prints the moved record. Coverage: no test — every
  `Service::run` lane reaches the spawn but none observes an expiry (60 s cadence / 120 s expiry are
  hard-coded while the XTCP tests sleep ≤300 ms), and the effect is covered only by direct
  `expire_sessions`/`clean` unit calls; an expiry-observing lane needs an injectable clock, which is a
  behaviour change for the tasks program rather than this seam. See the `TODO.md` progress paragraph.
- Port-reservation pruner **and** signal listener → `frp-server/src/service/tasks.rs`,
  `pub(super) fn spawn_port_reservation_pruner_task(&self)` and
  `pub(super) fn spawn_signal_listener_task(&self)` — PR #488 at code head `7e0e1dbc` (based on `4aede41b`).
  Two blocks in one PR on purpose: the pruner is a 3-line call chain into `proxy_ops/`, so a dedicated PR would
  spend a full review cycle on a wrapper, and the signal listener is the same mechanism in the same module;
  each still carries its own `cmp`/sha256 proof, control-flow enumeration and coverage finding. Payloads:
  pruner `service.rs:814-816` = **3 lines / 119 bytes `cmp`-identical** (sha256
  `c3b2edfdb2af7258…`) and signal listener `service.rs:893-929` = **37 lines / 1551 bytes `cmp`-identical**
  (sha256 `3f678df37798fce8…`); `frp-server/src/service.rs` 2000 → 1969, `tasks.rs` 40 → 95. Both methods are
  **sync** (neither awaits before its spawn); both landmarks stay at their call sites; the one import delta is
  `use tracing::info;` in `tasks.rs` (the moved `info!` records need it in both cfg arms). The signal
  listener's `#[cfg(unix)]`/`#[cfg(not(unix))]` arms move with the block and `mod tasks;` stays unconditional;
  the never-compiled `not(unix)` arm was checked by swapping the gates (compiles clean under
  `RUSTFLAGS="-D warnings"`). Coverage: the signal listener keeps its existing lane
  (`frps/tests/cli_exit_codes.rs:743` via the `:625` helper's real `kill -TERM`), and the pruner's effect
  remains unreachable (the inner fn consumes the interval's first tick; 24 h expiry), so that gap stays
  recorded. One range cite that straddled the seam was re-anchored by content — `service.rs:890-922` →
  `:895-898` (the landmark + the new call; start fingerprint unchanged, only `fp_end` moved). Both reviewers
  judged that right, because the two citing sentences assert *where `run` spawns the SIGTERM task* rather than
  the task body. See the `TODO.md` progress paragraph.
- TLS certificate hot-reload task **and** stale-control reaper → `frp-server/src/service/tasks.rs`,
  `#[cfg(feature = "tls")] pub(super) fn spawn_tls_cert_reload_task(&self)` and
  `pub(super) fn spawn_stale_control_reaper_task(&self)` — PR #489 at code head `6f712517` (based on
  `8046d257`). The last two task rows, grouped for the same reason as #488. Payloads: TLS `service.rs:829-888`
  = **60 lines / 3240 bytes** (sha256 `1212488187a7bb70…`) whose body `tasks.rs:72-131` is identical to the base
  after the base's **uniform 4-space brace-level de-indent** (de-indented slice sha `adf2161648b32c02…`, joined
  with a trailing newline; the two reviewers' joined-slice shas differ only in join basis), and reaper
  `service.rs:904-1063` = **160 lines / 10273 bytes** (sha256 `1bad6d2ea5f48827…`), `cmp`-identical with **no**
  re-indent and including all 98 of its comment lines, which are the specification. Gating: the attribute moved
  from the braced block to **the method and its call site** (the SSH-seam convention), with the two TLS imports
  gated in `tasks.rs` and `mod tasks;` left unconditional; the reaper is ungated. Both directions were closed by
  mutation in review (removing A's method gate reds the no-`tls` shape; gating B's method gives `E0599` at its
  ungated call). `frp-server/src/service.rs` 1969 → 1758, `tasks.rs` 95 → 337, and `run` now holds only the
  accept loop and the graceful drain. Coverage: no test — both blocks' **effects** are unreachable (no lane
  swaps a cert/key after start or waits ≥60 s; `run_id_to_ctl_tx`/`ControlTx`/`is_closed` have zero occurrences
  in the test trees), so the gaps stay recorded. One cite **moved file** with the payload: the reaper's comment
  references `http.rs:97-101`, now a live cite from `tasks.rs:272` (retargeted to `http.rs:110-114` by PR #490,
  which corrected that cite as mis-aimed). See the `TODO.md` progress paragraph.

- Inline tests of `frp-server/src/control/bridge.rs` → `frp-server/src/control/bridge/tests.rs`
  (parent file kept, sibling module dir, as in the entry above) — PR #451 at code head `9f064385`
  (based on `01fb93e3`), commit `3b57e709`: 5449 → 3324 lines. Every body line is identical apart
  from one indent level (of the module's 2124 body lines, 1963 are de-indented exactly one level and
  161 stay byte-verbatim — 142 blank and 19 beginning inside a multi-line literal), so the 563
  extracted string/char literal values are identical before and after, and `-- --list` is the same 46
  `control::bridge::tests::*` names.
- Inline tests of `frp-server/src/ssh_gateway.rs` → `frp-server/src/ssh_gateway/tests.rs` (plus
  `key_tests.rs`, `virtual_ctrl_tests.rs`, `preauth_tests.rs`) — PR #451 at code head `9f064385`
  (based on `01fb93e3`), commit `9f064385`: 4864 → 2749 lines. Same invariants (of the four bodies'
  2111 lines, 1960 are de-indented exactly one level and 151 stay byte-verbatim — 141 blank and 10
  beginning inside a multi-line literal; 817 literal values unchanged; the same 70
  `ssh_gateway::*` names). **Plan correction:** the P8 Step-0 table lists only `ssh_gateway/tests.rs`
  (1992–3785, 1794 lines), but the ~2740 target stated for this file is its 2742 production lines, so
  all four inline modules moved in the one commit.

Recommended method: extract **one listener block at a time**, as an
`async fn start_kcp_listener(&self) -> Result<()>`-shaped method, starting with
KCP (largest) or WebSocket. No ordering change, no control-flow change, no error
text change — each block already binds its own port and spawns its own task.

*Risk:* **low** — no shared mutable state beyond `&self`/`AppState`, no cfg
entanglement in this file (a 427-line inline `#[cfg(test)]` region now), and the extraction is
verifiable by inspection of the diff.

*Validation:* `cargo clippy -D warnings`, `cargo test --workspace --all-features`,
`scripts/compat-test.sh` (KCP/QUIC/WS are all compat-covered),
`scripts/protocol-matrix.sh` (this is exactly the 11-row transport matrix — the WS
and KCP rows would catch a listener that stops starting), and the `health` CI job.

### P2 — `frp-client/src/service.rs` (5108 production lines, 34 production fns)

**The layout question is settled, and empirically.** A scratch crate was used to
verify the module rules rather than assume them:

- a **child** module (`frp-client/src/service/x.rs` declared as `mod x;` in
  `service.rs`) **can** read the parent's private fields and call its private
  methods;
- a **flat sibling** (a new top-level `service_registration.rs`) **cannot** —
  `E0603` — and would force ~60 `SessionCtx` fields plus ~20 `Service` fields to
  become `pub(crate)`.

So: use a `frp-client/src/service/` **directory of children** and **keep
`SessionCtx` and `Service` in `service.rs`**. This mirrors what `frp-server`
already does (`service.rs` + `control/*.rs` re-opening `impl Service`; see
`control/proxy_ops/mod.rs:2995`) — except the server's `AppState` fields happen to be
`pub` already, so that precedent does not cover the privacy point.

Corrected spans (the earlier table in this document used distance-to-next-`fn`,
which inflated several entries): `run_message_loop` 1109, `register_proxies` 594,
`reload_from_sources` 503, `run` 373, `spawn_session_tasks` 316,
`connect_and_login` 231 — and two entries were **badly** wrong:
`health_check_monitored` is **3** lines (not 434) and `record_plugin` is a nested
**19**-line fn (not 212).

| Order | New module | Moves | Risk |
|---|---|---|---|
| **S0** | `service/tests.rs` | the inline test module (5112–6855; measured: module 1743 lines, body 1741) + the two test-only imports (`tokio::sync::watch`, `crate::vnet::{register_vnet_tun, vnet_tun_cidr}`) | **very low** — no production *logic* change. **Two clauses of this row were falsified by PR #491**: the imports do **not** "become dead in the parent" (both are `#[cfg(all(feature = "vnet", test))]`, and a child's `use super::*;` marks the parent's import used — proved by a shape-identical probe *and* `cargo clippy -p frp-client --all-features --lib --tests -- -D warnings` rc 0 with them left behind), and moving them **is** a six-line production change, so "no production line changes" is wrong as written |
| S1 | `service/reload_apply.rs` | `request_reload`, `close_wire_name_for_reload`, `try_reload`, `reload_from_sources`, `filter_active_proxies`, `filter_active_visitors` — **measured at the pre-S1 base: 645 lines (six spans, each including its doc comment), 31 533 bytes**; the earlier `(4321–4823)` / `(~570 LOC)` figures were pre-S0 numbering *and* excluded the doc comments | low — **verified**: zero `tokio::spawn`, no `select!`, no `unsafe` in range; the phase-A/commit ordering in `reload_from_sources` (send the Close/New batch before resolving wire keys and committing plugin/health state, Step 7 last) is the thing to preserve. The `pub(crate) use reload_apply::{filter_active_proxies, filter_active_visitors}` is **mandatory and exactly sufficient**: those two free fns are the only items reached by an external *path* (`store.rs:592`) plus the parent's call sites; the other four are inherent `impl Service` methods, whose visibility is per-`fn`, so their method callers (`frpc/src/main.rs:702`, the reload tests) stay reachable without a re-export |
| S2 | `service/registration.rs` | the registration frame plumbing (511–693) + `register_proxies` (1798–2391, ~590 LOC) | low–medium — the response loop is a cancellation-sensitive state machine and the `Arc<Mutex<IoStream>>` → `Arc::try_unwrap` handoff is subtle, but a verbatim move changes neither |
| S3 | `service/message_loop.rs` | `run_message_loop` (2752–3860) + `SessionChannels`, `LoopExit`, `StunResult`, the retry statics (~1180 LOC) | medium — pure relocation; 4 vnet gates, 3 spawns and 5 `expect` sites must land unchanged |
| **S3b** | *(same file)* | **the arm bodies** of `run_message_loop`, one per PR — see below | medium each |
| S4 | `service/session.rs` | `run` (1166–1538), `connect_and_login`, `spawn_session_tasks`, `teardown_session`, `request_stop`, `shutdown_visitor_tasks`, `cancel_detached_tasks`, `spawn_admin_server` (~1500 LOC) | medium — load-bearing spawn order and a 5-step teardown |
| S5 | `service/health.rs` | `health_check_monitored` (3 lines), `spawn_health_checks`, `healthy_resets_error_count` (~100 LOC) | low — **lowest value; may be skipped** |

**Landed from this table so far:** **S0** (PR #491) — the inline test module is now `frp-client/src/service/tests.rs` (1742 lines), `service.rs` 6855 → 5107, with a de-indent census of 1640 exactly-one-level + 101 byte-verbatim (99 blank, 2 inside a backslash-continued literal) + 0 anything else, and four rustfmt re-joins (three token-preserving; one drops a trailing comma inside a generic, which is inert). `scripts/large-functions.sh` now reports `service.rs` 5106 production / 5108 total and the new `tests.rs` as a whole-file test module (0 / 1743 / 1743).

**S1** (PR #492) — `service/reload_apply.rs` (674 lines) holds the six reload/apply items (645 lines moved byte-for-byte, doc comments included; `service.rs` 5107 → 4467), with the parent's minimal `pub(crate) use` re-export and `checked` rising 577 → 579 because two cites became newly live (the new module comment's `store.rs:592` cite and a test comment's extended path), not because anything was dropped. `scripts/large-functions.sh`: `service.rs` 4466 production / 4468 total / 2 test; `reload_apply.rs` 675 / 675 / 0; `tests.rs` 0 / 1743 / 1743.

**S3b is the real answer for the repository's 2nd-largest function.**
`run_message_loop` is one `select!` state machine whose **loop skeleton must stay**
(persisted partial-frame read, persistent heartbeat timer, deliberately no
`biased;` — all pinned by `partial_frame_survives_competing_ping_tick.rs`). But its
**arm bodies are separable**, and this was verified rather than assumed:
`tokio::select!` ends the polling scope before running handlers (tokio 1.53.1
`src/macros/select.rs:638–749`, "Create a scope to separate polling from handling
the output"), so a handler may take `&mut SessionCtx`; and each inbound arm is
terminal, so its `continue` becomes a plain `return`.

| Arm (lines) | LOC | Coupling to pass |
|---|---:|---|
| `CloseProxy` 2956–3071 | 116 | `&SessionCtx`, `proxy_info_map`, `health_cancels`, `p2p_bridge_tokens`, vnet fields, `plugin_handles`, writer |
| proxy retry tick 3422–3551 | 130 | `&mut SessionCtx` (`waitstart_seen`), `&mut last_start_err`, `proxies`, `cfg`, `proxy_info_map`, writer |
| ping tick 3335–3420 | 86 | `&mut SessionCtx` (ping fields, scopes, `v2`), `oidc_client`, `auth_cfg`, writer |
| XTCP notify → STUN 3631–3733 | 103 | `xtcp_sockets`, `stun_result_tx`, `nat_hole_stun_server`; spawns |
| health event 3553–3613 | 61 | `p2p_bridge_tokens`, `proxy_info_map`, `health_proxy_configs`, `v2`, `cfg_user`, writer |
| `NewProxyResp` 3142–3183 | 42 | `proxy_info_map` + `&mut last_start_err` |
| `NatHoleResp` 3103–3141 | 39 | `&mut pending_xtcp`, `xtcp_sockets`, `&mut visitor_pending`, `p2p_bridge_tokens`, writer |
| visitor request 3792–3826 | 35 | `&mut visitor_pending`, `xtcp_cleanup_tx`, `v2`, writer; spawns |
| STUN result 3737–3767 | 31 | `&mut pending_xtcp`, `xtcp_sockets`, `stun_result_rx`, writer; spawns |
| `NatHoleClient` 3081–3102 | 22 | `punch_proxy_still_live`, `p2p_bridge_tokens`, `session_alive`, writer |
| vnet trio 3184–3324 | 141 | `cfg`, `vnet_controller`, `vnet_tun_names`, `vnet_peer_routes`, `vnet_tun_tx`; 3 gates |
| `xtcp_cleanup` 3775–3787 | 13 | `&mut pending_xtcp`, `&mut visitor_pending`, `xtcp_cleanup_rx` |

Order: `CloseProxy` → retry → ping → STUN spawn → health → `NewProxyResp` →
`NatHoleResp` → visitor → STUN result → `NatHoleClient` → vnet trio. Leave the
3–11-line arms inline. **Handlers must be `.await`ed inline, never spawned** — the
retry arm's own comment records that "both locks' writers run only in this
message-loop task", which holds only while that is true.

**Do not split** the `select!` skeleton or its two persisted futures; the
registration response loop inside `register_proxies` (1960–2355, one
cancellation-sensitive state machine); `ControlWriter` (60 lines, imported by
`vnet.rs` and `nat_hole.rs`); the nested `record_plugin`; `with_unsafe_features`
(a 363-line linear constructor and the densest cfg area, 16 gates). Do not create
a `util.rs` grab-bag — move each helper with its primary caller.

Hazards beyond the layout rule: three literal `SessionCtx` constructions in the
tests (~150 lines) mean the struct must stay put; `ctx.control_rx.is_none()` doubles
as the "writer task active" probe (do not reorder the take); `spawn_session_tasks`
and `teardown_session` have load-bearing spawn/teardown order; **84
`cfg(feature)` sites** mean `cargo check -p frp-client --no-default-features
--features tiny|micro` is mandatory per seam; and the error/`expect` text is
contract (27 `expect` sites listed in the analysis). No `unsafe` in the file.

### P3 — `frp-client/src/visitor.rs` (2906 production lines, 36 production fns, 959 test lines)

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

### P4 — `frp-server/src/control/proxy_ops/` (3610 production lines at base, 34 production fns)

At base, production code was lines 1–3610 and the remaining 4444 lines were inline
tests. **Step 0 landed in PR #453** (`aae3a484`): `proxy_ops.rs` (8054 lines) became
`proxy_ops/mod.rs` (3618) plus three sibling test files, taking the production file
to 3610 lines with no logic and no path change. Re-measured figures are
8054 / 4444 / 3610 (same boundary as the provenance note above) — not the originally
recorded 8044 / 4432 / 3612. Seams 1 and 2 then landed as `92a454b3` and
`a618f281`, taking `mod.rs` to 3049 lines (3043 production).

Two structural facts dominate everything after that:

**(a) Path-preserving is mandatory and cheap.** Seven files reach into
`proxy_ops::` by path — five production importers (`err_msg`, `handle_new_proxy`,
`unregister_control`, `release_udp_port_with_owner_check`,
`remove_proxy_and_release_client_counts`) and seven test importers of
`crate::control::proxy_ops::unregister_generation_tests::{proxy_info, test_state}`
(there is also an eighth production caller, `frp-server/src/service.rs:1678`
`crate::control::proxy_ops::unregister_control(`). Converting the file to a
directory keeps **every external path byte-identical** *without* any
`pub(crate) use` re-export: a file module and an inline module have the same module
path, so the originals' visibility carries over unchanged. Measured in PR #453 —
`git diff --name-only` for `aae3a484` lists only the five `proxy_ops*` paths.

**(b) No `AppState` field is private** (only the three group controllers are
`pub(crate)`), so **no field-visibility change is needed for any seam**. There is
no `unsafe` in the file.

Seams, in the order they should be attempted (line numbers for the remaining rows
are current `mod.rs` positions at `a618f281`):

| Order | New module | Moves | Risk |
|---|---|---|---|
| 0 | *(directory + test modules)* — **landed `aae3a484`** | see Step 0: `mod.rs` + `unregister_generation_tests.rs`, `subdomain_conflict_tests.rs`, `tcp_auto_bind_retry_tests.rs` | **lowest** |
| 1 | `proxy_ops/validate.rs` — **landed `92a454b3`** | `validate_new_proxy` (was 891–961, pure), `duplicate_domain` (was 68–77) + its test module (now `validate/subdomain_conflict_tests.rs`) | low — zero `AppState` coupling, self-testing |
| 2 | `proxy_ops/vhost.rs` — **landed `a618f281`** | `register_http_vhost` (was 968–1213), `register_https_vhost` (was 1221–1441) | low — already fully extracted; no test region references them |
| 3 | `proxy_ops/tcp_group.rs` | `tcp_group_listener` (`mod.rs:2703–2856`), `handle_tcp_group_member_registration` (`mod.rs:2867–2977`) | low — leaves, owned args |
| 4 | `proxy_ops/registry.rs` | `build_proxy_info` (`mod.rs:404`), `register_sk_index` (`mod.rs:483`), `register_proxy_entry` (`mod.rs:784–871`), the three `rollback_*` (`mod.rs:502`, `710`, `731`, `753`), `remove_proxy_and_release_client_counts` (`mod.rs:679–699`) | medium-low |
| 5 | `proxy_ops/ports.rs` | `PortError`, `allocate_proxy_port` (`mod.rs:161–399`), the rollback/free helpers, the reservation pruner + its `impl AppState` (`mod.rs:2984`, `2995`) | medium-low |
| 6 | `proxy_ops/teardown.rs` | `unregister_control` (`mod.rs:2299–2692`) — one function, 394 lines | medium |
| 7 | `proxy_ops/listener.rs` | `bind_proxy_listener` (`mod.rs:2058–2080`), `bind_tcp_proxy_with_retry` (`mod.rs:2114–2205`), `setup_proxy_listeners` (`mod.rs:886–1269`), `listen_and_proxy` (`mod.rs:2211–2289`) | medium — largest move, 13-arg interface |
| 8 | `proxy_ops/tcpmux.rs` | the inline tcpmux arm (was 2267–2546, 276 lines) inside `handle_new_proxy` (`mod.rs:1279–2049`) | **medium — the only seam that rewrites control flow** |

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

### P5 — `frp-server/src/control/login.rs::authenticate` (492) and `frp-client/src/work_conn.rs`

Neither file appears on a file-size ranking, yet each holds a function in the
repository's top ten by code size:

- `authenticate` (`frp-server/src/control/login.rs:254`, 492 code lines; 510 before the
  auth-method seam landed) — the login handshake and every
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

**Landed so far (server half — PR #454 at code head `7d95d267`, based on `18bcd1ad`; rebased from
`f881d15e`, code commit patch-identical under `git range-diff`):** the auth-method split, stated
precisely — the base **already** had `verify_login_auth` (base `frp-server/src/control/login.rs:245-588`,
called from `authenticate` at base `:944`) and `throttled_login_error` (base `:210-228`) as sibling
functions, so this seam (a) moves those two pre-existing siblings into child modules of the parent file —
the same parent-file + child-module layout as the landed `frp-server/src/service/listeners.rs` seam, not
`mod.rs`: `frp-server/src/control/login/throttle.rs` (`pub(super) async fn pre_auth_throttle_gate`,
`pub(super) async fn throttled_login_error`) and `frp-server/src/control/login/auth.rs`
(`pub(super) async fn verify_login_auth` plus `verify_oidc_login` / `verify_token_login` /
`check_token_replay`); (b) extracts the 32-line pre-auth throttle gate out of `authenticate`; and
(c) splits `verify_login_auth`'s inline `if/else if/else` dispatch into three early-returning functions
— **(c) is restructuring, not a verbatim move**, backed by behaviour-preservation evidence rather than
token identity. `authenticate` stays the ordered orchestrator at 510 → 492 code lines (838 → 811 total),
`frp-server/src/control/login.rs:645` → `:254`; the file 3361 → 2943 lines. Purity holds for the moved
arms: literal multiset 359 == 321 + 32 + 6 with an empty residual, no old token missing from the new
files, and strictly-increasing order markers (see the `TODO.md` progress paragraph). The ordering
invariants are pinned by no test yet and are filed as a new item. The client half
(`frp-client/src/work_conn.rs`) is untouched.

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
but there is a **free 3151-line reduction with zero production change** — and five
ranked seams after it.

**First step — landed (PR #452, branch `refactor/fileify-vhost-tests`, code head `7ff46a60`, based
on `f881d15e`, rebased onto `18bcd1ad`):** move the inline `#[cfg(test)] mod tests` to
`frp-server/src/vhost/tests.rs`. At the base that body was `vhost.rs:3180-6330` — **3151 lines**,
measured as `git show f881d15e:frp-server/src/vhost.rs | sed -n '3180,6330p' | wc -l` — carrying 61
test functions, and the file measured 6331 lines, not 6311; the committed extraction is a uniform
4-space dedent plus stock `cargo fmt` (`rustfmt --edition 2021` on the dedented body is
`cmp`-identical to the new file, zero hand edits), and `vhost.rs` is now **3179** lines. Because
`tests` stays a *child* of `vhost`, `use super::*` still reaches every private item — **no visibility
edits, no production change**. Gate, verified: the same 765 `-- --list` names (61 under
`vhost::tests::`) still run, clippy `--all-targets` is clean, and `vhost.rs:1-3177` is byte-identical
to base with `mod tests;` its only added production line.

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
`extract_sni_from_client_hello` (`tests/vhost_https_sni.rs:160` — the only call; the old cite's line is now a config field),
`run_vhost_http_listener` / `run_vhost_https_listener` (`frp-server/src/service/listeners.rs:1109,1132` — the callers moved there with the M-15/M-16 seams),
`count_host_headers` (`tcpmux.rs:465`), `write_not_found_response`
(`tcpmux.rs:517,714`), `clamp_vhost_timeout` (`bridge.rs:3105`), `VhostManager`
(`state.rs:28`, `dashboard.rs`, `control/proxy.rs`, `proxy_ops/`).

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
applied here too — PR #451 moved the inline tests out, and the stand-alone test target is now 1257 lines — and there is one genuinely
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
**covers only the SSH gateway's banner and auth-rejection surface, not the gateway's full behaviour.**
An earlier revision of this section said compat "does not exercise the SSH gateway at all";
that was measured false in the M-14 round — `test_ssh_gateway_banner`
(`scripts/compat-test.sh:7871`) and `test_ssh_gateway_auth_rejection` (`:7933`) both write a
**Rust** frps config, append `[ssh_tunnel_gateway] bind_port = <port>` and launch `$RUST_FRPS`,
so they do reach the gateway through `Service::run` (both registered at `:8140-8141` and both
passing). The third scenario, `test_ssh_gateway_go_frps_compat` (`:8001`), launches the **Go**
frps and proves nothing about this side. `scripts/protocol-matrix.sh` has zero `ssh`
references. The real nets are `frp-server/tests/ssh_gateway.rs` (**17** e2e tests, **13** of
which set `ssh_tunnel_gateway.bind_port` via `ssh_test_config`) and the **70** in-file unit
tests under `frp-server/src/ssh_gateway/` (`tests.rs` 62 + `key_tests.rs` 3 + `preauth_tests.rs`
2 + `virtual_ctrl_tests.rs` 3 — note they drive `SshListener` directly, not `Service::run`), so
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
   its 35 `#[cfg]` attributes now).
4. `bash scripts/compat-test.sh` — the only hard compatibility evidence.
5. `bash scripts/protocol-matrix.sh` — catches data-plane breakage that compiles
   and connects fine.
   **But check what a gate actually covers before trusting it:** `compat-test.sh`
   covers only the SSH gateway's banner and auth-rejection surface
   (`scripts/compat-test.sh:7871` and `:7933`, both Rust-frps; the `:8001` scenario is
   Go-frps), so the decisive gates are `frp-server/tests/ssh_gateway.rs` (17 tests, 13
   through `Service::run`) and the 70 in-file unit tests under `frp-server/src/ssh_gateway/`. Likewise
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
2. ~~`service.rs` seams: `service/` subdirectory, or flat sibling modules?~~
   **Settled by evidence, not preference.** Only a `service/` **child** module can
   reach the parent's private fields; a flat sibling gets `E0603` and would force
   ~80 field-visibility widenings. So: `frp-client/src/service/` children, with
   `SessionCtx`/`Service` staying in `service.rs`. (Verified in a scratch crate —
   see P2.)
3. **`visitor.rs` has few tests (959 test lines for 2906 production lines).** Is
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
