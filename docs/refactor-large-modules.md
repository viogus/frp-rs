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
| 3 | `handle_new_proxy` | `frp-server/src/control/proxy_ops/mod.rs:122` | 546 |
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
`control/proxy_ops/ports.rs:479`) — except the server's `AppState` fields happen to be
`pub` already, so that precedent does not cover the privacy point.

Corrected spans (the earlier table in this document used distance-to-next-`fn`,
which inflated several entries): `run_message_loop` 1109, `register_proxies` 594,
`reload_from_sources` 503, `run` 373, `spawn_session_tasks` 322 (334 with its 12-line doc block — the earlier 316 was stale),
`connect_and_login` 231 — and two entries were **badly** wrong:
`health_check_monitored` is **3** lines (not 434) and `record_plugin` is a nested
**19**-line fn (not 212).

| Order | New module | Moves | Risk |
|---|---|---|---|
| **S0** | `service/tests.rs` | the inline test module (5112–6855; measured: module 1743 lines, body 1741) + the two test-only imports (`tokio::sync::watch`, `crate::vnet::{register_vnet_tun, vnet_tun_cidr}`) | **very low** — no production *logic* change. **Two clauses of this row were falsified by PR #491**: the imports do **not** "become dead in the parent" (both are `#[cfg(all(feature = "vnet", test))]`, and a child's `use super::*;` marks the parent's import used — proved by a shape-identical probe *and* `cargo clippy -p frp-client --all-features --lib --tests -- -D warnings` rc 0 with them left behind), and moving them **is** a six-line production change, so "no production line changes" is wrong as written |
| S1 | `service/reload_apply.rs` | `request_reload`, `close_wire_name_for_reload`, `try_reload`, `reload_from_sources`, `filter_active_proxies`, `filter_active_visitors` — **measured at the pre-S1 base: 645 lines (six spans, each including its doc comment), 31 533 bytes**; the earlier `(4321–4823)` / `(~570 LOC)` figures came from an older revision's line numbering (`reload_from_sources` sits at 4471 pre-S0 and 4465/4466 after it — never 4321) and from the classifier's doc-comment-excluding body count (the span's width, 503, *is* that body count) | low — **verified**: zero `tokio::spawn`, no `select!`, no `unsafe` in range; the phase-A/commit ordering in `reload_from_sources` (send the Close/New batch before resolving wire keys and committing plugin/health state, Step 7 last) is the thing to preserve. The `pub(crate) use reload_apply::{filter_active_proxies, filter_active_visitors}` is **mandatory and exactly sufficient**: those two free fns are the only items reached by an external *path* (`store.rs:592`) plus the parent's call sites; the other four are inherent `impl Service` methods, whose visibility is per-`fn`, so their method callers (`frpc/src/main.rs:702`, the reload tests) stay reachable without a re-export |
| S2 | `service/registration.rs` | the registration frame plumbing + `register_proxies` — **measured at the pre-S2 base: the coherent plumbing block is `:505-688` (184 lines / 8531 bytes, `006b1698…`; the earlier `511–693` span was one line short of `reg_frame_payload_read`'s closing brace) and `register_proxies` is `:1874-2480` = 607 lines / 35 848 bytes including its 13-line doc comment (594 / 34 943 without it, which is why the old `~590 LOC` was close) | low–medium — the response loop is a cancellation-sensitive state machine and the `Arc<Mutex<IoStream>>` → `Arc::try_unwrap` handoff is subtle, but a verbatim move changes neither |
| S3 | `service/message_loop.rs` | `run_message_loop` + `SessionChannels`, `LoopExit`, `StunResult`, `PROXY_RETRY_INTERVAL`, `WAIT_START_RETRY_TIMEOUT` and the `const PROXY_RETRY_GRACE` — **measured at the pre-S3 base: `run_message_loop` is `:2055-3163` (1109 lines / 68 389 bytes, `17ab1908…`; the row's `2752–3860` had the same 1109-line width but an older revision's numbering — the loop starts at 2890 pre-S0, 2847 after S1 and 2055 after S2, so 2752 matches none of them) and the moved plumbing block is `:172-234`, so the moved span is 1181 lines, of which 1175 are byte-identical carry-over and 11 are retokenised visibility lines — the row's `~1180 LOC` corroborated**. **Two corrections from the landed seam:** `REGISTRATION_RESPONSE_TIMEOUT` does **not** move (zero references inside the moved span; all five production references are in `registration.rs`, the phase it bounds), and **`PING_FIRST_BACKOFF` stays** because it is `pub const` API — `frp-client/tests/heartbeat_wire_order.rs` imports `frp_client::service::PING_FIRST_BACKOFF`, so moving it would break a published path | medium — pure relocation; 4 vnet gates ✓, 3 spawns ✓ and **7** `expect` sites (the row said 5; measured on seven distinct lines) must land unchanged |
| **S3b** | *(same file)* | **the arm bodies** of `run_message_loop`, in **five grouped PRs** (A–D2 below) — the earlier
"one per PR" was a pre-arm-1 risk guess; see the regrouping note | medium per group |
| S4 | `service/session.rs` | `run`, `connect_and_login`, `spawn_session_tasks`, `teardown_session`, `request_stop`, `shutdown_visitor_tasks`, `cancel_detached_tasks`, `spawn_admin_server` — **measured at the pre-S4 base: 1313 lines / 66 103 bytes (66 029 characters) with doc comments and attributes, or 1264 lines fn-only, so the row's `~1500 LOC` was overstated by 12–16%; **the spans are an older revision's numbering** — measured, `run` starts at 1298 pre-S0, 1255 at the S1 head and 1007 at the pre-S4 base, so the row's `(1166–1538)` matches none of them**. `spawn_admin_server`'s coherent span **includes** the `#[cfg(feature = "admin")]` attribute directly above it (a gate-less slice compiles the axum admin server into every build) | medium — **both risk claims verified by measurement, not repeated**: the teardown really is 5 steps (five `// Step N:` comments, ascending, no gaps) and the spawn order is load-bearing (writer task, then the vnet controllers whose route adverts ride the writer channel, then previous-session visitor shutdown, then the vnet visitor listener, then the STCP/XTCP listener) |
| S5 | `service/health.rs` | `health_check_monitored`, `spawn_health_checks`, `healthy_resets_error_count` — **measured: 136 lines / 6380 bytes (6368 characters) with doc comments, or 107 lines fn-only, so `~100 LOC` was close** | low — **not skipped: done in S4's PR** (#495), because folding it in cost one cycle instead of an author + two reviews + records cycle of its own; each module still carried its own per-item proofs and reference audit |

**Landed from this table so far:** **S0** (PR #491) — the inline test module is now `frp-client/src/service/tests.rs` (1742 lines), `service.rs` 6855 → 5107, with a de-indent census of 1640 exactly-one-level + 101 byte-verbatim (99 blank, 2 inside a backslash-continued literal) + 0 anything else, and four rustfmt re-joins (three token-preserving; one drops a trailing comma inside a generic, which is inert). `scripts/large-functions.sh` now reports `service.rs` 5106 production / 5108 total and the new `tests.rs` as a whole-file test module (0 / 1743 / 1743).

**S1** (PR #492) — `service/reload_apply.rs` (674 lines) holds the six reload/apply items (645 lines moved byte-for-byte, doc comments included; `service.rs` 5107 → 4467), with the parent's minimal `pub(crate) use` re-export and `checked` rising 577 → 579 because two cites became newly live (the new module comment's `store.rs:592` cite and a test comment's extended path), not because anything was dropped. `scripts/large-functions.sh` prints `service.rs` 4466 production / 4468 total / 2 test; it classifies `reload_apply.rs` as 675 / 675 / 0 and the new `tests.rs` as a whole-file test module (0 production, hence absent from the printed table; 1743 total).

**S4+S5** (PR #495, grouped) — `service/session.rs` (1363 lines) and `service/health.rs` (166 lines) hold the session and health paths; across 1449 moved lines the **entire** delta is **five `pub(super)` tokens plus one rustfmt signature reflow** (adding `pub(super) ` pushed `shutdown_visitor_tasks`' signature past 100 columns). This is the seam that needed a *new* tool rather than a re-export: `health_check_monitored` and `healthy_resets_error_count` are free functions with **unqualified** callers in `service.rs`, `session.rs`, `registration.rs`, `reload_apply.rs` and the test module, so the parent gained a **private** `use health::{…};` — a private `use` is visible to `service` and its descendants, i.e. exactly the original reach (probe-confirmed: deleting it fails with four `E0425`s), and nothing outside `service` names any of the eleven items. `service.rs` 2512 → **1072**. **With S3b excepted this closes the plan's P2 table**; the 1072 remaining lines are the deliberately-retained glue (`SessionCtx`, `Service` and their `impl`s, plus helpers).

**S3b, first arm** (PR #498, `CloseProxy`) — the arm body (base `:314-429` = 116 lines / 7032 bytes,
`1e869a6d…`) became one `.await`ed call to a private `handle_close_proxy`; the extracted body is identical to
the de-indented original apart from a whitespace-only `matches!` reflow, `continue;` → `return;` (sound: nothing
follows the `select!` inside the loop) and one dropped `&` at the `remove_vnet_tun` writer argument
(type-exact, since the parameter is already `&Arc<…>`; the `needless_borrow` explanation did not reproduce — see below). Skeleton invariants unchanged (4 vnet gates, 3 `tokio::spawn`, 7 `.expect(`, no
`biased;` in code), and twelve `heartbeat_wire_order.rs` cites were re-pointed with every header pin identical.
**13 arms remain across 11 rows**, in five groups and in the order the table gives.

**S3** (PR #494) — `service/message_loop.rs` (1219 lines) holds `run_message_loop` plus its three companion types and three retry items; across 1181 moved lines the **only** delta is **eleven `pub(super)` tokens** (the method; the three types; and `SessionChannels`' seven fields, which the parent's field-named literal requires — found by compilation, `E0451`). A plain `use message_loop::{…}` suffices; no re-export was needed. The loop skeleton is byte-identical (persisted partial-frame read, one persistent heartbeat `Sleep` re-armed at the loop top, no `biased;` — the third is why `frp-client/tests/partial_frame_survives_competing_ping_tick.rs`, unchanged by this seam, still witnesses the invariants from the child module), and **S3b did not happen** (the new file declares exactly one `fn`). `service.rs` 3681 → 2512.

**S2** (PR #493) — `service/registration.rs` (815 lines) holds the registration frame plumbing (base `service.rs:505-688`, byte-identical) and `register_proxies` (base `:1874-2480`), the latter identical **except one visibility token**: `pub(super)` was required because its only callers are the parent (`service.rs:1300`) and the sibling `service/tests.rs:930`, and a private item is `E0624` from both (probe-confirmed). **No re-export was needed** — unlike S1, all seven moved names are referenced only inside the moved text (verified by full-tree search in both review rounds). `service.rs` 4467 → 3681. The stray-guard region was a verified **no-op** in the code commit (no `.sh` file changed and no cite inside it moved) — the first such cascade since the region mechanism was understood — while the records commit that followed did re-bake it, because its cite re-points included lines inside the region.

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
| ~~`CloseProxy`~~ **landed** (PR #498) | 116 | **`&mut SessionCtx` — not `&SessionCtx`** (see the correction below), `proxy_info_map`, `health_cancels`, `p2p_bridge_tokens`, the seven vnet fields, `plugin_handles`, writer, **plus `self.cfg`** (which this row omitted; read once in the vnet teardown) |
| ~~proxy retry tick~~ **landed** (PR #503) | 130 | base `:444-573` / 8103 B / `f1daa5a5…` → `handle_proxy_retry_tick_arm` (`:1313-1437`), call `:367-374` **8L/305B/`413e1954…`**; coupling `&mut SessionCtx` (`waitstart_seen`), `&mut last_start_err`, `&self` for `proxies`/`cfg`/`proxy_info_map`, `writer` |
| ~~ping tick~~ **landed** (PR #503) | 86 | base `:357-442` / 4982 B / `85979b12…` → `handle_ping_tick_arm` (`:1207-1283`), call `:357-366` 10L/367B/`2dd834a5…`; **this arm held the program's last `continue;`** (base `:427` → `:1269`); coupling `&mut SessionCtx` (ping fields, scopes, `v2`), `oidc_client`, `auth_cfg`, `writer` |
| ~~XTCP notify → STUN~~ **landed** (PR #504) | 103 | base `:453-555` / 6464 B / `9d751b69…` → `handle_xtcp_notify_arm` (`:1335-1449`), call `:453-456` 4L/165B/`f7aae8af…`; coupling `&mut SessionCtx` (`xtcp_sockets`), `stun_result_tx`, `nat_hole_stun_server`; **spawns 1** (off-loop STUN, write handed back on `stun_result_tx`) |
| ~~health event~~ **landed** (PR #505) | 61 | base `:375-435` / 4154 B / `708b6b21…` → `handle_health_event_arm` (`:1506-1575`), call `:375-378` 4L/157B/`3139a0e2…`; 2 rustfmt reflows only (tokens 633 = 633); **reaches state through `&self`** (5 uses / 3 fields: `p2p_bridge_tokens`, `proxy_info_map`×2, `health_proxy_configs`), so the M-31 correction applies **here**; **carries the lock-order obligation** — it takes `p2p_bridge_tokens` then writes `proxy_info_map`, the inverse of `handle_close_proxy`, so it must stay inline |
| ~~`NewProxyResp`~~ **landed** (PR #501) | 42 | base `:387-428` / 2881 B / `41fc390d…` → `handle_new_proxy_resp_arm`; coupling: `&mut last_start_err` only — **no `ctx` at all**; `proxy_info_map` reached via `&self`; and it gains the **first direct test** of these arms (the inline `mod tests`) |
| ~~`NatHoleResp`~~ **landed** (PR #501) | 39 | base `:348-386` / 2625 B / `1fdfffd5…` → `handle_nat_hole_resp_arm`; coupling: `&mut SessionCtx` (`&mut pending_xtcp`, `&mut visitor_pending`, `&xtcp_sockets`, `session_alive`) and `writer`; **`p2p_bridge_tokens` is reached via `&self`, not passed** (the row listed it as a parameter, which is what sent this group's brief wrong) |
| ~~visitor request~~ **landed** (PR #505) | 35 | base `:484-518` / 2285 B / `af0bd955…` → `handle_visitor_request_arm` (`:1620-1660`), call `:426-429` 4L/177B/`11c82ac9…`; **0 deltas** (the program's second zero-delta arm); `self.` = 0, so the **D1 form** applies here; spawns 1 (the 20 s cleanup, off-loop) |
| ~~STUN result~~ **landed** (PR #504) | 31 | base `:559-589` / 1927 B / `b774ecdf…` → `handle_stun_result_arm` (`:1482-1518`), call `:459-466` 8L/338B/`fa1b9b3a…`; coupling `&mut SessionCtx` (`&mut pending_xtcp`, `&xtcp_sockets`, `stun_result_rx`, `v2`) **plus the loop-local `xtcp_cleanup_tx`**, which this row previously omitted; **spawns 1** (the 15 s cleanup) |
| ~~`NatHoleClient`~~ **landed** (PR #501) | 22 | base `:326-347` / 1498 B / `f4ff263c…` → `handle_nat_hole_client_arm`; coupling: `&mut SessionCtx`, `writer`, `punch_proxy_still_live`, `session_alive`; **`p2p_bridge_tokens` via `&self`** (split `self` / `.p2p_bridge_tokens` / `.lock()` across lines at `:1197-1199`, which is why a joined-literal grep misses it) |
| ~~vnet trio~~ **landed** (PR #502) | 138 measured (70+35+33; the row's 141 counts the three separator lines between the arms) | base `:336-405` / `:407-441` / `:443-475` → `handle_vnet_route_advertise_arm` / `handle_vnet_packet_arm` / `handle_vnet_route_remove_arm`; each arm keeps its call-site `#[cfg(feature = "vnet")]` **and** the handler gains one; coupling `&self` only (`cfg`, `vnet_controller`, `vnet_tun_names`, `vnet_peer_routes`, `vnet_tun_tx`) |
| ~~`xtcp_cleanup`~~ **landed** (PR #504) | 13 | base `:597-609` / 570 B / `6fd91bf5…` → `handle_xtcp_cleanup_arm` (`:1535-1543`), call `:473-480` 8L/310B/`8f2e26d0…`; coupling `&mut SessionCtx` (`&mut pending_xtcp`, `&mut visitor_pending`); **0 deltas**, spawns 0 / awaits 0 |

**`writer`-parameter rule, from groups A and B (PRs #501, #502).** A handler needs
`#[cfg_attr(not(feature = "vnet"), allow(unused_variables))]` **only when its only use of `writer` sits behind a
vnet gate** — and a handler that takes **no `writer` at all never needs it**: group B's three vnet arms are
receive-only (0 `writer` in code; the four textual hits are doc prose), so they carry no attribute, and a
*counterfactual* `writer` parameter on one of them is unused even with `vnet` on, i.e. the precondition cannot obtain.
Settle each case by a removal probe; the two group-A handlers happen to carry a non-load-bearing attribute. Measured both ways: removing the attribute from the landed `handle_close_proxy` gives
rc 101 (`unused variable: writer`), while removing it from the two group-A handlers gives rc 0 — so on those two it
suppresses a genuine future warning rather than documenting a constraint, and it should be dropped when they are next
touched. Group A is also the precedent for the checklist: each arm's row carries its own `continue` census, its own
`LoopExit::` count and its own stripped inner-loop scan, with only the loop-level "nothing follows the `select!`" fact
shared — which is what makes a grouped PR reviewable arm by arm.
**The correction applies per row, and *neither* generalisation of it is right.** The M-31 note said D1's rows "have the
same shape" as the NatHole rows (state reached through `&self`); measured, every D1 span and handler has **zero** `self.`
uses. But the opposite conclusion — "the correction does not generalise" — is one over-generalisation too far, because
group D2 landed **one row of each shape in a single PR**: its **health** row uses `self.` (5 uses over 3 fields:
`p2p_bridge_tokens`, `proxy_info_map`×2, `health_proxy_configs`) exactly as group A's NatHole rows do, while its
**visitor** row is `ctx.`-only (`self.` = 0), exactly as D1's three are. So the rows must be read one at a time: the
M-31 correction is *right* for the rows that reach state through `self.` (group A, D2's health row) and the D1 form is
right for the rows that do not (D1, D2's visitor row). Both rows also needed a second fix — the health row presented
`ctx` fields as parameters and the visitor row omitted the loop-owned `xtcp_cleanup_tx`, which its handler's signature
carries as `&mpsc::Sender<String>`. **Rule: derive each row's mechanism from the arm, never from another group.** The verification round put the pattern
sharply: *three consecutive grouped PRs found this column wrong in three different directions* — group A's rows reach state
through `self.`, D1's present `ctx` fields as parameters, and D2's two rows are one of each shape — and every one of those
came from reading the coupling column **as a spec rather than a plan**. A row's mechanism belongs to the landed handler.

**Regrouping (decided after arm 1 landed, 2026-10-04).** The row's original "one per PR" predates the first arm, when
the recipe, the signature constraint and the coverage gap were all unknown. Arm 1 (`CloseProxy`, PR #498) established
them, so the remaining work is grouped **by code adjacency where the arms are contiguous and by mechanism otherwise**
(which is why D2's two non-contiguous arms still belong together) into five PRs — which is what the project's
own instruction asks for ("group related items that share a mechanism into one PR where that does not weaken review").
Grouping reduces ceremony, **not evidence**: every arm in a group still carries its own per-arm proof (base span/bytes/
sha256 → extracted span/bytes/sha256, the deltas enumerated — whitespace reflow, `continue;` → `return;`, any forced
type-exactness change — its own terminality argument, and the skeleton-invariants check), and each PR still gets two
reviews, at least one adversarial, and **each grouped PR's description carries a per-arm checklist** — one row per arm
with its span/bytes/sha, terminality argument and delta list — so a single review pass cannot silently skip an arm.

| group | arms | measured spans at `main` = `9f75d9e0` | LOC |
|---|---|---|---:|
| **A** | `NatHoleClient` + `NatHoleResp` + `NewProxyResp` | `:326-347` + `:348-386` + `:387-428` | 103 |
| **B** | vnet trio (`VnetRouteAdvertise`/`VnetPacket`/`VnetRouteRemove`) | `:430-499` + `:501-535` + `:537-569` | 138 measured, vs the table's 141 — the row counts the three blank separator lines between the trio's arms, which the per-arm spans do not |
| **C** | ping tick + proxy retry tick | `:580-665` + `:667-796` | 216 |
| **D1** | XTCP notify → STUN + STUN result + `xtcp_cleanup` (share `pending_xtcp`/`xtcp_sockets`) | `:876-978` + `:982-1012` + `:1020-1032` | 147 |
| **D2** | health event + visitor request | `:798-858` + `:1037-1071` | 96 — **mechanism, not adjacency**: both are event→side-effect handlers on the control connection (proxy health transitions; visitor requests) that no other group covers, which is why they pair despite straddling D1 |

Every measured LOC above matches the row's own figure for that arm (e.g. ping 86, retry 130, STUN result 31,
`xtcp_cleanup` 13), so the table's **sizes** were right all along — only its **line numbers** were pre-S3 and stale.
**C stays its own group on purpose, but not for the reason first written here.** Measured across the eleven arms,
the eleven arms take **only short-lived, single-lock critical sections** (measured: 27 lock/write/read uses, including
six `self.proxy_info_map.write().await` — one of them at `:784`, inside C's retry arm — plus `route_table.write().await`
and `vnet_peer_routes.lock()`), so lock *volume* does not distinguish the groups; what does is that the **ordering**
hazard lives in the functions these arms call (`try_reload`, the `:758-762` note). What actually distinguishes C is that it is the only group carrying a
**documented ordering invariant**: the lock-order note at `:758-762` plus the retry arm's own "both locks' writers
run only in this message-loop task" obligation. **D1 owns the largest hidden surface** — the only three `tokio::spawn`s
among the eleven, plus three shared NAT-hole maps (`pending_xtcp`, `xtcp_sockets`, `visitor_pending`), so its review
must apply the same "handler called inline, never spawned" check that C's does. Two further measured facts the groups
share: all thirteen arms contain **zero** `LoopExit::` (the loop's six exits live outside them, so no arm's early exit
can move another's preconditions), and the `continue;` → `return;` transformation **recurs in three of the eleven** —
`NatHoleClient` `:337`, `NatHoleResp` `:373` (inside the nested `match` at `:368`) and ping tick `:650` — so **group A
carries two of them**, and A's and C's delta lists must include the line. None of the three sits inside an inner loop
(each start→`continue` span has no `for`/`while`/`loop`), so the landed arm's terminality proof generalises verbatim.
A group's arms also share mutable state (A: `p2p_bridge_tokens`; `NatHoleResp` and all three D1 arms share the NAT-hole
maps), so every per-arm proof must carry its own borrow/signature delta — the coupling column already anticipates it.

**Correction to every row above, from the first landed arm (PR #498).** The coupling column says `&SessionCtx` for
several arms; a handler **cannot** take a shared `&SessionCtx`. `SessionCtx` owns
`reader: Option<BoxedReadHalf>` where `BoxedReadHalf = Box<dyn AsyncRead + Unpin + Send>`, so
`SessionCtx: Send + !Sync` ⇒ `&SessionCtx: !Send`; holding that shared reference across a handler's `await`s makes
`run_message_loop`'s future non-`Send` and breaks `tokio::spawn(client_service.run())` at its test call sites
(the reproducible failure is `E0308` "types differ in mutability" at the call site; one round additionally reported
	the chain `Sync` not implemented → `Box<dyn …>` → `Option<Box<…>>` →
`SessionCtx` → `&SessionCtx`). **Every handler here takes `&mut SessionCtx`** (or a disjoint field borrow), which
is a type-level requirement rather than a stylistic one — the landed handler only *reads* `cfg_user`/`v2`. The same
seam also showed that a handler's `writer` parameter needs
`#[cfg_attr(not(feature = "vnet"), allow(unused_variables))]` (rc 101 without it in the non-`vnet` `-D warnings`
shape), and that the landed arm's coupling list in the table above needs regenerating (it uses no `plugin_handles` and no
	`self.cfg`). It also showed that **none of these arms had a direct test lane when the first arm landed**: no test puts a `CloseProxy` (or most other arm
inputs) on the wire to a client `Service`. The landed extraction makes such a test cheap, but it needs either
`pub(super)` on the handler (the same minimal widening S2 and S4 needed — a sibling test module cannot see a private
method, `E0624`) or an inline `#[cfg(test)] mod` in `message_loop.rs`; the first arm deliberately did not add one,
and it should be added with a later arm rather than left as a note. **Group A did add one** (PR #501): `NewProxyResp`
needs no `SessionCtx`, so `handle_new_proxy_resp_arm` is driven directly by a new inline `#[cfg(test)] mod tests`
(four calls covering five behaviours over a real `Service`; the adversarial round's mutation check found an inverted
phase or `is_empty` condition changes three of its assertions); the two
NatHole handlers still have no lane, for exactly the `SessionCtx` + `ControlWriter` reason above. One distinction worth
keeping straight: group A's two `&writer` → `writer` drops **are** clippy-forced (re-adding the `&` gives rc 101 with
three `needless_borrow` errors), whereas the landed `CloseProxy` arm's was lint-clean type-exactness — so a dropped `&`
in this file is justified by measurement each time, never by the precedent.

**cfg-gate placement, from group B (PR #502).** A vnet arm's `#[cfg(feature = "vnet")]` must sit on **both** the call
site and the extracted handler, and the pair is load-bearing **only in the non-`vnet` shape**: measured with
`--no-default-features --features tls,tcp-mux`, removing **one** handler gate gives rc 101 with 6 errors
(`E0425`×3 + `E0609`×3) and **one** call-site gate 2 (`E0599`×2), while removing **all three** handler gates gives 15
(7 `E0425` + 8 `E0609`) and all three call-site gates 6 — the counts are scope-dependent, so state which. With `vnet`
**on**, removing either is **rc 0** — the adversarial round's measurement; the verification round's probes were in the vnet-off
shape only — so both gates are inert there. That is also why a gate census must be reported per
shape rather than as one number.

**Counting `#[cfg]` — name the rule (from group D1's review, PR #504).** Two careful rounds reported different totals for
the same file because they counted by different rules: raw `#[cfg(` lines (10 before the test module, one of which is a doc
comment quoting `#[cfg(test)]`) versus real attributes (**9** `#[cfg(…)]` = 8 vnet + 1 `any(target_os)`, plus **3**
`#[cfg_attr(…)]`). The delta that mattered was zero at both ends either way; the lesson is that a `#[cfg]` census should say
which rule it uses, exactly as gate-error counts must state their scope and byte counts their basis.

**Test-induced weak cites, from group C (PR #503).** A new direct test that re-assigned a value the test helper
already set duplicated the handler's own line `ctx.ping_retry_backoff = None;`, and because nine `heartbeat_wire_order.rs`
cites land on that line the guard's weak count went **104 → 113** — nine *production* witnesses degraded by a *test*.
Both review rounds rejected accepting it: the assignment was redundant, and replacing it with a comment restored the
unique occurrence and the header to `weak=104 weak_set=dbbea851…` at zero test cost. The lesson is worth the space
because `--write` **hides** this class rather than removing it — a weak cite is by construction one that no longer
witnesses a unique line — and the earlier claim that the base already counted those cites as weak was false (at the
base, **zero** weak rows targeted this file).

**S3b complete (2026-10-05, `fac8511b`).** All **12 data rows / 14 arms** are landed — `CloseProxy` (#498), A (#501),
B (#502), C (#503), D1 (#504) and D2 (#505). Nothing in the table is unlanded; what remains inline in `run_message_loop`
is exactly what the plan excludes: the six small `match msg` arms (`Pong` `:293`, `Ping` `:303`, `CloseProxyResp` `:317`,
`Error` `:323`, `Ok(_)` `:347`, `Err` `:350`), `reload` `:379`, `stop` `:430`, the watchdog `:449`, `writer.wait_failed`
`:456`, the read arm's own plumbing (`:280`) and the two timer futures whose bodies are now handler calls. This was
verified **three times independently of this table**: by the group D2 author's census, by the adversarial round walking the
12 rows against the merged tree, and by the verification round counting the merged `select!` directly — it holds exactly
**14 handler calls** (`handle_close_proxy` at `:315` plus thirteen `*_arm` calls), i.e. exactly the 14 arms, with no row's
body left inline. **The `run_message_loop` body is therefore no longer a large function:**
`frp-client/src/service/message_loop.rs` is 2917 lines of which the loop itself is a dispatch skeleton, and the extracted
handlers plus their direct tests account for the rest.

Order: `CloseProxy` (landed, PR #498) → **A** (`NatHoleClient`/`NatHoleResp`/`NewProxyResp`; **landed, PR #501**) →
**B** (vnet trio — the next group) → **C**
(ping, retry) → **D1** (XTCP/STUN/cleanup) → **D2** (health/visitor); within a group, the arms may go in either
order as long as each keeps its own proof. Leave the
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

**Seam 1 landed (2026-10-05, PR #506, base `345776b9`, head `91ac57a4`) — `visitor/stcp.rs`.**
`run_visitor_listener` (base `:1146-1779` = 634 raw lines / 33 199 B / `7373ce44…`) and `VisitorConnCtx` with its doc
comment (base `:98-123` = 26 L / 910 B / `7c1d8427…`) moved into a new **child** module `frp-client/src/visitor/stcp.rs`
as a **byte-identical** move: both spans reproduce their base sha in the new file (`stcp.rs:53-686` and `:26-51`), and the
struct alone (`:104-123`, 20 L / 493 B / `e757b095…`) does too. `visitor.rs` 3864 → **3215**; the crate's `src/**` row
35 files / 40 596 → **36 / 40 633**. The only added text is the child's `use super::*;` and the parent's `mod stcp;` +
`pub(crate) use stcp::run_visitor_listener;`.

**Why this seam needed *zero* visibility changes, which is the reusable part.** Because `stcp.rs` is a child of
`visitor`, every private callee keeps its token (`plan_visitor_dial`, `VisitorTransportConfig`, `bridge_until_cancelled`,
`XtcpPunchConfig`, `TunnelSession`, `open_tunnel`, `process_tunnel_start_events`, `run_sudp_visitor_listener`, …) and
`use super::*` carries the parent's imports; the re-export keeps `crate::visitor::run_visitor_listener` as the spelled
path at its only call site, so `frp-client/src/service/session.rs` is **not in the diff**. A byte-identical span admits
no interior edit, and the review confirmed no resolution change: the child **adds** no `#[cfg]` — it carries the **2** its byte-identical span brought with it
(`#[cfg(all(feature = "quic", feature = "kcp"))]` at `stcp.rs:107` and `:158`, so "0 `#[cfg]`" would be wrong) — and the parent module is ungated,
and `cargo check -p frp-client --all-targets` is rc 0 in both the all-features and default shapes (no glob ambiguity or
shadowing). **The one behavioural side effect, admitted rather than hidden:** the `tracing` target becomes
`frp_client::visitor::stcp` (`module_path!()`), which `RUST_LOG` prefix-matching still covers and which nothing in the
tree filters on — the review checked `*.rs`/`*.md`/`*.sh`/`*.yml`/`*.toml` for the old path and found none.

**Coverage, which is half the deliverable for this file** (the plan warns P3 is the least-tested large file in the
repo): `stcp_e2e` **5/0** (four pre-existing plus one new), `xtcp_pair_e2e` 2/0, `xtcp_visitor_failure_e2e` 3/0,
`sudp_e2e` 7/0, `stcp_visitor_reject` 1/0, `visitor_response_timeout` 1/0, `xtcp_p2p` 12/0. Two **mutation witnesses**
prove the lanes execute the moved code: a panic in the accepted-connection arm reds **all five** `stcp_e2e` tests while
`sudp_e2e` stays 7/0 under the same mutation (so that arm is load-bearing for STCP and not for SUDP), and a panic
replacing the SUDP dispatch reds all seven `sudp_e2e` tests. One **real gap was closed**: every pre-existing lane ran
`tcp_mux = false`, so the moved `wrap_client_mux` arms had no lane at all — `stcp_e2e.rs` gains a mutation-witnessed
`test_stcp_e2e_relay_tcp_mux` (with a `start_frps_with_mux` helper, the old `start_frps` becoming a delegate) that reds
**only** when the moved `wrap_client_mux` is unwrapped. The remaining unlaned branches are enumerated with line numbers
in the batch report rather than waved at: bind failure, accept error, the dial errors, response-read failures,
unexpected response frame, the `user_conn missing` arm, three "shutting down, abandoning" arms, the fallback yamux arm,
and the XTCP encrypted P2P bridge.

**Three corrections this seam forced on this document, all of which the code won:**

1. **This section's cfg figure was stale — and the count needs *three* named axes, because two review rounds and the
coordinator each measured a different, correct number.** The rule and the axes: **file** (`frp-client/src/visitor.rs`),
**tree** (before or after the move), **boundary** (the first `#[cfg(test)]` line, or the `mod tests {` line), and
**counting** (a line whose `lstrip()` starts with `#[cfg(` = "real"; a line merely containing `#[cfg` = "raw").
Measured: on the **base tree** `345776b9` (3865 lines, tests from `:3168`) the production region holds **28 real / 30
raw** and the whole file **33 real / 35 raw**; on the **post-move tree** (3216 lines, tests from `:2519`) the same rules
give **26 real / 28 raw** and **31 real / 33 raw**; using the `mod tests {` boundary instead gives **25** (base) and
**23** (post-move) real. The two trees differ by **exactly the two gates the byte-identical move carried** —
`#[cfg(all(feature = "quic", feature = "kcp"))]` at `stcp.rs:107` and `:158` — which is why 28−2=26 and 33−2=31, and
which *demonstrates* the "adds no gate" claim rather than asserting it. `#[cfg_attr]` is 0 everywhere. All three
numbers were right; only the axes were unstated, and this program has now had six cases of correct-but-different
totals for one quantity.
2. **The two suites this section names as P3's XTCP validation do not reach the moved code at all.**
`frp-server/tests/xtcp_hole_punch.rs` and `frp-core/tests/xtcp_p2p.rs` contain **0** references to
`frp_client`/`ClientService`/`VisitorConfig`; `xtcp_pair_e2e.rs` contains 0 `run_visitor_listener` references and
`xtcp_visitor_failure_e2e.rs` 0 of that function (with 4 other visitor references — enough for prefix/sibling
coverage, not for the moved body). **The real client-side lanes are `frp-client/tests/xtcp_pair_e2e.rs` and
`xtcp_visitor_failure_e2e.rs`**, plus the STCP ones above.
3. **"The XTCP matrix" is not `protocol-matrix.sh`.** That script's rows are the eleven transport rows and it contains
**zero** `xtcp` references. The XTCP matrix is `scripts/compat-test.sh --xtcp-only` (flag at `:166`, documented at
`:181`), which runs entirely in-tree when `--frps-remote` is absent and expands to 17 `test_xtcp_*` wrappers — it was run
(**17/0**) and belongs in any P3 sweep as its own step.

**Seam 2 landed (2026-10-06, PR #507, base `2aaeed0c`, head `4c8cc0f7`) — `visitor/xtcp.rs`.**
The XTCP half of `frp-client/src/visitor.rs` moved into a new **child** module `frp-client/src/visitor/xtcp.rs`
in four commits: `224a9637` (the move), `521c3a12` (the window ended at the doc comment's end instead of
inside it), `7ea97808` (that mixed comment split at its semantic boundary), `4c8cc0f7` (the child module's
`//!` header reworded to state that split — the one review finding against the branch, a doc-text fix that
left the file at 344 lines). Four windows, every one
byte-identical to its base text after normalising the added visibility tokens. **Basis of every figure below:**
the normalisation is `sed -e 's/^pub(super) //' -e 's/^    pub(super) /    /'`, the hash is the **SHA-1 of the
newline-terminated window text** (not a git blob id and not SHA-256), and the byte count includes the final
newline, so a raw head window reads larger by exactly 11 B per `pub(super) ` prefix. `XtcpPunchConfig` doc+struct
base `:339-366` (28 L / 1274 B / `60f5e283…`) → `xtcp.rs:33-60`; the punch doc base `:368-370` (3 L / 236 B /
`c8b93bba…`) → `:62-64`; `do_hole_punch` base `:389-668` (280 L / 12 217 B / `0c7e6f7e…`) → `:65-344`; and
the clamp doc base `:371-379` (9 L / 582 B / `452baefe…`), which **stayed in the parent** at `:341-349`.
`visitor.rs` 3215 → **2983**; the new child is **344** lines; the crate's `src/**` row 36 files / 40 633 →
**37 / 40 745**. `clamp_hp_timeout` itself stayed in the parent (`:350`) because its only non-XTCP user is the
`vnet`-gated test `hp_timeout_floor_and_cap`: moving it would have needed a wider token plus a `#[cfg]`-gated
re-import for zero cohesion gain — that alternative was **executed and measured** (+3 lines, +1 token,
+1 `#[cfg]`, both checks rc 0) and rejected on the evidence, not dismissed. The only added text is module
plumbing — the child's `//!` header (`:1-29`, then the separating blank at `:30`) and `use super::*;` (`:31`), the parent's `mod xtcp;` +
`use xtcp::{do_hole_punch, XtcpPunchConfig};` (`:161-162`) — plus one 79-line test
(`tunnel_session_tests::do_hole_punch_precheck_channel_and_cancel_arms`, parent `:2862-2940`).

**Why this seam's visibility change is the reusable part, and why seam 1's zero-change claim cannot be
reused.** Rust privacy is downward-only, so a parent cannot name a child's private items; the move's first cut
failed with 2× `E0603` + 6× `E0616` at the parent `use`, and the honest fix is `pub(super)` on the struct, its
nine fields and the function — 11 tokens, counted. Inside a **private child module** `pub(super)` is exactly
`pub(in crate::visitor)`, the original reachable set, so nothing widened; `pub`/`pub(crate)` and any re-export
were both refused, and no code outside `frp-client/src/visitor*` names either item (only doc comments at
`frp-client/tests/xtcp_visitor_failure_e2e.rs:10,255,310` and `frp-client/src/service/session.rs:1002-1003`).
Seam 1 could claim zero visibility changes only because its moved item was already `pub(crate)` and a re-export
preserved the spelled path at its call site; for the remaining seams the rule is "the minimum token, stated"
rather than "no token". The other admitted side effect is the same as seam 1's: `module_path!()` makes the
`tracing` target `frp_client::visitor::xtcp`, which `RUST_LOG` prefix-matching covers and which nothing in the
tree filters on.

**Coverage.** `--lib visitor` **29/0** (one new), `xtcp_pair_e2e` **2/0**, `xtcp_visitor_failure_e2e` **3/0**,
`stcp_e2e` 5/0, `sudp_e2e` 7/0, and the XTCP matrix `scripts/compat-test.sh --xtcp-only` **17/0**. Mutation
witnesses: **M1** (panic at the handler entry `xtcp.rs:66`) reds the lib lane **28/1** and `xtcp_pair_e2e`
**0/2**, and its `RUST_LOG=frp_client::visitor=debug` trace prints the moved body under the new target;
**M2** (`cfg.vtx.is_closed()` → `true`) and **M3** (the pre_check cancel arm → `pending()`) each red the new
test (panics at parent `:2925`/`:2934`); **M4** shortened `frp-core/src/stun.rs:192`'s 5 s timeout in a probe
to show the dead-STUN lane's topology reaches the two STUN-failure returns that the stock timeout outlives. One
real gap closed: the PreCheck closed/backlogged split and its cancel arm had no lane, so the new test drives
them. The remaining unlaned branches are enumerated with line numbers in the batch report (the PreCheck
timeout/server-error/channel-closed returns, the STUN cancel and `other_addr = Some` arms, both NatHoleResp
error/closed/timeout paths, the `sid` / `p2p_key` / `p2p_sid` / `detect_behavior` None arms, and the
punch-cancel and `session_fut` Err arms), and `xtcp_visitor_failure_e2e` enters the moved body under M1 yet
still passes — its three cases are not discriminating for the body as a whole, which is why the new unit test
exists.

**Four corrections this seam forced on this document and on the closed items:**

1. **This section's proposal row is point-in-time and stays.** The `visitor/xtcp.rs` row (`:754`) proposes
   "`do_hole_punch` (395), plus the STUN/punch helpers"; at this seam's base the function measures **280 raw
   lines**, its "helpers" are in-body arms, and `clamp_hp_timeout` is a separate 8-line helper that stayed in
   the parent. The four-modules table's `:26` row likewise gives `run_visitor_listener` at `visitor.rs:1141`
   (where it lived when the plan was written; seam 1 moved it to `visitor/stcp.rs:56`). Both tables describe
   the plan as proposed, so neither is edited — the landed windows above are the record.
2. **The closed XTCP/quic items' `frp-client/src/visitor.rs:N` cites were already stale at this seam's base,
   and that is not this PR's drift.** They are keyed to seam 1's base `345776b9` (3864 lines); measured against
   `2aaeed0c` (3215 lines) only `:94-95` and `:1` still resolved, and two values (`TODO.md:2079`'s `:371` and
   `:2082`'s `:2900-2901`) quote compiler diagnostics from an even older tree. `TODO.md` is point-in-time by
   `scripts/tests/todo-cite-guard.sh`'s own skip list, so they are documented here rather than rewritten.
   **This seam breaks no `TODO.md` cite that was correct at its base.**
3. **The `#[cfg]` census needs its rule named, and the first one mixed two heads.** At the head the child
   carries **3** `#[cfg(...)]` (`:55`, `:306`, `:322`) and **0** `#[cfg_attr]` under
   `grep -Ec '^[[:space:]]*#\[cfg\(' frp-client/src/visitor/xtcp.rs` — the same three gates the base window
   carried, so the move adds none (the gate at `:55` is the `quic_params` field's
   `#[cfg(all(feature = "quic", feature = "kcp"))]`, the pair at `:306`/`:322` the KCP/QUIC data-plane arms).
   The earlier report's ±1 "drift" was a mixed-tree count, not drift, and the POSIX-BRE spelling of that
   pattern is unbalanced and needs `grep -E`.
4. **A straddled doc comment is a real cost, and its accounting has two forms.** The base's single 12-line
   comment (`:368-379`) was attached to `fn clamp_hp_timeout` although its first three lines describe
   `do_hole_punch`, so *both* of this seam's first two windows mis-assigned text: the original window ended
   inside the comment (leaving a half-sentence orphaned in the parent) and the corrected window attached all
   12 lines to `do_hole_punch` (leaving `clamp_hp_timeout` undocumented). The landed split gives each function
   its own comment, both byte-identical to their base text. Consequently the `~24.8 days` grep has two correct
   totals: the parent's **anchored doc-form** `^/// ~24\.8` count is **1** (the restored clamp doc) and its
   unanchored count is **2** (that line plus the pre-existing self-contained `//` copy inside
   `hp_timeout_floor_and_cap`, base `:2279` → head `:1968`, text unchanged); the child's count is **0**.

**Seam 3 landed (2026-10-06, PR #508, base `a0debc74`, head `ac43aee8`) — `visitor/sudp.rs`.**
The SUDP cluster of `frp-client/src/visitor.rs` moved into a new **child** module
`frp-client/src/visitor/sudp.rs` as a single **byte-identical** window: base `:821-1513` (693 lines / 30 058 B /
`39d89e02…`) → child `:24-716`, and `cmp` of the two raw ranges passes. `git diff -U0` is exactly three hunks
(`@@ -163,0 +164,12 @@`, `@@ -821,694 +832,0 @@`, `@@ -0,0 +1,716 @@`) with **zero** context lines; numstat is
`visitor.rs` 12/694 and `sudp.rs` 716/0. Each of the six items reproduces its base SHA-1 on its own
(hash = SHA-1 of the newline-terminated window text, seams 1/2's recipe): doc + `run_sudp_visitor_listener`
base `:821-1098` → child `:24-301` `8b5fea00…`; `sudp_next_datagram` `:1100-1120` → `:303-323` `ef60562b…`;
`connect_sudp_visitor_stream` `:1122-1231` → `:325-434` `0c9a7b5c…`; `run_sudp_worker` `:1233-1494` →
`:436-697` `ea08ccd3…`; `SudpReaderAbort` + `impl Drop` `:1496-1503` → `:699-706` `f77fac38…`;
`wait_sudp_shutdown` `:1505-1513` → `:708-716` `1319bad5…`. The parent's deleted region is base `:821-1514`
(694 lines = the 693-line window plus the separating blank; 30 059 B / `3fee5069…` — *not* `39d89e02…`, which
is the window itself: an earlier draft of the batch report conflated the two through a command-substitution
trailing-newline strip, corrected at the coordinator's request). `visitor.rs` 2983 → **2301**; the new child is
**716** lines; the crate's `src/**` row 37 files / 40 745 → **38 / 40 779**. Added text is plumbing only: the
child's `//!` header `:1-20`, blank `:21`, `use super::*;` `:22`, blank `:23`; the parent's 9-line explainer
comment, `mod sudp;` (`:173`) and `pub(crate) use sudp::run_sudp_visitor_listener;` (`:174`) inserted at
`:164-174` (12 lines with the trailing blank `:175`).

**This seam is seam 1's zero-visibility-change case, not seam 2's token case.** All six items keep their base
tokens — the listener stays `pub(crate)` (`sudp.rs:42`), the other five stay private (`:310`, `:329`, `:458`,
`:700`, `:702`, `:709`) — because the cluster's only cross-module caller is
`frp-client/src/visitor/stcp.rs:61` (`return run_sudp_visitor_listener(config).await;`, reached through that
file's `use super::*;`), and the parent re-export preserves the spelled path at its only call site; no
`crate::visitor::run_sudp_visitor_listener` path exists anywhere in the tree. So `pub(super)` (seam 2's answer),
a `pub(crate)` widening and any further re-export were all unnecessary, the first compile needed no privacy
fixup, and the reusable rule stays "the minimum token, stated" — this seam's minimum is zero. `use super::*`
reaches `VisitorListenerConfig` (3 uses), `VisitorTransportConfig` (3) and `plan_visitor_dial` (2), and 0 uses
of `VisitorConnCtx` / `TunnelSession` / `open_tunnel` / `process_tunnel_start_events` / `bridge_until_cancelled`
/ `clamp_hp_timeout` / `run_visitor_listener` / `do_hole_punch` / `XtcpPunchConfig`. The admitted
`module_path!()` side effect is the same as seams 1/2: the `tracing` target becomes `frp_client::visitor::sudp`.

**Census.** `grep -Ec '^[[:space:]]*#\[cfg\(' frp-client/src/visitor/sudp.rs` counts **1** — `sudp.rs:85`'s
`#[cfg(all(feature = "quic", feature = "kcp"))]` on a `quic_params` destructure arm — with **0** `#[cfg_attr]`,
i.e. exactly the gate the base window carried, so the move adds none. Unlike seam 2 no moved item is gated:
there is no `#[cfg(feature = "sudp")]` anywhere, so the cluster compiles in every feature shape.

**Coverage.** Both SUDP lanes discriminate the moved body: `cargo test -p frp-client --test sudp_e2e` 7/0 and
`--test sudp_worker_partial_frame` 1/0 at head, and four one-line `panic!` insertions — M1 at `sudp.rs:43:5`
(first statement of `run_sudp_visitor_listener`), M2 at `sudp.rs:640:25` (the `Some(p) =>` arm that writes a
datagram to the server connection in `run_sudp_worker`), M3a at `sudp.rs:315:5` (`sudp_next_datagram`'s entry)
and M3b at `sudp.rs:710:5` (`wait_sudp_shutdown`'s entry) — each turn **both** lanes red (0/7 and 0/1,
`rc=101`, crate panic at the inserted line) while `stcp_e2e` stays 5/0 and `--lib visitor` 29/0 under every
one of them. So nothing in the moved body is lane-dead, and the STCP lane plus the unit suite are regression
**controls, not SUDP witnesses**. A fifth probe at `sudp.rs:476:9` (the `Some(udp_packet_codec)` arm) reddens
exactly one test, `test_sudp_e2e_v2_roundtrip`, which falsified the author's own "no lane sets
`udp_packet_codec`" judgement: that arm is covered by a single test — a thin lane, not a gap — and is recorded
as such. `sudp.rs:85`'s `#[cfg(all(feature = "quic", feature = "kcp"))]` is compiled in under frp-client's
default features and *is* executed (a discarded pattern field, not a branch). Uncovered, by judgement rather
than instrumentation (no coverage tool was run): bind failure `:99-101`; reader `send_to` failure `:146-148`;
the unparseable and absent `remote_addr` drops `:149-151`/`:152-154`; the inner channel-closed arms
`:156-158`/`:199-201`; `recv_from` error `:204-206`; first-packet `None` `:237-240`; the connect-failure
recovery arm `:269-277`; the seven `connect_sudp_visitor_stream` error/early-return arms `:356-360`,
`:366-371`, `:399-401`, `:413-415`, `:420-422`, `:424-426`, `:428-430` (including the timeout waiting for
`NewVisitorConnResp`); `split_work_conn_halves` failure `:480-484`; the two `CipherWriter::new` IV failures
`:510-514`/`:524-528`; the 60 s idle timeout `:633-636` (the whole lane runs ~16 s); worker channel-closed
`:664-666`; the `Ping`/`Pong` arm `:679-681`; an unexpected message `:682-684`; and reader read-error /
end-of-stream `:685-687`/`:689-691`. Option-matrix gap: no lane samples v2 with compression (either `enc`
value) or v2 with encryption — the (v2, comp, enc) cells (T,T,T), (T,T,F) and (T,F,T) are unexercised (the
matrix read off `sudp_e2e.rs:23-24`/`:39-40` defaults, `:167-171` enc+comp, `:231-233` comp only, `:418` v2
plain). `SudpReaderAbort`'s `Drop` (`:700-706`) is entered on every `run_sudp_worker` return, but no lane
forces a parked reader, so its abort effect is unverified.

**Corrections this seam forced:**

1. **This section's proposal row for `visitor/sudp.rs` is point-in-time and stays.** Its three parenthesised
   numbers (`run_sudp_visitor_listener (1791)`, `run_sudp_worker (2207)`, `connect_sudp_visitor_stream (2078)`)
   are each exactly **952** lines above this seam's base (measured `:839`, `:1255`, `:1126`), so the row is
   coherent with the plan-time tree and the landed windows above are the record. The row's "cohesive UDP
   family" is confirmed: the cluster was contiguous (`:821-1513`) with nothing else inside it, which is why
   this seam is the only one so far that needed **one** window (seam 1 needed two, seam 2 four).
2. **This seam stales one `TODO.md` cite that was correct at its base — unlike seam 2.** `TODO.md:2822` cites
   `frp-client/src/visitor.rs:1203-1208` for the dial-timeout arm; that text (SHA-1 `b61aa5ab…`) is byte-equal
   at base `:1203-1208` and child `:406-411`, so the cite was accurate at `a0debc74` and is not after the move.
   `TODO.md` is point-in-time by `scripts/tests/todo-cite-guard.sh`'s own skip list, so it is documented here
   rather than rewritten; the parent `:1203-1208` now holds unrelated `list_local_ips` text. The older
   point-in-time audit/archive docs cite eight more numbers inside the moved window
   (`docs/archive/plans/audit-fix-2026-08-12.md:117`: `:835`, `:940`, `:1353`, `:1647`;
   `docs/audit/2026-08-09-0.70.1-release-audit.md:59,60,176`: `:1107`, `:1283`, `:1149`, `:1465`, `:1087`), all
   keyed to pre-seam trees and out of both guards' scope.
3. **A measurement-surface lesson.** The working tree is not a stable measurement surface while an author is
   running mutation witnesses: a mid-mutation `sudp.rs` shifts every child line by one, which produced a
   spurious "the window mapping is off by one" reading from `sed` on the working tree, while the committed
   mapping (`git show <rev>:<path>`) was byte-exact. Seal span measurements to revisions, not to files.

**Seam 4 landed (2026-10-06, PR #509, base `9441317e`, head `7d6a1d50`) — `visitor/vnet.rs`.**
The `virtual_net` visitor cluster of `frp-client/src/visitor.rs` moved into a new **child** module
`frp-client/src/visitor/vnet.rs` as **five byte-identical windows**, the first non-contiguous seam: the
`bridge_until_cancelled` bridge and `list_local_ips` sit between the windows and stay in the parent (Corrections
1–2). W1 `VnetTunTxMap`/`VnetTunSubnetMap` base `:22-26` (5 lines / 152 B / `d03e3f7f…`) → child `:34-38`;
W2 `VirtualNetVisitorConfig` `:98-147` (50 / 2 177 / `bf0d5675…`) → `:39-88`; W3 `run_virtual_net_tunnel_io`
`:715-806` (92 / 3 857 / `a65dc297…`) → `:89-180`; W4 `run_virtual_net_visitor` + `deliver_tunnel_ingress` +
both shutdown waiters `:833-1167` (335 / 12 934 / `8c664335…`) → `:181-515`; W5
`#[cfg(all(test, feature = "vnet"))] mod tests` `:1263-1524` (262 / 11 321 / `a0e31630…`) → `:516-777`.
744 lines / 30 441 B in total (hash = SHA-1 of the newline-joined window text, seams 1–3's recipe), each span
occurring **once** in the child and **zero** times in the parent, so the child is a pure copy of base text. The
child is exactly a **33-line prelude** (29 `//!` lines, the separating blank, `use super::*;`, and the two-line
`#[cfg(all(feature = "vnet", test))] use std::collections::HashMap;` re-add) followed by the five windows with
**no separator lines** — 33 + 744 = **777** lines / 32 432 B. `visitor.rs` 2301 → **1569** (67 663 B); the
crate's `src/**` row **38 / 40 779 → 39 / 40 824** (measured file-by-file over `git ls-tree`, not by a glob). 751
parent lines are deleted — the 744 moved lines, five separating blanks and the two-line `HashMap` import pair at
base `:1-2` — and 19 added: the 14-line explainer comment `:117-130` and the gated declaration
`#[cfg(feature = "vnet")]` `:131`, `mod vnet;` `:132`, `#[cfg(feature = "vnet")]` `:133`,
`pub(crate) use vnet::{run_virtual_net_visitor, VirtualNetVisitorConfig};` `:134`.

**Zero visibility change, and the module itself is gated.** All eight moved items keep their base tokens:
`pub(crate) struct VirtualNetVisitorConfig` (child `:41`) and `pub(crate) async fn run_virtual_net_visitor`
(`:190`) are `pub(crate)` at base, and the two aliases (`:35`, `:38`) plus the four helpers (`:95`, `:405`,
`:492`, `:508`) are private at base — line-level byte identity is the proof. `use super::*;` reaches only three
parent names: `VisitorTransportConfig` (2 uses), `plan_visitor_dial` (2) and, in the moved tests,
`clamp_hp_timeout` (6); the aliases are the child's own local copies of `crate::vnet::{VnetTunTxMap,
VnetTunSubnetMap}` (the same aliasing `frp-client/src/work_conn.rs:42` uses). The only external caller is the
`virtual_net` visitor spawn at `frp-client/src/service/session.rs:909-910`, spelled
`crate::visitor::run_virtual_net_visitor` / `crate::visitor::VirtualNetVisitorConfig`, which the parent's
`pub(crate) use` keeps reachable — no `pub(super)`, no widening, no extra re-export. Unlike the
stcp/xtcp/sudp children, which are unconditional, both `mod vnet;` and the re-export carry
`#[cfg(feature = "vnet")]` because `vnet` is **not** a default feature (`frp-client/Cargo.toml`), so the child
stays out of non-vnet builds entirely. The admitted `module_path!()` side effect is seams 1–3's: the tracing
target becomes `frp_client::visitor::vnet`.

**Census.** `grep -Ec '^[[:space:]]*#\[cfg\(' frp-client/src/visitor/vnet.rs` counts **13** with **0**
`#[cfg_attr]`: the **12** gate lines the five windows carried plus the re-added `HashMap` gate at `:32`. The
parent goes 28 → **17** (−12 moved, −1 `HashMap` gate, +2 declaration gates), so no gate is lost or invented.

**Coverage.** The moved tests travel with the code (W5) and the feature lane discriminates them:
`cargo test -p frp-client --lib --features vnet visitor` reads `36 passed; 0 failed` at head, identical to the
base count, with the test ids now `visitor::vnet::tests::*`; the default lane `--lib visitor` stays 29/0 and
`--test reload_vnet_proxy` (not feature-gated — it runs in the default suite as the M6 reload regression) stays
1/0. One one-line `panic!` witness kills: M1 at the first statement of `deliver_tunnel_ingress` (child `:413`)
reddens four tests at `vnet.rs:413` and fails `virtual_net_tunnel_io_wraps_encrypted_compressed_bytes` through
the same call, the lane going rc 101. Two witnesses survive, and survive because nothing reaches them, not
because the code is stripped — M1 proves the same file, feature set and lane compile and call into the module:
M2 at the first statement of `run_virtual_net_visitor` (child `:225`, after the config destructure at `:223`) and M3 at
the first statement of `wait_for_shutdown_or_delay` (child `:493`) both leave the lane at 36/0 (and
`reload_vnet_proxy` green, since it runs with `vnet` off and fails its controller setup before the spawn).
Unreached, by static enumeration rather than instrumentation (no `cargo-llvm-cov` on this toolchain), so
cross-checked by M1–M3: **all** of `run_virtual_net_visitor` `:190-398` — its only caller is the feature-gated
`virtual_net` spawn and no test starts a real client session with a `virtual_net` plugin proxy;
`wait_for_shutdown_or_delay` `:492-504` and `wait_for_shutdown_signal` `:508-515`, used only from that function
and from `run_virtual_net_tunnel_io`'s select arm; inside `run_virtual_net_tunnel_io` `:95-180` (partially
reached by the one encryption/compression test) the split-failure arms `:108-111`, the plain-writer `else`
`:131-133`, the flush-failure arms `:134-137`, the shutdown select arm `:142-145`, the channel-closed arm
`:154-157`, the peer-closed `Ok(None)` `:162-165` and the packet-read `Err` `:171-174`; and inside
`deliver_tunnel_ingress` `:405-487` (four tests cover delivery, subnet direction, shared-buffer fan-out and the
ambiguous fallback drop) the queue-full `Err(TrySendError::Full)` `:434-440`, the closed-channel arms `:441` and
`:455-461`, and the re-`try_send` failure `:470-474`.

**Corrections this seam forced:**

1. **The plan row's `list_local_ips` stays in the parent — a deliberate plan/reality mismatch.**
   `docs/refactor-large-modules.md:756` lists `list_local_ips` under `visitor/vnet.rs`, but it carries no
   `#[cfg]` and its only caller is `frp-client/src/visitor/xtcp.rs:171`, which is always compiled; moving it
   into the feature-gated child would break that call site in default builds (or force a second always-compiled
   module). It is left at `visitor.rs:706`, and the point-in-time row is left as written.
2. **`bridge_until_cancelled` stays too, and is not a deviation.** Base `:808-831` (now `:675-698`): six call
   sites in `frp-client/src/visitor/stcp.rs` (`:342`, `:364`, `:502`, `:523`, `:637`, `:658`) plus a test in
   the parent — shared STCP/tunnel-session machinery the plan row does not name.
3. **The batch report's byte ledger overstated the child by one term.** It read "30-line prelude + 5 windows +
   4 blank separator lines = 777"; the child has **no** separator lines (W1 ends `:38` and W2 starts `:39`; W2
   ends `:88`/W3 `:89`; W3 ends `:180`/W4 `:181`; W4 ends `:515`/W5 `:516`) and the ledger is a 33-line
   prelude + the 744 moved lines. Re-measured at the coordinator from `git show <rev>:<path>`, not from the
   working tree.
4. **One host-load flake, not reproduced.** A first run of the `--lib --features vnet visitor` lane read
   `35 passed; 1 failed` on the sibling
   `proxy::tests::test_visitor_auth_debug_log_does_not_leak_secret_or_replay_proof` — a file this move does not
   touch, filtered in only because its name contains "visitor" — while two clean re-runs read `36 passed;
   0 failed`. Recorded as a measurement note; nothing in this seam depends on a single lane run.
5. **One pathline expectation is re-baked.** The parent's comment citing `service/session.rs:1030` moved from
   `visitor.rs:156` to `:97` with the deletions above; the cite text (and its token `b8c5f28b2dca68a3`) is
   unchanged: the first `--write` reported 1 added / 1 removed / 579 unchanged, and the second — after the
   drift fixes below — 0 added / 0 removed / 580 unchanged, because only the table's point-in-time cite-set
   digest moved.
6. **The adversarial round caught a citation drift the guard cannot see.** A re-point driven by
   `todo-cite-guard`'s FAIL lines moves only cites whose target stopped being an *item header*; a cite whose
   base target moved by 45 lines onto *another* item's header stays green and stays stale. Three sites were
   left behind: `frp-core/src/cli.rs:5072` (R2 — drift introduced by this seam, since its base target `:10759`
   is now the `[common]` strict-mode item while the R2 item moved to `:10804`) and two **pre-existing**
   mis-aims that name the R5 `-l`-shorthand item while pointing at R2's header
   (`frps/tests/cli_exit_codes.rs:2454`, `.github/workflows/ci.yml:2033`). All three now read `:10804`, so the
   cascade sentence's 58 holds. **The residual pre-existing drift class is six sites, not two:** besides that R5
   pair (correct target `:10837`), four R1-subject cites point at the `[common]` item — `frps/tests/log_completion.rs:655`,
   `frps/src/main.rs:422`, `frps/src/main.rs:471` and `.github/workflows/ci.yml:3057` — and all four already
   pointed at that unrelated header at base (`:10714`, shifted arithmetically correctly to `:10759`), while R1 is
   at `:10784`. All six are left for the class-wide drift repair first surfaced in seam 3's adversarial round, so
   that one pass fixes every known mis-aim (these six plus the #508 clusters) together instead of site by site.

### P4 — `frp-server/src/control/proxy_ops/` (3610 production lines at base, 34 production fns)

At base, production code was lines 1–3610 and the remaining 4444 lines were inline
tests. **Step 0 landed in PR #453** (`aae3a484`): `proxy_ops.rs` (8054 lines) became
`proxy_ops/mod.rs` (3618) plus three sibling test files, taking the production file
to 3610 lines with no logic and no path change. Re-measured figures are
8054 / 4444 / 3610 (same boundary as the provenance note above) — not the originally
recorded 8044 / 4432 / 3612. Seams 1 and 2 then landed as `92a454b3` and
`a618f281`, taking `mod.rs` to 3049 lines (3043 production); seam 3 landed as `d90a834f`,
taking it to 2767 lines (2761 production); seam 4 landed as `cbb9d4b3`, taking it to 2439 lines (2433 production); seam 5 landed as `359a031e`, taking it to 1938 lines (1930 production).

Two structural facts dominate everything after that:

**(a) Path-preserving is mandatory and cheap.** Seven files reach into
`proxy_ops::` by path — five production importers (`err_msg`, `handle_new_proxy`,
`unregister_control`, `release_udp_port_with_owner_check`,
`remove_proxy_and_release_client_counts`) and seven test importers of
`crate::control::proxy_ops::unregister_generation_tests::{proxy_info, test_state}`
(there is also an eighth production caller, `frp-server/src/service/tasks.rs:222`
`crate::control::proxy_ops::unregister_control(`). Converting the file to a
directory keeps **every external path byte-identical** *without* any
`pub(crate) use` re-export: a file module and an inline module have the same module
path, so the originals' visibility carries over unchanged. Measured in PR #453 —
`git diff --name-only` for `aae3a484` lists only the five `proxy_ops*` paths.

**(b) No `AppState` field is private** (only the three group controllers are
`pub(crate)`), so **no field-visibility change is needed for any seam**. There is
no `unsafe` in the file.

Seams, in the order they should be attempted (line numbers for the remaining rows
are current `mod.rs` positions at `359a031e`):

| Order | New module | Moves | Risk |
|---|---|---|---|
| 0 | *(directory + test modules)* — **landed `aae3a484`** | see Step 0: `mod.rs` + `unregister_generation_tests.rs`, `subdomain_conflict_tests.rs`, `tcp_auto_bind_retry_tests.rs` | **lowest** |
| 1 | `proxy_ops/validate.rs` — **landed `92a454b3`** | `validate_new_proxy` (was 891–961, pure), `duplicate_domain` (was 68–77) + its test module (now `validate/subdomain_conflict_tests.rs`) | low — zero `AppState` coupling, self-testing |
| 2 | `proxy_ops/vhost.rs` — **landed `a618f281`** | `register_http_vhost` (was 968–1213), `register_https_vhost` (was 1221–1441) | low — already fully extracted; no test region references them |
| 3 | `proxy_ops/tcp_group.rs` — **landed `d90a834f`** | `tcp_group_listener` (was window `mod.rs:2696–2856`, fn at `:2703`), `handle_tcp_group_member_registration` (was window `mod.rs:2858–2977`, fn at `:2867`) | low — leaves, owned args |
| 4 | `proxy_ops/registry.rs` — **landed `cbb9d4b3`** | `build_proxy_info` (was `mod.rs:407`, now `registry.rs:48`), `register_sk_index` (was `mod.rs:486`, now `:127`), `register_proxy_entry` (was `mod.rs:787–874`, now `:291–378`), the four `rollback_*` (was `mod.rs:505`, `713`, `734`, `756`, now `:146`, `217`, `238`, `260`), `remove_proxy_and_release_client_counts` (was `mod.rs:682–702`, now `:172–206`) | medium-low |
| 5 | `proxy_ops/ports.rs` — **landed `359a031e`** | `first_bindable` (now `ports.rs:19`), `PortError` (`:51`), `allocate_proxy_port` (was `mod.rs:171–409`, now `:86–324`), the rollback/free helpers (`udp_port_has_other_owner` `:333`, `free_replaced_port` `:365`, `release_udp_port_with_owner_check` `:437` — keeps `pub(crate)`, `proxy_consumes_client_port` `:458`), the reservation pruner + its `impl AppState` (`:468`, `:479`) | medium-low |
| 6 | `proxy_ops/teardown.rs` — **landed PR #514** (code `10fd4809`) | `unregister_control` (was `mod.rs:1527–1928`, now `teardown.rs:19–420`, fn at `:27`) — one function, 394 code lines (402 with its doc) | medium |
| 7 | `proxy_ops/listener.rs` — **landed** | `setup_proxy_listeners` (was `mod.rs:112–508`, now `listener.rs:29–425`, fn at `:42`), `bind_proxy_listener` (`:434`), `TCP_AUTO_BIND_MAX_ATTEMPTS` (`:463`), `bind_tcp_proxy_with_retry` (`:490`), `listen_and_proxy` (was `mod.rs:1290–1528`, now `listener.rs:427–665`, fn at `:587`) | medium — largest move, 13-arg interface |
| 8 | `proxy_ops/tcpmux.rs` — **landed PR #516** | the inline tcpmux arm (was `mod.rs:541–816`, 276 lines) became `register_tcpmux_proxy` (`tcpmux.rs:25`, 309-line module) called from `handle_new_proxy` (`mod.rs:122`) | **medium — the only seam that rewrites control flow** |

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

**Seam 3 landed (2026-10-06, PR #510, base `bcdad888`, head `d90a834f`) — `proxy_ops/tcp_group.rs`.**
The TCP-group cluster of `frp-server/src/control/proxy_ops/mod.rs` moved into a new **child** module
`frp-server/src/control/proxy_ops/tcp_group.rs` (303 lines / 14 065 B) as two contiguous, byte-identical
windows: W1 `tcp_group_listener` base `:2696-2856` (161 lines / `2740987a…`) → child `:22-182`, W2
`handle_tcp_group_member_registration` `:2858-2977` (120 lines / `6ce645f4…`) → `:184-303`, with the single
blank separator at base `:2857` travelling as child `:183` (combined `:2696-2977`, 282 lines / 13 270 B /
`455e0a56…`). The parent went 3049 → 2767 lines (`+3/−285`): it gains `mod tcp_group;` and a private
`use tcp_group::{handle_tcp_group_member_registration, tcp_group_listener};` at `:23-24`, and loses base
`:2694-2978` (285 lines: the `// ---- TCP group shared listener ----` marker at `:2694`, its
following blank `:2695`, the 282 moved lines `:2696-2977`, and the trailing blank `:2978`). Both functions
became `pub(super)` — the only byte change to the moved text (11 B each) — so the child's unprefixed
`:22-303` round-trips to `455e0a56…` exactly. Unlike seams 1 and 2, **no import needed pruning** from the
parent; the child's own prelude is `std`/`tokio`/`tracing`, `frp_core::msg`, `crate::service::{AppState,
InternalMsg}` and a depth-1 `super::{build_proxy_info, err_msg, free_replaced_port, reject_new_proxy,
write_resp}`.

Code-head gates: fmt; `clippy -D warnings` (0 warnings); `check --all-targets --all-features`; `check
--no-default-features`; `--lib --all-features` 525/0 (= base; plain `--lib` is 472/0 at both heads); `server_protocol` + `relay_integrity` + `vhost_http_group`
17/0; compat `go-to-rust-http-group` + `go-to-rust-tcp-plain`; `repo-health.sh` invariants;
`todo-cite-guard` 101/0; `large-functions.sh` sizes unchanged (path and line only: `tcp_group_listener`
111 code / 154 total / 27 % comments at the new `tcp_group.rs:29`, `handle_tcp_group_member_registration`
95/111/14 % at `:193`); release build of both binaries. The parent's production count went 3043 → 2761.
`pathline-cite-guard` was **red at the code head** — 580 checked / 30 violations against a base of 580/0,
proven attributable by restoring the base state — and is repaired by this records commit (Correction 3).

**Coverage is unchanged by the move, and its failure mode is worse than an empty lane** (two witnesses,
each reverted with a matching `git hash-object`, gate-7 binaries rebuilt from the mutated source and
injected through `FRP_COMPAT_RUST_FRPS`/`FRP_COMPAT_RUST_FRPC`). W1 — `panic!("M1")` at
`tcp_group_listener` entry — **survives every lane, but not because the lane is empty**: the function is
spawned from `setup_proxy_listeners` (base `mod.rs:1136-1138`, head `:1139-1141`), and an
`eprintln!("M1-ENTERED")` probe at its entry prints **once** under `--nocapture` in
`http_plugin::test_plugin_new_proxy_content_user_object_and_fields`, so the listener body *is* entered;
the mutation still leaves that lane green because the listener runs in a detached `tokio::spawn` task
whose panic nothing observes. The original reading ("printed 0 times, so no lane ever enters
`tcp_group.rs:29-182`") was a libtest output-capture artifact and is corrected here (Correction 10). A
failure of that task is therefore unobserved by every lane, even though the lane reaches the code.
W2 — `panic!` at `handle_tcp_group_member_registration` entry — reddens **every lib-running job** (both
witnesses are ungated `#[tokio::test]`s), the two failures being
`control::proxy_ops::unregister_generation_tests::tcp_group_auto_assign_handler_walk_declared_zero_semantics`
and `...::group_create_bind_race_joins_existing_group` (exit 101, 523 passed / 2 failed, panic at
`tcp_group.rs:207:5`); gates 6/7 survive. Both readings are identical at the base, so this seam changes
nothing about them.

**Corrections this seam forced:**

1. **The function takes 12 parameters, not the 13 the brief said.** `handle_tcp_group_member_registration`
   is `state`, `run_id`, `control_id`, `writer`, `np`, `_remote_port`, `_internal_tx`, `_listener_handles`,
   `_udp_sockets`, `v2`, `allocated_port`, `_tcp_group_created` — five of them unused (underscored) because
   the shared-listener path skips them, and `#[allow(clippy::too_many_arguments)]` still applies at 12.
   This is the seam's only interface fact a reviewer could falsify from the brief alone, so it is recorded.
2. **No compat scenario covers the TCP-group shared listener.** `bash scripts/compat-test.sh --list` has
   `test_g2r_http_group` for *HTTP* groups and nothing for TCP groups, and `frp-server/tests/` has no
   tcp-group integration file, so the compat gate witnesses only that the two neighbouring scenarios still
   pass — it cannot witness this seam. The lib lane is the only end-to-end witness (W2 above).
3. **35 cites into `mod.rs` move, and the guard sees only 26 of them.** The 3-line parent prelude
   (`:23-25`) shifts every cite below it by **+3**, and the 282 deleted lines shift every cite below the
   window by **−282**. The re-point was driven by that explicit old→new map, never by the guard's FAIL
   list: 26 `docs/developing.md` cites and `docs/refactor-large-modules.md:24` (`:1279` → `:1282`) moved
   +3, while the two `TODO.md` cites of the `#[path]` sites moved −282 (`:3044-3046` → `:2762-2764`). Only
   the 26 are in the guard's scan — cites *written in* `TODO.md` and in this plan are excluded from it
   (the guard-blind class first surfaced in seam 4's adversarial round), which is why its FAIL list must
   never be used as the cascade criterion. That first pass still missed six of the 35: five in
   `TODO.md:6950-6953` (`:1279`→`:1282`, `:784`→`:787`, `:483`→`:486`, `:886`→`:889`, `:2211`→`:2214`) and one at
   `docs/refactor-large-modules.md:536` (`control/proxy_ops/mod.rs:2995` → `:2713`, which had also gone past
   EOF at the head). Both were caught in review rather than by the guard; the completeness scan that
   should have found them had been capped with `| head -20` (Correction 7).
4. **The re-bake moved the weak-anchor population.** The table's pins went `checked=580 weak=104` →
   `weak=103` with the set pin `dbbea8513634ee3b` → `564fea99514dcb24`, because one re-pointed cite now lands on text
   unique within its target file; `ambiguous=3`, `excluded=101` and the 580 total are unchanged. The
   re-bake rewrote 27 citation rows plus the pins header line (the table diff is 28/28) and is idempotent afterwards (`0 added,
   0 removed, 580 unchanged`), with `ci.yml`'s `guard_data_pin` re-baked to `294f26cb5c534900d021efc138c46f4b26b5d61f2f650b6b81a95248663de67f`.
5. **`scripts/large-functions.sh` ignores `--top` unless it is the first argument.** The brief's
   `large-functions.sh --all --top 20` silently ran the default list; use `--top N --all`. No measurement
   in this seam depends on it — the two sizes above were read from the full run — but the invocation is
   corrected here so the next seam does not mistake a default list for a filtered one.
6. **The records commit forced a second, larger citation cascade, and the pin re-bake followed from it.**
   Inserting this seam's ledger paragraph (a blank plus 22 lines after base `TODO.md:8164`) shifted every
   cite into `TODO.md` below that point by **+23** — 58 cites in 24 files. The set was computed with the
   guard's own cite rules (full `TODO.md:N` plus its bare-`:NNNN` continuation forms, with the four
   point-in-time files and the three point-in-time directories excluded), so it evaluated exactly the 101
   references `todo-cite-guard` counts, and every shifted cite was checked by base/head line-text identity
   (0 mismatches) instead of by a FAIL list. Six of the 24 changed files are themselves pinned guard
   scripts, so six `ci.yml` literals moved — `guard_pin` for `scripts/tests/repo-health-fixtures.sh`,
   `scripts/tests/compat-stray-guard.sh`, `scripts/tests/remote-frps-reap.sh` and
   `scripts/tests/ab-measurable-delta.sh`, `guard_cls_pin` for `scripts/ab-measurable-delta.sh` and
   `guard_matrix_pin` for `scripts/ab-matrix.sh` — one shifted cite sits inside scenario 10's pinned
   region (`SCEN10_REGION_SHA`), and the table's own `guard_data_pin` moved to the value in Correction 4.
   The deferred class-wide repair of the six mis-aimed R1/R5 cites must use their post-cascade numbers:
   the cites now read `TODO.md:10782` (×4) and `:10827` (×2), and the correct targets are `:10807` and
   `:10860`. (`:10827` has three raw occurrences: `frp-core/src/cli.rs:5072` is correctly aimed at the R2
   entry, so only the other two are in the mis-aimed R5 subset.)

7. **The six cites written from point-in-time documents are a second guard-blind class, and a
   completeness scan must never be capped.** `pathline-cite-guard` skips every cite *written in* a
   point-in-time file, so `TODO.md:6950-6953` and this plan's own `:536` were invisible to it; the
   seam's shift script inherited that blind spot **and** its partial-path scan was piped through
   `| head -20`, which cut exactly those hits. The rule is the map, not the FAIL list: enumerate every
   cite class (full path, `<dir>/mod.rs:N`, `<a>/<b>/mod.rs:N`, `mod.rs:N`, bare `:N` continuations,
   `A-B`/`A–B` ranges) with no output cap, then validate every endpoint by base/head line-text identity.
8. **The plan's own seam table hid 26 endpoints — the same point-in-time class as Correction 7, not a
   third one.** Rows 4–8 name their targets as bare `mod.rs:N` / `mod.rs:A–B` with no directory prefix.
   The guard *does* parse that token: it resolves to more than one tracked `mod.rs`, so in a scanned file
   it is reported as ambiguous and reddens the ambiguous-path set pin (measured by appending a bare
   `mod.rs:1282` cite to `docs/developing.md` in a scratch tree: `FAIL the ambiguous-path set changed
   (pinned 3343d4d37da5672a, measured ad51951a0fbd3a52)`, 580 checked / 1 violation). Rows 4–8 escape
   only because this plan is in `PIT_FILES`, exactly like the six cites in Correction 7. The 26 endpoints
   were therefore re-pointed by hand under the same explicit map, each verified with `grep -n` of the
   named symbol at the head. Row 3 also changed convention without saying so: it now states both the moved
   window (`:2696`/`:2858`) and the `fn` declaration lines (`:2703`/`:2867`) that rows 4–8 use.
9. **The move changed the operator-visible `tracing` target.** The eight event sites in the moved window
   and its `#[instrument(skip(...))]` span carry no explicit `target:`, so they now render
   `target: frp_server::control::proxy_ops::tcp_group`, and a panic in the moved code reports
   `tcp_group.rs:`+line. No test pins that string and no gate asserts a log target, so every lane stayed
   green; `RUST_LOG` directives are unaffected because `frp-core/src/logging.rs:396` (`filter_from_env`)
   builds a static `Targets` filter, whose `a::b=level` directives prefix-match the longer module path.
   PR #453 recorded this class for the log sites it moved into `vhost.rs`; recording it here keeps the
   two seams consistent.
10. **Adversarial review falsified the W1 coverage wording.** The paragraph above originally read "an
    `eprintln!("M1-ENTERED")` probe printed 0 times, so no lane ever enters `tcp_group.rs:29-182`". At
    head `e2b0dc45` the probe prints **once** (`1 passed; 0 failed`, exit 0) when the lane's own test runs
    with `--nocapture` (`cargo test -p frp-server --features dashboard --test http_plugin
    test_plugin_new_proxy_content_user_object_and_fields`) — and 0 times without it, because libtest
    captures a passing test's output. The mutation's conclusion (a `panic!` at that entry survives every
    lane) still holds, but for the real reason: the listener is a detached `tokio::spawn` task whose panic
    nothing observes, so the *task's* failure is unobservable in every lane. The lane does reach the
    function — `frp-server/tests/http_plugin.rs:552` (`full_new_proxy`) builds a `tcp` proxy with
    `group: Some("g1")` (`:563`/`:566`), the test calls it at `:637`, and the control connection drives
    `mod.rs:1461-1462` `is_tcp_group` → the `:1471` branch → the spawn in `setup_proxy_listeners` at
    `mod.rs:1139-1140`. The same correction is applied to `TODO.md:8179-8182`,
    to the W2 scope (every lib-running job, not the lib lane alone; both witnesses are ungated
    `#[tokio::test]`s), and to the PR body's Coverage section.
11. **The new module doc's call sites were swapped, and `tcp_group.rs:7-8` is fixed here.** That
    sentence named the callers as `handle_new_proxy` (base lines 1072, 1186, 1505) and
    `setup_proxy_listeners` (base line 1137); the enclosing-function scan shows base `1072`, `1137` and
    `1186` all sit inside `setup_proxy_listeners` (base `:886`) and only `1505` inside `handle_new_proxy`
    (base `:1279`) — the numbers were right, the owners swapped. The mis-attribution is new prose written
    by this seam (the `//!` block at `tcp_group.rs:1-8` does not exist at `bcdad888`) and it sits outside
    the byte-identical window (`:22-303` == base `:2696-2977`), so editing it cannot disturb the round-trip
    hashes — the adversarial delta review rejected the original "pre-existing, deferred for byte-identity"
    rationale and the owners are swapped in the records commit. No guard and no test sees the sentence.

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

**P5 client landed (2026-10-07, PR #517) — `work_conn/udp.rs`.** The UDP/SUDP work-connection
family moved out of `frp-client/src/work_conn.rs` into the child module
`frp-client/src/work_conn/udp.rs` as one moved window (base `work_conn.rs:411-1442`, 1032 lines, sha1
`eadd1c10…` → `udp.rs:9-1043`), differing only by `pub(super)` on the 17 declarations the inline test
module still drives plus one rustfmt signature reflow; parent 3030 → 2006 lines. The moved log sites
now render `target: frp_client::work_conn::udp` (`RUST_LOG` prefix matching still covers
`frp_client::work_conn=…`). Mutation witness: `UDP_SESSION_IDLE_TIMEOUT` 30 s → 31 s reds
`udp_session_idle_timeout_is_go_parity_30s`.

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
