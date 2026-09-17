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

## Recommendation

Ranked by *risk reduction per unit of disruption*, using the measurements above.

| Priority | Target | Why | Shape |
|---|---|---|---|
| **P1** | `frp-server/src/service.rs::run` | Largest function in the repo (1291 code lines); **a linear startup sequence**, so extraction is mechanical and low-risk; `handlers/` already sets the precedent for this exact kind of split | ~10 listener blocks → named methods |
| **P2** | `frp-client/src/service.rs` | #1 production file size (4930), #1 churn (53), #1 fix density (230), 84 cfg gates | 5 seams, ~1900 lines |
| **P3** | `frp-client/src/visitor.rs` | #2 production size (3685) and **almost untested** (165 test lines) | 3–4 seams |
| **P4** | `frp-server/src/control/proxy_ops.rs` | `handle_new_proxy` 546 code lines; 2nd-highest fix density | 2–3 seams |
| **P5** | `frp-server/src/control/login.rs::authenticate` (510) and `frp-client/src/work_conn.rs` (`spawn_work_conn` 469, `run_udp_work_conn` 419) | Surfaced only by the measurement script; not on any file-size list | 1 seam each |
| **P6** | `frp-server/src/control/bridge.rs` | Hot data path, highest risk per line changed. Only the UDP family and the injector adapter clearly pay | 2 seams |
| — | `vhost.rs`, `ssh_gateway.rs`, `handlers/*` | Largest production functions are 189 / 318 / 463 code lines and already decomposed by concern | leave alone |

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

| Proposed module | Functions to move | Code lines |
|---|---|---|
| `control/proxy_ops/registration.rs` | `handle_new_proxy` (1849) | 546 |
| `control/proxy_ops/listeners.rs` | `setup_proxy_listeners` (1456), `tcp_group_listener` (3273), `handle_tcp_group_member_registration` | ~407 |
| `control/proxy_ops/ports.rs` | `allocate_proxy_port` (171), `bind_tcp_proxy_with_retry`, port reservations, `PortError` | ~421 |
| *(stays in place, or splits later)* | `register_http_vhost` (968), `register_https_vhost` (1221), `unregister_control` (2869) | ~594 |

`handle_new_proxy` is second only to `run_message_loop` in code size and is a
per-proxy-type dispatch: extracting one proxy type's registration per PR is the
lowest-risk way to shrink it.

*Risk:* **low-medium** — only 14 cfg gates, and `ports.rs` is genuinely
self-contained. Note the inline test modules
(`subdomain_conflict_tests`, `tcp_auto_bind_retry_tests`, `port_error_text_tests`,
4432 lines) move with their code.

*Validation:* `scripts/compat-test.sh` is the key gate — this file produces the
port-allocation error text the compat suite asserts against Go.
`frp-server/tests/` covers registration and group behaviour.

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

### Not a target — `vhost.rs`, `ssh_gateway.rs`, `handlers/` — leave alone

`vhost.rs`'s largest production function (`handle_http1_request`) is **189 code
lines**; the file's size is 50% inline tests. `ssh_gateway.rs` has 135 functions
but a largest of 318 lines, i.e. it is already decomposed by concern.

Splitting either would be churn without a corresponding risk reduction. If
`vhost.rs` must shrink, the honest move is to **extract its inline tests** into
`frp-server/tests/`, not to rearrange the production code.

---

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
