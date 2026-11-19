# Onboarding — first week

You know Rust and you are inheriting a proxy of roughly 210k production lines.
This file is the
reading order, the five commands that define "green", and the traps that cost
the last maintainers real time. It assumes you have `ssh` access to nothing and
a laptop with Rust installed.

The honest estimate, measured while writing this: **you can build and run it in
an hour, change it confidently in three days, and merge without supervision in
about a month.** The month is not the Rust — it is the citation ledger, the
compatibility gates and the review protocol described below.

## Hour 1 — make it run

```bash
cargo build --release -p frps -p frpc     # ~2 min
./target/release/frps -c frps.toml & ./target/release/frpc -c frpc.toml
```

Copy the minimal pair of config files from [`README.md`](../README.md). Then
read, in this order:

1. [`architecture.md`](architecture.md) — 15 minutes. The control/work split,
   the transport stack, the bridge, and the KCP/NAT sections.
2. [`naming.md`](naming.md) — 10 minutes. Three spellings of every config name
   and the ten places a setting touches; this is the highest-yield page here.
3. The rules live in [`../CLAUDE.md`](../CLAUDE.md) — read the
   "Development Workflow" section. It is binding, not advice.

Do not start with [`config.md`](config.md) (1,100 lines of field reference, one
row per setting) or with the audit history in `docs/history/` — both are
lookups, not reading.

## Day 1 — where things are

| You want to change | Start at |
|---|---|
| a config key | [`../frp-core/src/config/server.rs`](../frp-core/src/config/server.rs), [`../frp-core/src/config/client.rs`](../frp-core/src/config/client.rs), then the ten-step checklist in [`naming.md`](naming.md) |
| how bytes are copied | [`../frp-core/src/bridge.rs`](../frp-core/src/bridge.rs) (choose an entry point) and [`../frp-core/src/splice.rs`](../frp-core/src/splice.rs) (Linux fast path) |
| a wire message | [`../frp-core/src/msg.rs`](../frp-core/src/msg.rs) plus [`../frp-core/src/protocol.rs`](../frp-core/src/protocol.rs) — and the contract tests in the same files |
| a proxy type | [`../frp-server/src/control/`](../frp-server/src/control) on the server, [`../frp-client/src/proxy.rs`](../frp-client/src/proxy.rs) on the client |
| a plugin | [`../frp-client/src/plugin/`](../frp-client/src/plugin) |
| KCP behaviour | [`../frp-core/src/kcp/`](../frp-core/src/kcp) — the driver lives in `socket.rs`, the state machine in `protocol.rs` |
| the CLI | [`../frp-core/src/cli/mod.rs`](../frp-core/src/cli/mod.rs) — the *surface* (name, default, help text, Go parity) is a data table (`FRPS_GO_FLAGS`, `FRPC_PROXY_GO_FLAGS`, …) parsed by `bpaf`, with a hand-written argv pre-pass for `-c=value` forms |
| the dashboard / status API | [`../frp-server/src/`](../frp-server/src) behind the `dashboard` feature |

Two reading aids that save a day each:

- Most source files open with a module-level doc comment that says what the
  file owns; read that first, then jump by symbol (your editor's outline or
  `grep -n "^pub \(async \)\?fn \|^pub struct "`). Some modules keep their tests
  in a sibling `<name>/tests.rs` (for example
  [`../frp-core/src/config/tests.rs`](../frp-core/src/config/tests.rs)) and the
  parent ends with a one-line `mod tests;`; others keep an inline
  `#[cfg(test)] mod tests` at the bottom. Check before you scroll.
- [`../TODO.md`](../TODO.md) is the open-work ledger with a done-when per item.
  Headings marked `resolved` are history kept for the evidence.

## The five commands that mean green

```bash
cargo test --workspace --all-features          # needs an all-features frps binary
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
bash scripts/repo-health.sh                     # invariants: paths, versions, toolchain pin
bash scripts/tests/pathline-cite-guard.sh       # line-exact citations
```

and two gates that must be run and cited for anything touching protocol,
transport, encryption or a proxy:

```bash
bash scripts/compat-test.sh                     # 86 scenarios against Go frp v0.72.0
bash scripts/protocol-matrix.sh                 # 11 transport rows must move bytes
```

A green `cargo test` proves frp-rs agrees with itself. Only `compat-test.sh`
proves it agrees with Go frp. Do not cite the unit suite for a compatibility
claim; see [`developing.md`](developing.md).

## Traps that cost the previous maintainers time

1. **Test counts are pinned in CI as literals.** Adding one `#[test]` reds jobs
   in [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) until the
   literal moves (`env.FRPC_CLI_TESTS`, the frps bin `n_floor`, `guard_cites`).
   Bump the count in the same commit, or you lose ten minutes per round trip.
2. **The citation table is line-exact.** Any edit above an existing citation
   shifts it. `--write` re-reads the tree and records whatever the (possibly
   stale) line now says, so a run without a content check silently turns a
   broken pointer into a "passing" one. Re-point by *content* first, then
   `--write`, then re-pin `guard_data_pin`. New files must be `git add`ed first — the guard
   scans tracked files only and will silently drop their rows.
3. **Feature stubs drift.** Under `--no-default-features` the KCP, STUN and
   XTCP types are stubs in [`../frp-core/src/lib.rs`](../frp-core/src/lib.rs)
   (QUIC has no stub — it is gated at each call site instead). A method
   added to the real type and called from shared code compiles with the feature
   on and fails with it off — CI has a lane for each extreme; run
   `cargo check -p frp-core --no-default-features --all-targets` before pushing.
4. **Byte strings are ASCII-only.** Write `"…".as_bytes()` when the text has
   non-ASCII; `b"…"` cannot carry it. And a backslash-continued literal's
   continuation lines are re-indented by refactors without changing its value,
   so a formatter pass is not a semantic change.
5. **`.worktrees/*/target` eats the disk.** A worktree builds its own target
   tree, which is tens of gigabytes with debug info. Use
   `CARGO_TARGET_DIR=<main checkout>/target` and set `FRPS_BIN`/`FRPC_BIN` so
   integration tests find the binaries.
6. **`docs/archive/`, `docs/history/`, `docs/audit/`, `CHANGELOG.md`,
   `TODO.md`, `performance-audit.md` and `docs/refactor-large-modules.md` are
   point-in-time.** Never edit their numbers to match new behaviour; add a dated
   section that says what changed. The citation guard deliberately skips them.
7. **A narrowed build clobbers the dashboard test binary.** `cargo test -p frps`
   or a clippy run that links `frps` replaces `target/debug/frps` with the
   no-dashboard artifact — the same path the dashboard tests resolve through
   `FRPS_BIN` — and the resulting failure says `port N not ready after 15s`, not
   "wrong binary". Build with `cargo build -p frps --features dashboard` and run
   `cargo test -p frp-server --features dashboard -j 1`; the wider
   `cargo test --workspace --all-features` is unaffected.

## Working protocol (non-negotiable)

1. Work in a git worktree, never on `main`.
2. Every change gets **two independent reviews by agents that did not write
   it**, at least one adversarial — its brief is to falsify, not to confirm.
   Record both in the PR with method, findings and disposition. An unrecorded
   review did not happen.
3. Any protocol, transport, encryption or proxy change runs
   `scripts/compat-test.sh` before merge.
4. Do not add a dependency without the three-part justification (why, why not
   an existing crate, binary-size cost) in [`../CLAUDE.md`](../CLAUDE.md).
5. Version numbers track Go frp exactly — bump every crate, `VERSION`, the
   download script and the README together.

## Week 1 — a first change

Pick from [`../TODO.md`](../TODO.md) a P2 that is *measured*: the ledger writes
down the evidence and the done-when. A good first change touches one config
key plus the ten-step checklist — you will feel the citation ledger immediately,
which is the point. Then read
[`refactor-large-modules.md`](refactor-large-modules.md) for the structural
work that is queued, and [`history/development-log.md`](history/development-log.md)
if you want the reasoning behind a decision you disagree with.
