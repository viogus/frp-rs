# Binary Size Optimization Plan

> **Status 2026-08-06:** refreshed with fresh measurements (Linux, HEAD c8882d8,
> release profile). Baseline: **frps 8.42 MB / frpc 7.35 MB** (frps `.text` 5.2 MiB).
> Task-by-task verdicts below: ✅ valid, ❌ disproven, ⛔ rejected/obsolete.
> Methodology authority: `docs/superpowers/notes/2026-08-size-optimization-analysis.md`
> (LTO fat GCs uncalled code — verify every candidate with `cargo bloat` before acting).

## Goal

Reduce frps (8.42MB) and frpc (7.35MB) binary sizes through three phases:
quick wins, feature flag tuning, and deep optimization.

## Global Constraints

- All changes must be backwards-compatible with existing config files
- Must not regress `cargo test --workspace --all-features` (804 passed, 0 failed)
- Must not regress `cargo clippy --workspace --all-targets --all-features -D warnings`
- Must not regress `cargo fmt --all -- --check`
- Must not regress compat test suite (72 run_test + 17 XTCP with Go frp v0.70.1)
- Binary strip (`strip = "symbols"`) must remain effective
- No new dependencies without justification per CLAUDE.md dep policy
- Size A/B must use same-env stash comparison (same worktree, same target cache);
  ~17 KB (0.2%) layout jitter exists between identical rebuilds

## Task Status Summary

| Task | Verdict | Why |
|---|---|---|
| 1. authenticate monomorphization | ✅ valid | live at 45.1KB today |
| 2. Box Service::run closure | ✅ valid | live at 101.5KB today (largest fn) |
| 3. Disable backtrace symbolication | ❌ disproven | no gimli/backtrace in bloat output — LTO already GCs it |
| 4. Extract pure logic from async closures | ✅ valid | assign_work_to_proxy 53.9KB, handle_new_proxy 44.1KB |
| 5-7. Feature default tuning (SSH/QUIC/dashboard opt-in) | ⛔ rejected | user decision: default matrix stays (2026-08 analysis note) |
| 8. Replace toml_edit with toml | ⛔ obsolete | `toml` 0.8 already uses toml_edit internally; no separate dep |
| 9. Split frp-core into feature-gated modules | ❌ low value | LTO GC semantics make "compilation unit" splits ineffective; see note |
| 10. panic_immediate_abort (nightly) | ✅ parked | requires nightly; only revisit with -Zbuild-std work |

## Phase 1: Quick Wins (target: 8-12% reduction, ~600-900KB)

### Task 1: Eliminate `authenticate` generic monomorphization ✅
- **What:** frps `authenticate` generates one 45.1KB closure (measured 2026-08-06).
  Erase to `&mut dyn AsyncRead`/`&mut dyn AsyncWrite` since auth is per-connection (not hot-path).
- **Files:** `frp-server/src/control/login.rs`
- **Expected:** ~40KB reduction (frps)
- **Risk:** Low — auth happens once per connection start

### Task 2: Box large async futures ✅
- **What:** `Service::run` inner closure is 101.5KB — the single largest function in frps.
  Box the innermost async block to reduce stack-frame code.
- **Files:** `frp-server/src/service.rs`
- **Expected:** ~40-60KB reduction (frps)
- **Risk:** Low — one heap alloc per connection

### Task 3: Disable backtrace symbolication ❌
- **What (claimed):** `std::backtrace_rs::symbolize::gimli` (16.9KB) linked even with
  `panic = "abort"`.
- **Measured:** no gimli/backtrace symbols in `cargo bloat` output — with
  `panic = "abort"` and no `Backtrace::capture` call sites, LTO fat GCs the whole
  chain. Nothing to remove.

### Task 4: Extract non-async pure logic from large async closures ✅
- **What:** `assign_work_to_proxy` (53.9KB), `handle_new_proxy` (44.1KB) contain pure
  data-construction logic mixed into async state machines. Extract config building,
  message construction, and validation into non-async helper functions.
  (`dispatch_frp_message` no longer in the top-17 — re-verify before touching.)
- **Files:** `frp-server/src/control/bridge.rs`, `frp-server/src/control/proxy_ops.rs`
- **Expected:** ~50-80KB reduction (frps)
- **Risk:** Low — pure refactoring, no behavior change

## Phase 2: Feature Flag Tuning ⛔ (user decision: default matrix unchanged)

### Task 5: Make SSH (russh) opt-in
- **What:** russh + ssh_key = 397KB (7.6% of frps .text today). Change `ssh` feature
  from default-on to opt-in.
- **Verdict:** rejected — user decided default feature matrix stays as-is.

### Task 6: Make QUIC opt-in
- **What:** quinn_proto + quinn = 269KB (frps). Change `quic` feature from default-on to opt-in.
- **Verdict:** rejected — same user decision.

### Task 7: Make dashboard (axum) opt-in
- **What:** dashboard is already opt-in today (not in default features).
- **Verdict:** obsolete — already done.

### Task 8: Replace `toml_edit` with `toml`
- **Verdict:** obsolete — `toml` 0.8 (the dep in use) internally depends on
  toml_edit; there is no separate toml_edit dependency to remove.

## Phase 3: Deep Optimization

### Task 9: Split `frp-core` into feature-gated modules ❌
- **What:** frp-core contributes 658KB (frps, 12.5% of .text). Split into
  feature-gated compilation units so the linker can eliminate unused code paths.
- **Verdict:** low value — LTO fat means code without callers is already GC'd;
  feature-splitting only helps where code is *conditionally referenced*, which
  the existing feature matrix already covers.

### Task 10: `panic_immediate_abort` (nightly) ✅ parked
- **What:** Nightly `panic_immediate_abort` skips drop glue on panic path entirely.
- **Verdict:** parked — requires nightly toolchain + CI changes; revisit only if
  `-Zbuild-std` work is ever undertaken.

## Execution Order

Phase 1 → (Phase 2/3 blocked per verdicts above). Within Phase 1, tasks are
independent and can run in any order; each must be verified with same-env
stash A/B per the 2026-08 analysis note.
