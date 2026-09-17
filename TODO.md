# TODO — repository optimization backlog

**Live backlog.** The previous `TODO.md` (feature/parity tracking, fully resolved)
moved to [`docs/history/feature-backlog.md`](docs/history/feature-backlog.md).
Round-by-round hardening history is in
[`docs/history/development-log.md`](docs/history/development-log.md).

**Opened:** 2026-09-17, from a documentation audit at `89951ae`.
**Scope:** repo hygiene, documentation correctness, structural debt.
Not a feature roadmap.

## How to use this file

Every item carries **evidence** (a number or `file:line` that can be re-checked)
and **done-when** (an acceptance test). An item without both is a wish, not a
task. Tick the box in the same PR that satisfies `done-when`.

Priority is by *risk removed per unit of effort*, not by size:
**P0** hygiene → **P1** correctness → **P2** structure → **P3** strategic.

---

## P0 — hygiene

- [x] **`CLAUDE.md` health numbers were undated and stale.**
  Evidence: the table claimed 17 `unsafe` blocks in `frp-core`; the tree had 21.
  It also had no date or commit, so a reader could not tell how old any figure was.
  Done: added "Last verified" date + commit; countable figures now come from a script.

- [x] **Countable figures were hand-maintained.**
  Evidence: `unsafe`, LOC, test counts, vendored versions all typed into prose and drifted.
  Done: added `scripts/repo-health.sh` — prints code size, test/proptest counts,
  `unsafe` blocks, vendored versions, and **gates version alignment** (exit 1 on drift).

- [x] **Internal tool state was tracked in git.**
  Evidence: `git ls-files .superpowers` listed `.superpowers/sdd/progress.md`.
  Done: untracked and added `.superpowers/` to `.gitignore`.

- [x] **`.gitignore` contradicted the repo.**
  Evidence: `.gitignore` listed `Cargo.lock` while `Cargo.lock` is tracked
  (correctly — frp-rs ships binaries). The rule was inert and invited someone to
  "fix" it by untracking the lock.
  Done: removed the line, documented why the lock is committed.

- [x] **Duplicated content across live docs (4 sites).**
  Evidence: feature-flag table identical in `CLAUDE.md` and `docs/developing.md`
  (19 rows each); `Dependency Policy` in both; `Workspace Overview` in both
  `developing.md` and `architecture.md`; two doc indexes (`README.md` and
  `docs/README.md`).
  Done: each has exactly one canonical home; the rest are pointers.
  Note: merging surfaced a real drift — `developing.md`'s banned list had `hex`
  and `tokio-tungstenite`, which the canonical list lacked; they were merged in
  before the duplicate was deleted.

- [x] **A real SSH private key lives in the repo root.**
  Evidence: `.autogen_ssh_key` begins `-----BEGIN OPENSSH PRIVATE KEY-----`
  (Ed25519, SHA256:a8zw/whUpgVrIf7ytF5yQKisZyssRjaMEyEuHEDJIC8).
  **The original characterization in this item was wrong** — it is not test
  material. It is the *runtime* default host key path for the SSH tunnel
  gateway (`sshTunnelGateway.autoGenPrivateKeyPath` defaults to
  `"./.autogen_ssh_key"`, `frp-core/src/config/server.rs:443,469-470`, matching
  Go frp), so it appears whenever `frps` runs with the gateway enabled from the
  repo root. It authenticates nothing outside the local machine and was never
  committed (gitignored, `git ls-files` → 0).
  Done: documented in `.gitignore` (naming what the file is and why it must not
  be committed) and in `docs/config.md § ssh_tunnel_gateway`, including the
  option to point `auto_gen_private_key_path` outside the repo. No code change:
  the relative default is Go frp parity and changing it would be a divergence for
  a dev convenience.

- [x] **Orphaned worktree directory.**
  Evidence: `.claude/worktrees/vnet-route-ownership/` (46 MB) existed on disk but was
  absent from `git worktree list` — an already-pruned worktree whose `.git` file
  pointed at a deleted gitdir. It contained a stale copy of `docs/developing.md`,
  which **actively polluted repo-wide greps** (it produced false hits during this audit).
  Done: removed locally, and the stale `origin/worktree-vnet-route-ownership`
  remote-tracking ref pruned. Verified before deleting that the branch's two commits
  (`e271ac2`, `d8f77e0`) were already in `main` via the **squash** of #325 — all Rust
  files byte-identical, so nothing was lost. (They are not ancestors of `main` only
  because squash rewrites history — the same reason this backlog's own PRs are not.)
  Note: local-only cleanup, not part of any PR.

- [x] **`repo-health.sh` is not wired into CI.**
  Evidence: the version-alignment check is a documented *mandatory* rule
  (`CLAUDE.md § Versioning`) that had been enforced by memory only.
  Done: added a `health` job to `ci.yml` (no Rust toolchain, no cache — reads
  files with grep/find, so it costs seconds) that runs
  `bash scripts/repo-health.sh` and fails the build on drift. A version bump that
  misses `VERSION`, the download script or the README now fails CI instead of
  being noticed at release time.

---

## P1 — documentation correctness

The core problem this audit surfaced: **relocation fidelity was verified; content
truth was not.** Line counts, hashes and links prove bytes moved intact — they say
nothing about whether the described behaviour still holds.

- [ ] **No mechanism keeps prose in sync with code.**
  Evidence: `unsafe` 17→21 (fixed here); `docs/developing.md` claimed four vendored
  yamux patches when `vendor/yamux/README-FRP-RS.md` documents **five**;
  `~N lines` figures attached to filenames had gone stale by 2–5×.
  **Done-when:** every quantitative claim in a live doc is either generated by
  `repo-health.sh` or carries a `file:line` that a reviewer can check. Add a
  periodic (release-checklist) pass that re-verifies them.

- [x] **The docs did not tell the reader how little a green test suite proves.**
  Evidence: `docs/history/development-log.md` records the project's own tests
  encoding **wrong** behaviour and later being flipped (round 15→16 `SplitHostPort`
  premise; round 6 "stale pin"; round 4 "the round-3 claim was wrong — the test was
  RED"; round 9 returned "test completeness below standard" while 1253 tests were
  green, and its fixture kept `authentication_timeout = 0` so the replay protection
  under test was never exercised). Most tests pin *frp-rs's* behaviour at the time,
  not *Go frp's*.
  Done: new authoritative section
  [docs/developing.md § What a green test run does and does not prove](docs/developing.md#what-a-green-test-run-does-and-does-not-prove)
  — it separates hard evidence (compat suite, protocol matrix, XTCP VPS matrix)
  from proxy evidence, lists seven concrete cases from this project's history, and
  gives four practical rules (notably: cite Go source `file:line` or a probe of the
  real binary, never a passing test). A rule box in `CLAUDE.md § Testing & Tooling`
  and a convention in `docs/README.md` point at it.

- [x] **`CHANGELOG.md` and `docs/history/development-log.md` overlap.**
  Evidence: "audit round" appears 10× in `CHANGELOG.md` (91 KB) and 17× in
  `development-log.md` (109 KB); the same rounds were described in both, at
  different levels of detail, with no rule about which wins.
  Done: the boundary is decided and written where the conflict would arise —
  `CHANGELOG.md` = user-facing release notes (a few lines per item);
  `development-log.md` = the detailed record (findings, review outcomes, gate
  results, commit hashes); never the same detail twice, because two copies drift.
  Stated in `docs/README.md § Conventions`, at the top of `CHANGELOG.md`, and at
  the top of the development log. Historical entries are left as written.

- [x] **Paths inside `docs/archive/**` still read `docs/superpowers/`.**
  Evidence: deliberate (historical records must not be rewritten), but a reader
  following one hits a dead path.
  Done: rather than hand-listing "high-traffic" files, the translation is now
  **measured** — `scripts/repo-health.sh` reports how many `docs/superpowers/…`
  references exist inside the archive and how many resolve under the new prefix.
  Current: **20 references, 19 resolvable**. The single exception
  (`plans/2026-06-28-v2-protocol-implementation.md` → a spec that was never
  written) was already dangling before the rename and is named in
  `docs/archive/README.md` rather than rewritten to point elsewhere.

- [ ] **`docs/developing.md` and `docs/architecture.md` can still drift.**
  Evidence: after the merge they no longer duplicate sections, but both describe
  transports and encryption at some level, with nothing linking a claim to its
  source of truth.
  **Done-when:** `developing.md` contains no statement a reader could act on that
  is not either in `architecture.md` or referenced `file:line`.

- [x] **A source comment pointed at a path that no longer held code.**
  Evidence: `frp-core/src/kcp/protocol.rs` opened with "the frp-rs in-tree
  replacement for the vendored `kcp` crate (`frp-core/vendored/kcp-0.6.0`)" — but
  that directory had been emptied when the KCP state machine moved in-tree
  (`docs/archive/specs/2026-07-06-replace-rust-tokio-kcp-design.md:145,153`;
  `CHANGELOG.md`, "KCP self-implementation"). What remained was
  `frp-core/vendored/kcp-0.6.0/Cargo.lock` and nothing else, so a reader
  following the comment found no source.
  Done: the comment now records that the crate was removed and points at the
  changelog instead of a path that cannot be opened; the orphaned
  `frp-core/vendored/` directory was deleted locally (untracked, so not part of
  any commit).

- [ ] **No automated check for stale path references — and a naive one does not work.**
  Evidence: a regex sweep for repo-looking paths that do not resolve produced
  **135 hits, essentially all false positives**: `Cargo.toml` feature syntax
  (`frp-core/tls` is a feature, not a path), and crate-relative paths in
  per-crate READMEs and `Cargo.toml` (`src/lib.rs`, `tests/kcp.rs` resolve
  relative to that crate, not the repo root). It also **missed the one real
  finding above**, because the stale path was a directory that still existed.
  **Done-when:** either a check that resolves each path relative to the
  referencing file's own directory and distinguishes `Cargo.toml` feature syntax
  — or an explicit decision that this class stays a manual review item.
  Do not ship the naive regex as a CI gate: it fails on a clean tree.

- [x] **Documentation index is manual.**
  Evidence: `docs/README.md` lists docs by hand, so a new doc was invisible until
  someone remembered to add it.
  Done: `scripts/repo-health.sh` (the `health` CI job) now **fails** if any
  `docs/*.md` (except the index itself) or any `docs/*/` directory is not named in
  `docs/README.md`. Verified both ways: the tree passes today; removing a filename
  from the index fails the gate.

---

## P2 — structural

- [ ] **Very large source files.**
  Evidence: `frp-server/src/control/proxy_ops.rs` 8043 lines,
  `frp-client/src/service.rs` 6381, `frp-server/src/vhost.rs` 6311.
  These are the files most likely to hide an ordering bug — the project's own
  history shows ordering/lifecycle defects concentrated there (round 8 auth-bypass,
  round 10 TOCTOU, round 14 half-frame loss).
  **Done-when:** at least one of them is split along a seam with no behaviour change
  and the compat + protocol-matrix gates stay green.

- [x] **Three vendored crates are a standing maintenance liability.**
  Evidence: `vendor/rustls` (TLS, patched), `vendor/yamux` (5 patches),
  `vendor/russh` (2 patches). `[patch.crates-io]` pins them: upstream security
  releases do **not** arrive via `cargo update`.
  Done: the obligation now has a home instead of living in prose. A
  **pre-release checklist** in
  [`docs/developing.md § 6`](docs/developing.md#pre-release-checklist) makes the
  vendored-crate review an explicit release step (check 0.23.x rustls advisories,
  re-read each `vendor/*/README-FRP-RS.md`, confirm the exit condition has not
  arrived), and the README's vendored table points at it. The checklist notes
  honestly that with a single maintainer there is no second reviewer and the
  checklist line *is* the control. The rustls exit is now its own tracked item
  below.

- [ ] **Upgrade to rustls ≥ 0.24 and delete `vendor/rustls`.**
  Evidence: the vendored tree exists only to treat an invalid TLS SNI as "no SNI"
  so Go frp's XTCP QUIC visitors interoperate (`ip:port` as SNI). rustls ≥ 0.24 has
  `invalid_sni_policy = IgnoreAll` natively, which is exactly this behaviour.
  Until then, `[patch.crates-io]` means 0.23.x security releases must be tracked
  by hand — the highest-risk item on the release checklist.
  **Done-when:** the workspace is on rustls ≥ 0.24, the patch is expressed as
  `ServerConfig::invalid_sni_policy`, `vendor/rustls` and its `[patch.crates-io]`
  entry are deleted, and the XTCP QUIC compat scenarios still pass.

- [x] **`unsafe` has no automated guard.**
  Evidence: 21 blocks + 3 `unsafe fn` + 2 `unsafe impl` in `frp-core`; 38 blocks in
  `frp-vnet`; 64 `// SAFETY:` comments. The convention was enforced by review.
  Done: `scripts/repo-health.sh` now fails if an `unsafe {` block has no
  `// SAFETY:` justification, and that script is a CI gate (the `health` job).
  The check walks up over the whole contiguous comment/attribute block and also
  scans a few lines *into* the block — a first attempt using a fixed 3-line
  look-behind reported **14 false positives** on a clean tree, because the
  justification is usually a multi-line comment block or sits inside the block.
  Verified in both directions: clean tree passes; deleting one marker fails.
  One genuine gap was found and fixed rather than papered over:
  `frp-core/src/splice.rs` had two adjacent `unsafe { OwnedFd::from_raw_fd(..) }`
  expressions sharing a single justification comment, so the second block carried
  none of its own — it now has one (comment-only change).

- [ ] **Feature surface is wide for a single maintainer.**
  Evidence: SSH gateway, L3 VPN/TUN, OIDC, dashboard, h2c, 10 client plugins,
  SUDP, V2 protocol, and two XTCP data planes — each with its own parity debt.
  **Done-when:** an explicit keep/opt-in/drop decision per surface is recorded, so
  effort stops spreading by default.

---

## P3 — strategic

- [ ] **Bus factor is 1.**
  Evidence: of ~1450 commits, 1231 are one human author and 219 are an AI agent.
  No second person can currently review a protocol change.
  The documentation work removed the *reading* barrier (a 143 KB instruction file
  that was silently truncated is now a 20 KB one), but not the *authoring* barrier.
  **Done-when:** a written contributor path exists that does not require the
  original author — e.g. "add a client plugin" documented end-to-end and validated
  by someone else following it. (`docs/developing.md § Adding a New Proxy Type` is
  the closest existing artefact.)

- [ ] **Differentiation is thin.**
  Evidence: the README's pitch is mainly binary size (~8.5 MB vs Go frp ~15 MB) and
  memory. That is real but rarely sufficient to migrate off a mature, actively
  maintained upstream.
  **Done-when:** a short, honest positioning note: which use cases frp-rs is the
  better choice for, and which it is not.
