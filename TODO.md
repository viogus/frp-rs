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

- [ ] **`frpc`'s `GET /api/reload` diverges from Go frp — it requires a JSON body.**
  Evidence: the handler is
  `async fn handle_reload(State(state), Json(body): Json<ReloadBody>)`
  (`frp-client/src/admin.rs:155-161`), and the route deliberately registers `get`
  for Go compatibility (`admin.rs:585-586`: "Go frp compat: GET /api/reload (Go uses
  GET; keep POST too)"). axum's `Json` extractor requires
  `Content-Type: application/json` and rejects a body-less request with **415**, so
  the Go-compatible call `curl -u user:pass http://127.0.0.1:7400/api/reload` —
  which works against Go frp — does not reload here. Anything driving the endpoint
  from Go's route table hits this.
  Found while completing the endpoint tables in `docs/deployment.md`; documented
  there as a caveat rather than left implicit.
  **Done-when:** a body-less `GET /api/reload` returns 200 and reloads in
  non-strict mode (optional extractor or an empty-body default), with a test pinning
  all three cases: body-less GET → 200, `{"strict_config": true}` → strict mode,
  malformed body → 400.

- [ ] **The `tiny`/`micro` feature builds emit warnings, and CI does not deny them.**
  Evidence: `cargo build --release --no-default-features --features tiny|micro`
  on `main` reports (macOS arm64, rustc 1.96.0):
  - `frp-server/src/vhost.rs:3` — unused import `AsyncWriteExt` (its method call
    sites are feature-gated out of the small tiers)
  - `frp-client/src/plugin/mod.rs:153` `take_plugin_peer` — never used once the
    TLS plugins are compiled out
  - `frp-client/src/plugin/mod.rs:160` `plugin_peer_ip` — same
  `CLAUDE.md` claims "zero warnings on all 4 profiles", which is true on Linux
  (`-D warnings` runs only on `--all-features` clippy, where all three are used)
  and false elsewhere. The `Verify (bench + feature sets)` CI job runs
  `cargo check --no-default-features --features tiny|micro` **without** denying
  warnings, so it cannot catch this.
  **Done-when:** the three sites are correctly cfg-gated (or `allow`ed with a
  reason), and the tier check runs with `RUSTFLAGS="-D warnings"` so the claim
  becomes enforced instead of asserted. Verify each tier on macOS *and* Linux —
  `vhost.rs:3` is feature-gated, the `plugin/mod.rs` pair is feature-gated, and a
  fourth warning (`static_file.rs:1090` unused `file`) was platform-gated and is
  fixed in the same PR that added this item.
  (Also found on the same run: `cargo build -p frpc` warned on
  `static_file.rs:1090` because `file` is only read in the `target_os="linux"`
  branch — fixed, `let _ = file;` in the non-Linux arm.)

- [ ] **The compat gate is flaky, which weakens the project's strongest claim.**
  Evidence: on 2026-09-17 the `compat` CI job failed **2 of 3 consecutive runs on
  the same commit**, with different scenarios each time —
  `go-to-rust-quic: FAIL:CONNECT_TIMEOUT`, then `tcp-tls` and `tcp-tls-mux` at zero
  throughput plus `ws-plain` "proxy port not reachable" — and passed on the third.
  The diff was provably not the cause (its only compiled change sat inside a
  `#[cfg(not(target_os = "linux"))]` block, so the Linux binary was byte-identical),
  and the repo's history already records similar flakes that were "rerun 过"
  (ETXTBSY during a compat unit test; a VPS disk-full in `ab-matrix`).
  This matters more than a normal flake: `compat-test.sh` is the evidence the
  project treats as authoritative, and `CLAUDE.md` quotes "86 passed, 0 failed" as
  a health number. A gate that fails ~2/3 of the time cannot be used to distinguish
  a regression from noise, and the habit of rerunning until green is how a real
  failure eventually gets merged.

  **Recurrence (2026-09-17, PR #338 — a `TODO.md`-only diff, so nothing compiled
  could have changed):** `compat` failed not in the compat scenarios but in its
  `Run Rust unit tests` step — **851 passed, 1 failed**:
  `auth::tests::test_resolve_dynamic_token_exec_failure_redacts_stderr` panicked at
  `frp-core/src/auth.rs:3561` with
  `Failed to exec dynamic token command: Text file busy (os error 26)`. That is
  **ETXTBSY**: `execve` refuses a file that is open for writing in some process.
  The test writes a shell script to `$TMPDIR/frp-token-script-{pid}.sh`, chmods it,
  execs it and removes it (`auth.rs:3530-3570`); it asserts the error retains the
  *exit-status* class, and on this run got a *spawn* error instead. The name is
  keyed only on the process id, and the exact mechanism (pid reuse, a shared
  `$TMPDIR` on the runner, or fs behaviour under CI) is **not** confirmed — this
  records the symptom, not a diagnosis.
  **Done-when:** the flaky scenarios are identified by running the failing subset
  in a loop (`compat-test.sh --test <display-name>` makes this cheap), the cause is
  fixed or the scenario is documented as timing-sensitive with a bounded retry, and
  the reason is recorded. For the ETXTBSY case specifically: the exec-token test
  gets a name that is unique per invocation and is made robust to a busy script
  file, keeping the exit-status assertion rather than loosening it. Until then,
  `docs/developing.md` tells readers to re-run a red compat result before believing
  it, and not to treat green as absolute.

- [ ] **`Tests (server integration)` fails intermittently, and it turns `main` red.**
  Evidence: on 2026-09-17 the CI run for the merge commit `d9ca98b` failed on
  `Tests (server integration)` — **13 passed, 1 failed** —
  `test_ssh_gateway_exec_go_parity_errors_and_stcp_accept` panicking at
  `frp-server/tests/ssh_gateway.rs:943` with `SSH client should connect`. The
  **identical tree had passed that same job** minutes earlier on the PR head
  (`e75c637`, run 35244274080), and the re-run passed, so this is the test and not
  the diff.
  The mechanism is visible in the code: `connect_ssh_auth` retries
  `russh::client::connect` only `for _ in 0..20` with a 100 ms sleep
  (`ssh_gateway.rs:928-943`), a fixed window of roughly **2 seconds**, and then
  `expect`s success — so a loaded runner that takes longer than that to start
  accepting on the gateway panics. It is not a one-off: the same `0..20` + 100 ms
  pairing is repeated at lines 102, 224, 282, 345, 454, 591, 697, 797, 862 and 930,
  so those SSH-gateway tests share the same under-sized readiness budget. (A further
  `for _ in 0..20` at line 644 retries raw connections with its own 2 s per-attempt
  read timeout, so it is a different shape.)
  **Done-when:** readiness is a shared helper that polls against a wall-clock
  deadline sized for CI instead of a fixed ~2 s, applied at every site above, and a
  genuine connect failure still fails loudly with the last error rather than a bare
  `expect`. Other waits in this file already work at that scale
  (`Duration::from_secs(5)` at lines 250 and 406, `from_secs(10)` at 886 and 905),
  so there is a precedent to match rather than a new convention to invent.
  Same class as the compat-gate item above: a gate that fails intermittently on
  unchanged code cannot distinguish a regression from noise, and rerunning until
  green is how a real failure eventually gets merged.

- [x] **`docs/developing.md` and `docs/architecture.md` can still drift.**
  Evidence: after the merge they no longer duplicate sections, but both describe
  transports and encryption at some level, with nothing linking a claim to its
  source of truth.
  **Done-when:** `developing.md` contains no statement a reader could act on that
  is not either in `architecture.md` or referenced `file:line`.
  Done: §1/§2 are the only sections that make structural claims; §3-§6 and the
  dependency policy are process/tooling and were left alone. Measured: **9
  in-scope code-location statements** — §1's workspace/dependency description;
  §2's config struct, NewProxy entry point, registration-into-ProxyManager,
  port allocation, sk_index/vhost/tcpmux routing, listener setup,
  `InternalMsg::ProxyUserConn` construction, and bridging dispatch.
  **1 became a pointer** — §1's six-crate graph and ASCII diagram now defer to
  [architecture.md § Overview](docs/architecture.md#overview), which already
  carried the authoritative version. The other **8 carry 13 `file:line` anchors
  naming the symbol**, each verified by opening that exact line in this worktree
  (`ProxyConfig` at `frp-core/src/config/client.rs:585`; `handle_new_proxy`
  `proxy_ops.rs:1849`; `register_proxy_entry` `proxy_ops.rs:794`;
  `allocate_port_multi` `proxy.rs:821`; `register_sk_index` `proxy_ops.rs:493`;
  `setup_proxy_listeners` `proxy_ops.rs:1456`; `listen_and_proxy`
  `proxy_ops.rs:2781`; `ProxyManager` `proxy.rs:116`; `VhostManager`
  `vhost.rs:265`; `TcpMuxManager` `tcpmux.rs:34`; `InternalMsg::ProxyUserConn`
  `state.rs:344`; `assign_work_to_proxy` `bridge.rs:3117`;
  `run_work_bridge` `bridge.rs:2430`). **Two live errors were found and fixed en
  route**: `listen_and_proxy()` does not start listeners for
  http/https/stcp/tcpmux — only `tcp` binds a per-proxy listener — and
  `listen_and_proxy_udp()` does not exist anywhere in the tree (UDP/SUDP bind an
  `Arc<UdpSocket>` inside `setup_proxy_listeners`). A short rule near the top of
  `developing.md` now states the invariant for future editors. Residue, stated
  explicitly: §3's feature-flag/binary-tier claims and §5's "86 run_test
  scenarios" figure are hand-maintained numbers that can go stale, but they are
  process facts owned by the separate hand-maintained-numbers item, not
  architecture drift; nothing outside §1/§2 was changed.

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

- [ ] **Very large *functions* (not files).** — **[plan written](docs/refactor-large-modules.md)**
  Evidence: the original item ranked files by raw `wc -l`, which was wrong twice
  over. Measured properly (`scripts/large-functions.sh`, production code only):
  30–55% of the "large" files are inline tests and 36–77% of the "giant" functions
  are comments. By production lines the worst file is `frp-client/src/service.rs`
  (4930), not `control/proxy_ops.rs` (3612, of which 4432 of its 8044 raw lines are
  tests). And **file size hides the real problem**: the largest production function
  in the repository is `run` in `frp-server/src/service.rs` — **1291 code lines**,
  in a file that ranks only 11th by size. Churn agrees: `frp-client/src/service.rs`
  is #1 for commits touching it (53/400) and #1 for touches in `fix`/`audit`
  commits (230).
  **Done-when:** one seam extracted per PR, each a pure move with the diff visibly
  mechanical. Recommended first: `frp-server/src/service.rs::run`, a linear
  startup sequence of ~10 independent "if configured, start this listener" blocks
  — the lowest-risk large extraction available, and the connection-handling half
  of the same file was already split into `frp-server/src/handlers/`, so it
  finishes an existing job. Then `frp-client/src/service.rs` (5 seams). Full
  ranking, block inventory, validation bar and hazards:
  [`docs/refactor-large-modules.md`](docs/refactor-large-modules.md).

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

- [x] **Differentiation: measured, and now argued where users read it.**
  Evidence: the pitch used to be unverifiable — the README's own table was
  hand-written and mixed platforms, and `scripts/go-frp/` held v0.69.1 macOS
  x86_64 binaries while the project targeted v0.71.0. It is now generated by
  [`scripts/compare-go-frp.sh`](scripts/compare-go-frp.sh), which verifies
  platform *and* version and aborts otherwise. Same platform (macOS arm64), same
  version (v0.71.0), declared release profile — the table itself lives in
  [README § Technical Differences vs Go frp](README.md#technical-differences-vs-go-frp)
  and is **not** copied here, because this item used to be a third copy and
  hand-copied generated tables drift.
  So the real advantage is **3.5× smaller / 2.7× lighter**, not the 1.65× the old
  table implied — it was *undersold*, while frp-rs's own idle RSS was
  *overstated* (claimed 2–4 MB, measured 9.9 MB).
  Done: the positioning note is now the front door rather than a buried
  paragraph — [README § Overview](README.md#overview) leads with five one-line
  highlights (reversible adoption first, then size/memory, then the Rust-only
  knobs, then the verification posture), and
  [docs/why-frp-rs.md](docs/why-frp-rs.md) carries the full argument ordered by
  what decides a migration. Parts (a) and (b) of the original done-when are
  satisfied there, and "memory safety" is explicitly dropped as a
  differentiator (Go is memory-safe too; the Rust-specific claims are no GC, no
  runtime, and compile-time data-race freedom). Part (c) is split out below.

- [ ] **The "no GC ⇒ stable RSS over weeks" claim has no long-uptime evidence.**
  Evidence: every committed baseline measures frp-rs against itself, and the
  idle-RSS figures (9.9 MB frps / 9.2 MB frpc) are single samples, not a time
  series. Go's heap growing to roughly 2× live is a real mechanism, but this
  repo has not measured it on frp-rs's side against a running Go frps.
  The README and [docs/why-frp-rs.md](docs/why-frp-rs.md) now say so explicitly
  and point here rather than implying it is proven.
  **Done-when:** a multi-hour head-to-head RSS series (frp-rs `frps` vs the Go
  `frps` release, same platform, same proxy set, same traffic) published with the
  harness used, showing RSS over time for both — or the claim is dropped from the
  positioning docs. `scripts/memory-baseline.sh` already accepts
  `FRPS_BIN`/`FRPC_BIN`, so pointing it at the Go binary is the starting point.
