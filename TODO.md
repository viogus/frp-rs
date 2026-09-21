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

## Round-1 adversarial review — open defects

The first round that ran under the new review protocol
([docs/developing.md § Review protocol](docs/developing.md#review-protocol-mandatory)):
ten changes, twenty reviews — one claim-verifier and one adversarial reviewer each, none of
them the author. The adversarial role earned its place: it found defects in every change it
was pointed at, including two in gates that had been reported as "verified both directions".

Findings are listed by the change they came from. Each carries the reviewer's evidence;
where the reviewer's claim was mechanical I re-ran it myself and say so.

**The path-reference gate (#341) was wrong in both directions.**
- [x] **False positive: a crate-relative reference in a Rust comment is reported stale.**
  Evidence (confirmed by re-running the logic): `frp-core/tests/v2_handshake_round14.rs:3`
  names `src/v2_handshake.rs`. The gate tries only `frp-core/tests/src/v2_handshake.rs` and
  `src/v2_handshake.rs`; both are absent, while `frp-core/src/v2_handshake.rs` exists. The
  span escapes today only because it is not in backticks — wrapping it in backticks fails a
  clean tree. **Done-when:** the nearest ancestor containing a `Cargo.toml` is tried as a
  third base, with a test proving a crate-relative reference passes and a genuinely missing
  one still fails.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] **The counts quoted in the commit message and in this file do not reproduce.** The
  shipped script prints 207 references / 177 bare / 45 shorthands / 222 skipped; the commit
  says 198 / 171 / 45 / 216, and no revision the reviewer could materialise yields those.
  **Done-when:** re-measure on the final tree and correct both places.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] **The coverage claim is stronger than the gate.** `CLAUDE.md` says the gate asserts
  "every repo path named in current docs or source comments resolves", but it reads only
  backtick spans anchored at one of 15 roots. Two live stale references are therefore missed:
  `handlers.rs` in `docs/architecture.md:59` and `CLAUDE.md:168` (the file is now
  `frp-server/src/handlers/`), and `frp-client/visitor.rs` in `frp-core/src/lib.rs:119` (the
  file is `frp-client/src/visitor.rs`) — stale, and skipped only because it is not backticked.
  **Done-when:** either resolve bare filenames that match nothing anywhere in the tree and
  scan unbackticked path-like tokens, or narrow the wording to what is actually checked.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] **The gate fails open.** A scanner exception prints `skip … produced no result` and the
  script exits 0 (demonstrated by `chmod 000` on a scanned file). **Done-when:** empty or
  failed scan output sets `fail=1`.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] Lower severity: `vendor/**/*.md` is scanned, so an upstream dependency bump can redden
  CI on prose frp-rs cannot edit; the new doc section omits three of the script's
  `SKIP_FILES` and the root-anchoring rule; the "700 misses" figure has no committed script
  and three plausible reconstructions give 139 / 534 / 1076.

**The `/api/reload` fix (#342) changed default CLI behaviour without saying so.**
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] **Every default `frpc reload` is now strict.** `reload_cmd()` builds `strict_config`
  with `flag(true, true)` — absent → `true` (`frp-core/src/cli.rs:1010-1045`, comment
  "absent → true"). Before this change serde ignored the camelCase key, so the CLI's value
  was discarded and reloads were always non-strict; now it is honoured, so a reload of a
  config containing an unrecognised key fails where it used to succeed. **Done-when:** read
  Go's `cmd/frpc/sub/reload.go` at the v0.71.0 commit and either match it exactly or record
  the divergence; if Go's reload is non-strict by default, fix the CLI default rather than
  the alias.
  Done: fixed in #351. See that PR for the evidence and the residue it records.
- [x] **The test that is cited as the proof never runs in CI.** The parity test is gated
  `#[cfg(feature = "admin")]`; `ci.yml:159` runs `cargo test -p frp-client -j 1` without
  `--features admin`, and the only all-features test step (`ci.yml:82`) is `--lib`, which
  excludes integration tests. **Done-when:** the client integration lane runs with
  `--features admin`, or the test moves to a target that does.
  Done: fixed in #351. See that PR for the evidence and the residue it records.
- [ ] Lower severity: `?strictConfig=a&strictConfig=b` returns 400 here and 200 in Go (Go
  reads the first value), which falsifies the documented "never a 400"; the
  `Option<Json<..>>` rationale is wrong (axum yields `None` only when `Content-Type` is
  absent, not for a malformed JSON body with the header set); `HEAD /api/reload` now
  performs a real reload because axum serves HEAD through the `get` handler.
  The duplicate-parameter half and the doc claim are fixed in this change (raw-query parse,
  first value wins). The `Option<Json<..>>` rationale is **already** fixed: `handle_reload`
  takes `body: Bytes` and its comment gives the correct reason ("a body that is present but
  not well-formed JSON must be a 400 on every method"), so no `Option<Json<..>>` remains to
  mis-explain. The `HEAD`-performs-a-reload half is still open.
- [x] **Corrected record: the hypothesised "malformed escape also 400'd" class did
  not exist.** The claim was that `?strictConfig=%zz`/`%ff` answered 400 through axum's
  `Query` extractor. It is false, and it was never measured before being written down:
  `axum::extract::Query` is `serde_urlencoded::from_str`, and `form_urlencoded` 1.2.2 is an
  **infallible, lossy** iterator (`percent_decode` leaves invalid escapes literal and
  `decode_utf8_lossy` cannot error), so `Query<ReloadQuery>` could only 400 on a serde
  *structural* error. Measured on the pre-change extractor (temporary probe, `Query` +
  the removed struct) on **body-less** requests: `%zz` -> 200, `%ff` -> 200, `%` -> 200, and
  only `true&strictConfig=false` -> 400 `duplicate field`. That list is precisely the
  configuration in which the reduced "no malformed-escape change" claim holds; Reviewer 2's
  re-review found the second change it misses. With a JSON body present, the old extractor
  kept the key *present* with the literal `%zz`, so `parse_strict_config` was false and the
  query suppressed the body; the new parser drops the pair, so the parameter is absent and
  the body fallback applies: `POST /api/reload?strictConfig=%zz` +
  `{"strict_config": true}` was 200 non-strict and is now 400 strict (same for `%`, `%2`,
  `a;b`). `%ff` is genuinely unchanged — a well-formed escape is kept lossily, so the key
  stays present and still suppresses the body. So this round has **two** behaviour changes:
  the repeated parameter, and the dropped-pair/body interaction. Both follow from encoding
  Go's rules explicitly; the second is pinned by an HTTP-level case that carries a body.
  The raw-query rewrite is kept, but justified as the explicit Go-faithful contract rather
  than as a bug fix: it encodes
  `url.Values.Get` / `url.ParseQuery` rules (first value wins, an un-unescapable pair is
  dropped, `+`/`%XX` decode) instead of depending on a dependency's incidental leniency, and
  it is pinned against real Go (`net/url.ParseQuery` + `Values.Get` + `strconv.ParseBool`,
  go1.27.1): `strictConfig=%zz` -> `Get("")` non-strict; `%ff` -> `Get("\xff")` non-strict;
  `foo=%zz&strictConfig=true` -> `Get("true")` strict; `strictConfig` / `strictConfig=` ->
  `Get("")` non-strict; `strictConfig=a;b` -> `Get("")` non-strict (Go 1.17+ rejects `;`).
  Done: `first_strict_config_param`/`query_unescape` in `frp-client/src/admin.rs`,
  unit-tested against the Go table above and exercised at HTTP level in
  `frp-client/tests/reload_malformed_config.rs` and the `reload_*` unit tests, including the
  query-dropped-plus-body case.

**The tier-warning gate (#343) does not cover what was fixed.**
- [x] The two CI steps are `cargo check` without `--all-targets`, so that change's own cfg
  fixes — the `tls`-gated items in `frp-client/src/plugin/mod.rs` (four tests plus the
  `plugin_peer_ip_now` helper) and `frp-client/tests/plugin_http.rs` (one import plus two
  tests) — were not compiled by the gate added to enforce them. **Done-when:** add
  `--all-targets` (and re-check the cost) or state plainly in `docs/developing.md` which
  targets are covered.
  Done: the second branch, plus a new isolated gate. `--all-targets` was measured and
  rejected: on a `--workspace` run it activates the dev-dependency edges, and
  `frp-server`'s dev-dependency on `frp-client` (default features, `frp-server/Cargo.toml:67`)
  plus frp-client's on frp-server re-enable both crates' `default` sets — the micro step then
  compiles `frp-client = [chacha20,compression,default,http2http,kcp,oidc,quic,tcp-mux,tls,websocket]`
  instead of `[]` and `frp-server` gains `default`+`ssh`. That is a tier-coverage loss, not a
  gain, so the workspace steps stay as they are (with a `ci.yml` comment recording why). The
  tier test targets are now compiled by
  `cargo check -p frp-client --no-default-features --all-targets`, where `-p` makes the crate
  the only root so the dev-dependency edge cannot reopen its defaults, and
  `docs/developing.md § Binary Variants` states exactly which targets each step covers.
- [ ] `frp-server`'s `tls`-off test targets still have no gate: the symmetric
  `cargo check -p frp-server --no-default-features --all-targets` does not compile.
  `error[E0004]` at `frp-server/src/service.rs:1842` — `ConnectionType::WebSocket` is not
  covered, because feature unification gives `frp-core` the variant (through frp-client's
  default features, frp-client being frp-server's dev-dependency) while frp-server's own
  `websocket` feature is off. **Done-when:** `service.rs`'s `match` has a defensive arm for
  the unbuilt transport (or the variant is otherwise made unreachable under feature
  unification), and the isolated `-p frp-server` step joins the `-p frp-client` one in
  `ci.yml`.

**The SSH readiness fix (#344) left two sites and one unbounded case.**
- [x] Two SSH-gateway tests still connect with a bare `.unwrap()` and no readiness wait.
  Done: fixed in #353. See that PR for the evidence and the residue it records.
- [x] `SSH_READY_TIMEOUT` bounds the retry loop, not a stalled handshake: a peer that accepts
  TCP and then stalls can still hang the helper past the deadline. **Done-when:** wrap the
  attempt in a timeout so the bound is real.

**The doc-figure gate (#346) can be bypassed and mis-measures.**
  Done: fixed in #353. See that PR for the evidence and the residue it records.
- [x] **A doc line containing the literal `DOC-FIGURES: ok` makes the gate exit 0.** (The
  gate's own output is what is grepped, so a doc that quotes it satisfies the check.)
  **Done-when:** the pass/fail decision does not depend on scanning its own printed output.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] **The measurement undercounts, so it certifies wrong numbers.** Parameterised
  `#[tokio::test(...)]` attributes are not counted: the tree has 2111 test functions, not the
  gated 2058; `protocol.rs` has 49 regular tests, not 40; `frp-server/tests` has 218, not 213;
  and 7 compat scenarios are gated on Go frp V2, not 5. **Done-when:** the counters match an
  independent count (`grep -c` of every attribute form), and the five figures are corrected.
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] Live docs quoting those figures are not all gated, so the gate can be green while a
  duplicate is wrong. **Done-when:** every live-doc copy of a gated quantity is either gated
  or deleted in favour of a pointer.

**The ETXTBSY fix (#347) leaves its own detection untested.**
  Done: fixed in #354. See that PR for the evidence and the residue it records.
- [x] `io_error_from_token_error` — the function that decides "is this errno 26" — has no
  test. A mutation that never matches keeps every test green and silently restores the flake
  it was written to stop. **Done-when:** a test drives that classifier directly (a matching
  error retries, a non-matching one does not), so the branch cannot rot unnoticed.

**The feature-surface policy (#348) contradicts itself on one surface.**
  Done: fixed in #353. See that PR for the evidence and the residue it records.
- [x] `virtual_net` appears in **Keep** (inside "the 10 client plugins") and in **Opt-in**
  (the TUN-backed path) in the same section, and the "10 client plugins" set does not match
  the dispatch arms. **Done-when:** one tier per surface, and the plugin count reconciled
  with `frp-client/src/plugin/mod.rs`.
  Done: fixed in this change — Keep now says "9 of the 10 client plugins" and the Opt-in row
  names the `virtual_net` client plugin. The count reconciles with
  `frp-client/src/plugin/mod.rs:278-294`: nine dispatched user-facing plugin types
  (`http_proxy`, `socks5`, `static_file`, `unix_domain_socket`, `tls2raw`, `http2http`,
  `http2https`, `https2http`, `https2https`) plus the TUN-backed `virtual_net` (special-cased
  at `mod.rs:331` because it has no listener) = 10. The `visitor_plugin` dispatch arm is the
  internal visitor path, not one of the ten client plugins.
- [x] (corrected record — the original entry misquoted the document) The h2c bullet does
  **not** cite "a compat failure on that surface": `docs/developing.md` gives it two triggers,
  a Go-side change to its h2c handling (`net/http` upgrade path or `pkg/util/vhost`) and a
  user-reported h2c interop failure, neither of which needs a compat scenario — so the
  original claim that the condition "can never fire" was false. The real, unfixed defect was
  the section's opening citation: it presents `scripts/compat-test.sh` as the end-to-end
  evidence for the whole feature-surface policy, but the frozen surfaces the policy governs
  (SUDP, h2c, Windows TUN, the non-default XTCP KCP+yamux plane) and `virtual_net` have no
  compat scenario at all (grep of `scripts/` and `.github/` is empty). The original entry was
  a reviewer paraphrase of the policy written as a quotation and never checked against the
  file; the "defect report" was less accurate than the document it accused. **Done-when:**
  the citation is scoped to the surfaces compat scenarios cover, and the document says
  plainly which surfaces have none.
  Done: fixed in this change (`docs/developing.md § Maintenance policy: feature surface`,
  opening paragraph).

**The review protocol itself (#349) needs the same scrutiny.**
- [x] The record template shows `Reviewer 1 (<what they did>)` and `Reviewer 2 adversarial
  (<what they attacked>)`, but `CLAUDE.md` rule 4 mandates four things — method, what was
  checked, findings, **disposition**. The template omits two of them.
  Done: fixed in this change — `docs/developing.md § Recording it` now asks for all four per
  reviewer (method / checked / findings / disposition), and
  `.github/PULL_REQUEST_TEMPLATE.md` carries the same block.
- [x] Rule 4 has no enforcement surface: no PR template, no CI check, nothing that notices a
  pull request with no review record. It is self-attestation, which is the weakest form of
  the thing it asks for. **Done-when:** either a PR template carrying the block, or an
  explicit note that the rule is convention-only and why that is acceptable here.
  Done: fixed in this change — `.github/PULL_REQUEST_TEMPLATE.md` (new) puts the
  `## Reviews` block in every new PR body, so the record is the default rather than something
  a contributor must remember. Still convention-only (nothing red happens without it); the
  template is the prompt, and the reviewers themselves remain the control.

**Lower severity, recorded so it is not lost.** The rustls change (#345) says "the only 0.24
artifact is `0.24.0-dev.1`" (`0.24.0-dev.0` also exists), and its README names a CI command
that skips the SNI integration test it is cited for; the review-protocol commit's premise
"this repository has a single author" is contradicted by its own history (1231 human / 219
agent commits), which matters because the *reason* for two reviewers is that no second
**person** exists, not that no second author does.

- [ ] **`frp-core`'s test targets do not compile with no features.** Evidence:
  `cargo check -p frp-core --no-default-features --all-targets` exits 101 —
  `could not compile frp-core (lib test) due to 2 previous errors`, `(test "kcp") due to 3`,
  `(test "xtcp_p2p") due to 20`; sample errors `E0425 cannot find function 'connect_ws_raw'
  in this scope`, `E0432 unresolved imports frp_core::kcp::{dial_kcp, dial_kcp_with_driver,
  KcpListener}`, `E0425 cannot find function 'punch_udp_hole' in module frp_core::xtcp_p2p`.
  The `kcp`/`xtcp_p2p` integration tests and some lib tests have no `#[cfg]` gate for the
  features they need. **Done-when:** each such test carries its gate, so the command exits 0
  and the run can join the `-p frp-client` isolated CI step.
- [ ] **`frpc-tiny`'s test targets do not compile either.** Evidence:
  `cargo check -p frp-client --no-default-features --features tls,tcp-mux --all-targets`
  — exactly the tiny tier for frp-client, measured `['tcp-mux','tls']` — exits 101 with
  `could not compile frp-client (test "plugin_h2") due to 5 previous errors`: `E0433 cannot
  find module or crate 'h2'`, `'http'`, plus an `E0277`. `plugin_h2.rs` is gated
  `#![cfg(feature = "tls")]` only, but its `h2`/`http` imports come from `http2http`. The
  new isolated CI step uses `--no-default-features` (no features), so it does not reach this
  configuration. **Done-when:** the `plugin_h2` test target is gated on the feature that
  provides `h2`/`http` (`http2http`), so the tiny test targets build and a
  `-p frp-client --no-default-features --features tls,tcp-mux --all-targets` step can be
  added.
- [ ] **Pre-existing: no query-parameter-count guard, so >10000 params diverge from Go.**
  Go's `parseQuery` opens with
  `if !urlParamsWithinMax(strings.Count(query, "&") + 1) { return Values{}, err }`
  (`net/url/url.go:980`, `defaultMaxParams = 10000`), so an over-limit query yields empty
  `Values` and the reload is non-strict. Precision measured by Reviewer 2: `defaultMaxParams`
  is present in **go1.25.12** (the toolchain that built the shipped Go frp v0.71.0 binary) and
  **absent in go1.25.0** — a 1.25.x backport, not a 1.25.0 feature. Reproduced on two
  independent successful fetches (`go1.25.0` 0 hits, `go1.25.12` 2 hits for `defaultMaxParams`
  in `net/url/url.go`). Real Go frp v0.71.0 measured on
  `?strictConfig=true` + N×`&`: N=9999 → **400** (within the limit, strict), N=10000 →
  **200** (guard trips, non-strict). Rust has no such guard and is always strict. Why the
  differential oracle did not flag it (the parent agent's — Reviewer 1's — wording error,
  refuted by Reviewer 2): an oracle built on `url.ParseQuery` sees the limit by construction,
  so only a corpus that never emits more than 10000 parameters fails to reach it.
  **Done-when:** the parser mirrors
  Go's parameter-count guard (or the divergence is documented at the endpoint), with both N
  cases pinned.
- [ ] **Pre-existing: `#` in the request target changes strictness.** Go parses request URIs
  with `viaRequest=true`, which never splits a fragment, so `#` stays inside `RawQuery` and
  `GET /api/reload?strictConfig=true#strictConfig=false` is a **200** non-strict reload (the
  value becomes `true#strictConfig=false`, which `ParseBool` rejects). `axum::extract::RawQuery`
  comes from `http::Uri`, which strips the fragment, so frp-rs reads `strictConfig=true` and
  is strict — same endpoint, opposite strictness. **Done-when:** the raw request target is
  used (or the divergence documented at the endpoint), with the `#` case pinned.

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

- [x] **No mechanism keeps prose in sync with code.**
  Evidence: `unsafe` 17→21 (fixed here); `docs/developing.md` claimed four vendored
  yamux patches when `vendor/yamux/README-FRP-RS.md` documents **five**;
  `~N lines` figures attached to filenames had gone stale by 2–5×.
  **Done-when:** every quantitative claim in a live doc is either generated by
  `repo-health.sh` or carries a `file:line` that a reviewer can check. Add a
  periodic (release-checklist) pass that re-verifies them.
  Done: surveyed the live docs (README, CLAUDE, docs/README, architecture,
  developing, why-frp-rs, go-frp-compat-audit) and dispositioned **28 curated
  entries over 11 distinct measured quantities** (compat scenarios, XTCP
  scenarios, V2-gated scenarios, transport rows, `proptest!` blocks, protocol
  fuzz tests, protocol regular tests, core+server bench groups, `frp-server/tests/`
  test functions, client plugin types, total test functions). They are
  **generated**: `repo-health.sh` gained a curated doc-figure table that
  re-derives every expected value from its source (the script's own `--list`, the
  source file, the `criterion_group!` line) on each run, prints the witness
  `file:line` a reviewer can open, and fails the `health` job on mismatch.
  **5 claims were cited or de-numbered** (Go binary size, RSS, "~2000 tests",
  "~16–20 MB each" → pointers to the generated table or measured count), and the
  hand-typed "3.5×/2.7×" ratios in README were **deleted** — they had gone stale
  against their own generated table and are not load-bearing. The known proptest
  discrepancy is fixed: **11 is right** (`grep -c 'proptest!'` on
  `frp-core/src/config/tests.rs`, re-counted by the gate), and
  `docs/developing.md` said 9 — corrected, while CLAUDE.md's 11 is now confirmed
  by the gate rather than restated twice. The survey also caught two more stale
  counts no one had reported: `6 fuzz tests + 35 regular tests` was really 40
  regular tests, and `2 of which are gated on Go frp V2` was really 5.
  The verifier is a **curated list**, not a regex sweep over "numbers in docs"
  (the earlier naive path sweep produced 135 hits on a clean tree; a number sweep
  would be worse — every port and buffer size). Measured against this tree:
  **28/28 entries hit exactly once, 0 false positives** (56 output lines for 28
  entries), and it fails in both directions — flipping README's "86 scenarios" to
  "87" fails check #01 naming `README.md:30`, and deleting a claim reports the
  missing wording plus the value the tree now measures; reverting
  `docs/developing.md`'s proptest figure to 9 failed exactly that one entry and
  the gate exited 1.
  Periodic pass: one release-checklist step in
  `docs/developing.md § Pre-release checklist` — read the `Docs` section of the
  same `repo-health.sh` run and reconcile each `claimed … measured …` line with
  its witness `file:line` (the run itself already fails on a drifted figure, so
  the skim is for a claim that drifted in *meaning*).
  Residue (deliberately not converted; also listed in the docs conventions):
  `docs/refactor-large-modules.md` — a dated proposal opened at `9c84ada`, whose
  file/function line counts are already produced by `scripts/large-functions.sh`;
  CLAUDE.md's per-tier size/MB figures (platform-dependent; `--sizes` prints
  them); the README's "17 MB Go binary" (an upper bound its own generated table
  backs); Go-source `file:line` citations like `service.go:670-710` (checked by
  review, not statically); and `~2× live` heap growth, which has no cheap static
  source. `CHANGELOG.md`'s dated `86/86`, `11/11`, `17 XTCP` entries are
  point-in-time release notes and were left as written (the same figures in live
  docs are gated).

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

- [x] **`frpc`'s `GET /api/reload` diverges from Go frp — it requires a JSON body.**
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
  **Correction — the framing above was wrong:** Go frp reads **no request body at
  all** on this route (`ctx.Body()` is never called by `Reload`), and
  `client/api_router.go` registers it **GET only**. Strict mode comes from the
  query parameter `?strictConfig=`, parsed with `strconv.ParseBool` and the parse
  error **discarded** (`strictConfigMode, _ = strconv.ParseBool(strictStr)`,
  `client/http/controller.go` at commit `4a23aa18`), so a garbage value (`yes`,
  `garbage`, empty `?strictConfig=`) is a **200 non-strict reload, never a 400**.
  The body/malformed-400 cases describe frp-rs's own JSON extension, not Go.
  Done: `handle_reload` (`frp-client/src/admin.rs:178-206`) now takes
  `Query<ReloadQuery>` plus raw `axum::body::Bytes` (`Option<Json<..>>` would
  swallow a malformed body as `None`) and picks strict mode query-first, falling
  back to the JSON body; `parse_strict_config` mirrors `strconv.ParseBool` with
  Go's error→false handling. Body-less GET → 200 non-strict,
  `?strictConfig=true` → strict, `?strictConfig=<unparseable>` → 200 non-strict,
  malformed JSON body → 400. The JSON extension is kept for frpc's own CLI and now
  also accepts the camelCase `strictConfig` spelling that CLI actually sends
  (`frpc/src/main.rs:630`) — previously serde ignored it, so `frpc reload
  --strict_config` silently ran non-strict. Pinned by
  `reload_admin_go_query_parity_and_body_extension` in
  `frp-client/tests/reload_malformed_config.rs` and the
  `parse_strict_config_matches_strconv_parse_bool` unit test; `docs/deployment.md`
  updated.

- [x] **The `tiny`/`micro` feature builds emit warnings, and CI does not deny them.**
  Evidence: `cargo build --release --no-default-features --features tiny|micro`
  on `main` reports (macOS arm64, rustc 1.96.0). Measured precisely on the same
  host: **`tiny` is clean; all three warnings are `micro`-only** — the original
  `tiny|micro` phrasing was imprecise, because `tiny` keeps `tls` and each site
  is live in a TLS build:
  - `frp-server/src/vhost.rs:3` — unused import `AsyncWriteExt` (its remaining
    direct method use is the TLS-alert write in the `tls`-gated HTTPS vhost
    listener; the two response writers take `impl AsyncWriteExt` bounds)
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
  **Done:** reproduced on macOS arm64 / rustc 1.96.0 — `tiny` 0 warnings,
  `micro` exactly the three sites above. Fixed by cfg-gating, no `allow`s:
  `vhost.rs:3` split into `use tokio::io::AsyncReadExt;` plus
  `#[cfg(feature = "tls")] use tokio::io::AsyncWriteExt;`; `take_plugin_peer`,
  `plugin_peer_ip`, the four registry tests and the `plugin_peer_ip_now` helper
  are `#[cfg(feature = "tls")]`. Correction to this item's guess: the import
  gate is `tls`, not `http-proxy` — on the pre-fix tree
  `cargo check -p frp-server --no-default-features --features http-proxy` warns
  while `--features tls` is clean, and a `tls`-only build is exactly the one
  that needs the trait. `register_plugin_peer`/`clear_plugin_peers`/
  `PluginPeerGuard` stay unconditional (`work_conn.rs` registers them in every
  build), so `micro` behaviour is unchanged. CI: both `verify`-job tier steps in
  `ci.yml` now set `env: RUSTFLAGS: "-D warnings"` (this changes the compiler
  fingerprint, so the restored `target/` cache is not reused for those two
  steps — accepted). Two-direction proof of the gate:
  `RUSTFLAGS="-D warnings" cargo check --workspace --no-default-features
  --features micro` exits 0 with the fix; removing the `vhost.rs` import cfg
  exits 101 with `error: unused import: AsyncWriteExt`, and removing the
  `take_plugin_peer` cfg exits 101 with `error: function take_plugin_peer is
  never used`. All four profiles pass `-D warnings` on macOS (default,
  `--all-features`, `tiny`, `micro`; 0 warnings each). The gated test module is
  verified by `RUSTFLAGS="-D warnings" cargo check -p frp-client
  --no-default-features --all-targets` (exit 0) — a *workspace* `--all-targets`
  run cannot test this, because `frp-server`'s dev-dependency on `frp-client`
  re-enables frp-client's default features. That same sweep found and fixed one
  more site of this class: the `IoStream` import in
  `frp-client/tests/plugin_http.rs`, used only by its `tls`-gated https2https
  test, now `#[cfg(feature = "tls")]`. Linux is delegated to the edited `verify`
  CI job — macOS cannot run the Linux `#[cfg]` paths here.

- [ ] **The `Lint` gate depends on the unpinned runner toolchain, so it can go red on unchanged code.**
  Evidence: on `rustc 1.96.0` / `clippy 0.1.96` the documented gate
  `cargo clippy --workspace --all-targets --all-features -- -D warnings` failed
  on unmodified base content:
  `error: this boolean expression can be simplified` at
  `frp-server/tests/tcpmux.rs:398` (`clippy::nonminimal_bool` on
  `while !…is_some()`, exit 101); the lint is new in 1.96.0, so the same command
  is green on the older stable a CI image happens to ship. No workflow pins a
  toolchain — every job runs `rustup default stable`
  (`.github/workflows/ci.yml`), so `Lint`'s result is a function of the runner
  image, not the commit. `CLAUDE.md`'s "zero warnings" health line was false on
  1.96.0 until this round. (The `is_some()`→`is_none()` fix landed with the
  tiny/micro tier-warning item above; this item is the structural hazard, not
  that one line.)
  **Done-when:** the toolchain is pinned (a `rust-toolchain.toml`, or an explicit
  `rustup toolchain install <version>` + `rustup default <version>` in CI) so a
  rustc/clippy bump is a deliberate, reviewable change rather than a
  runner-image race, and the `Lint` gate is verified green on that pinned
  version. A `rust-toolchain.toml` would also make the local/CI lint result
  identical, which is the property the health table currently assumes.

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

  **Recurrence (2026-09-17, PR #351 — a `CHANGELOG.md` + one CI-lane feature-flag diff,
  so nothing on the data plane changed):** the `compat` job failed twice in a row on the
  same commit with a **different failing scenario each time** — first the
  `kcp-rust-to-rust` scenario reporting `proxy port 20403 not reachable`, then the
  `rust-to-go-tcp-tls` scenario reporting `FAIL:CONNECT_TIMEOUT` (both 85 passed / 1 failed)
  — and passed on the third attempt (the second re-run).
  What this establishes, and no more: the failure is **not** caused by the diff, because the
  diff cannot reach the data plane. It does **not** establish a mechanism. Note the suites are
  not interchangeable and must not be pooled: `kcp-rust-to-rust` and `rust-to-go-tcp-tls` are
  `compat-test.sh` scenarios, whereas `tcp-plain`, `tcp-tls`, `tcp-tls-mux` and `ws-plain` were
  reported by the **protocol-matrix** step of the same job, and `go-to-rust-quic` was a
  `compat-test.sh` scenario. `tcp-plain` is listed above only because it was part of the
  original #341 report; it is not part of this reproduction.
  Also worth separating: the #338 recurrence below is a different phenomenon — a single
  **ETXTBSY unit-test** failure inside the same job, not a scenario that moved between runs.
  Both matter, but "the failure moves around" is a claim about the scenario failures only.

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

  **Done (partial) — ETXTBSY case only.** The exec-token test now names its script
  per invocation (`pid` + an atomic sequence + nanoseconds; `pid` alone was not
  unique) and resolves it through a test-local `retry_on_etxtbsy` helper in
  `frp-core/src/auth.rs` that retries **only** the ETXTBSY class, bounded to 5
  attempts × 10 ms (worst case ~40 ms), with the exit-status assertion unchanged;
  the script is removed on every path by a drop guard. Proven deterministically
  off Linux by feeding the helper `io::Error::from_raw_os_error(26)`: 2 busy
  attempts then success retries, a non-ETXTBSY error (ENOENT) is not retried, and
  the loop is bounded to 5 attempts. Evidence:
  `cargo test -p frp-core --lib auth::` green 5× back to back (68 passed, 0 failed
  each), `cargo test -p frp-core` (850 lib tests) green, `cargo fmt --all --
  --check` and `cargo clippy -p frp-core --all-targets --all-features -- -D
  warnings` clean; forcing a non-exit-status failure (script `exit 0`, then an
  ENOENT path) still fails the test loudly. The compat-scenario flakes
  (zero-throughput `tcp-tls`/`tcp-tls-mux`, unreachable `ws-plain`,
  `go-to-rust-quic` timeout) are **not** touched and this item stays open.

- [x] **`Tests (server integration)` fails intermittently, and it turns `main` red.**
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

  Done: all 10 sites in `frp-server/tests/ssh_gateway.rs` now wait on a
  wall-clock deadline. The three bare-TCP readiness sites (lines 102, 224, 282)
  call the already-existing `common::wait_tcp_port(port, SSH_READY_TIMEOUT)`;
  the six `russh::client::connect` sites (345, 454, 697, 797, 862, 930 — 930 is
  `connect_ssh_auth`, the one that flaked) share a new `connect_ssh_ready`
  helper; and the pre-auth-cap test's raw `connect_raw` (591) keeps its own
  deadline loop because `wait_tcp_port`'s probe connection would transiently hold
  one of the 8 per-IP permits that test counts. Timeout: **10 s** for both,
  matching the file's existing `Duration::from_secs(10)` authenticated-handshake
  waits (886/905) and well above the old fixed 20 × 100 ms (~2 s) window, while
  still failing a real hang in 10 s rather than never. Failures are loud: the
  russh helper panics with the **last** connect error
  (forced probe: `SSH client should connect within 10s; last error: IO(Os { code:
  61, kind: ConnectionRefused, ... })`) instead of a bare
  `expect("SSH client should connect")`, and `wait_tcp_port` reports port +
  elapsed budget (`port 1 not ready after 10s`). The underlying gap: `start_test_server` waits for the FRP
  `bind_port` and the dashboard port (`common/mod.rs:644,649`) but never for the
  SSH gateway port, so every SSH test grew its own readiness loop — and those
  loops, not any missing helper, were the ~2 s ceiling. (`wait_tcp_port` carried a
  stale `#[allow(dead_code)]` while already being called twice from
  `start_test_server`; that allow is now removed and the helper is used at the SSH
  sites too. Report of "no caller" from the dispatching agent was wrong — it came
  from a grep that excluded `common/mod.rs` itself.) Evidence: `cargo test -p frp-server --test ssh_gateway`
  green **5× back to back**, 14 passed each (~15.2 s each), plus the two
  forced-failure runs above. Honest limit: five green runs do not *prove* an
  intermittent flake is gone; they show the ~2 s ceiling named as the cause is no
  longer the budget. Site 644 (raw connection with a 2 s per-attempt read
  timeout) was left unchanged, as the item excluded it. Also added "wait on a
  deadline, not an attempt count" to `docs/developing.md`'s Writing New Tests
  list, since this is the second flakiness item in this backlog.

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

- [x] **No automated check for stale path references — and a naive one does not work.**
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
  Done: `scripts/repo-health.sh` (the `health` CI job) gained a third `Docs`
  gate. Measured on the clean tree: **0 stale path references** — so it is a
  **gate** (`fail=1` on a hit), not a report. The script prints the current
  counts (198 references checked; 216 skipped as locator-less: 171 bare
  filenames like `mux.rs`/`store.rs` + 45 crate-`src/` shorthands like
  `control/mod.rs`/`plugin/h2.rs`).
  Each candidate resolves against the directory of the file that names it first
  and the repo root second, and Rust source comments are scanned as well as
  markdown, so the deleted-directory case from the item above is caught in both
  media. `crate/feature` spans are classified from each member's `[features]`
  table plus the implicit features of its optional dependencies (`frp-core/tls`
  is not a path), not from a hard-coded list. The check deliberately does *not*
  flag spans with no locating root: those are exactly the naive sweep's false
  positives, and their base cannot be recovered mechanically, so they are
  counted in the output and left to review. Historical records
  (`docs/archive/**`, `docs/history/**`, dated `docs/audit/**`, `CHANGELOG.md`),
  the dated root `performance-audit.md`, the forward-looking
  `docs/refactor-large-modules.md`, and this backlog — which quotes removed
  paths as evidence — are out of scope by design.
  It does **not** catch a directory that still exists with its contents emptied:
  recreating `frp-core/vendored/kcp-0.6.0/` holding only a `Cargo.lock` passes
  the gate. Existence is all that is mechanically checkable; "this directory no
  longer holds what the text claims" is semantic, and a "non-empty directory"
  heuristic would false-positive on the accurate `scripts/go-frp/` reference
  (it holds only a `LICENSE` today). That residue stays a manual review item.

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

- [ ] **Upgrade to rustls ≥ 0.24 and delete `vendor/rustls` — blocked upstream,
  no stable 0.24 exists.**
  Re-checked on crates.io 2026-09-17 (`https://crates.io/api/v1/crates/rustls`):
  `max_stable_version` = `0.23.45`, `newest_version` = `0.23.45`,
  `max_version` = `0.24.0-dev.1`. The only 0.24 artifact is a **prerelease**
  (`0.24.0-dev.1`, published 2026-07-23, `edition = "2024"`,
  `rust_version = "1.85"`); `[patch.crates-io]` pins a path, so a prerelease is
  not an option for the shipped TLS stack. The migration below is unchanged and
  still correct — it just has no target release yet, so this item is not
  actionable today and must not be closed.
  Evidence: the vendored tree exists only to treat an invalid TLS SNI as "no SNI"
  so Go frp's XTCP QUIC visitors interoperate (`ip:port` as SNI). rustls ≥ 0.24 has
  `invalid_sni_policy = IgnoreAll` natively, which is exactly this behaviour.
  Interim risk retired: the 0.23.x line was brought current to **0.23.45** (from
  0.23.43) — the fix for **GHSA-2mjx-qc3c-rqvc** (medium: TLS 1.3 handshake
  messages accepted across encryption-level boundaries; affects 0.23.13–0.23.44
  inclusive, so the previously vendored 0.23.43 *was* affected; same bug as Go
  `GO-2026-4340`). That re-vendor re-applied the SNI patch and is covered by
  `frp-core/tests/xtcp_quic_sni.rs`. The standing obligation is unchanged: while
  the patch exists, 0.23.x security releases arrive only by hand.
  **Done-when (trigger-gated):** *when `max_stable_version` ≥ `0.24`*, upgrade the
  workspace to that stable release, express the patch as
  `ServerConfig::invalid_sni_policy = InvalidSniPolicy::IgnoreAll` on the XTCP QUIC
  server config, delete `vendor/rustls` and its `[patch.crates-io]` entry, and
  confirm the XTCP QUIC compat scenarios still pass.

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

- [x] **Feature surface is wide for a single maintainer.**
  Evidence: SSH gateway, L3 VPN/TUN, OIDC, dashboard, h2c, 10 client plugins,
  SUDP, V2 protocol, and two XTCP data planes — each with its own parity debt.
  **Done-when:** an explicit keep/opt-in/drop decision per surface is recorded, so
  effort stops spreading by default.
  Done: the decision is recorded as a **tiered maintenance policy, not a deletion
  plan**, in
  [`docs/developing.md § Maintenance policy: feature surface`](docs/developing.md#maintenance-policy-feature-surface)
  (with a one-line pointer from `CLAUDE.md`). Tiers: **Keep** (full parity, Go
  work welcome) = the default surface — TCP/UDP/HTTP/HTTPS/STCP/XTCP, V1+V2 wire
  protocol, encryption/compression, tcp-mux, the five transports, OIDC, the
  dashboard, the SSH gateway, the 10 client plugins, and the server-side
  `[[httpPlugins]]` manager; **Opt-in** (best-effort, out of the default build on
  purpose) = `vnet`, `mimalloc`, `otel`, frpc `admin`; **Freeze** (bug-fix only,
  no new Go-parity work, nothing removed) = SUDP, h2c, Windows TUN, and the
  non-default XTCP KCP+yamux plane. Every frozen surface carries an explicit
  "unfreeze if" condition (a user report of real use, a Go-side change, or a case
  the QUIC plane cannot serve), and the section states how a surface moves tiers:
  the maintainer decides, in a commit naming the evidence, with no second
  reviewer.
  This item's own evidence needed one correction, and two of its framings were
  verified rather than trusted. The **server-side `http-proxy` plugin is
  default-on, not opt-in** (`frp-server/Cargo.toml:43`; also in `tiny` at
  `frps/Cargo.toml:24`), so it is recorded under Keep, and the contrary
  "server-side opt-in" clause in `CLAUDE.md` was fixed. h2c is real and distinct
  (`frp-server/src/vhost_h2c.rs`, 3414 lines) but rides that default-on
  `http-proxy` feature (`frp-server/src/vhost.rs:23`), so its freeze is a
  code-review rule rather than a build gate; the Windows TUN stub errors on every
  operation (`frp-vnet/src/tun_windows.rs:1,24,34`); and the **default XTCP data
  plane is QUIC**, not KCP (`frp-core/src/config/client.rs:823`,
  `docs/config.md:659`) — the live docs already agreed, so no correction was
  needed there. SUDP is confirmed as a distinct proxy type, not a UDP variant
  (`frp-core/src/config/loader.rs:219`).

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
